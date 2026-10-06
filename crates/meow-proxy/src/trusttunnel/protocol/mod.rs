//! TrustTunnel HTTP/2 wire protocol. The adapter supplies verified TLS through
//! the workspace dialer; this module never creates an outbound socket itself.

mod stream;
mod udp;

pub use stream::TunnelStream;
pub use udp::UdpAssociation;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::Bytes;
use http::{HeaderValue, Method, Request, StatusCode};
#[derive(Debug)]
pub(crate) struct AuthenticationFailed;
impl std::fmt::Display for AuthenticationFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustTunnel authentication failed")
    }
}
impl std::error::Error for AuthenticationFailed {}

use std::{
    io,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex as AsyncMutex,
};
use tokio_util::sync::CancellationToken;

pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> IoStream for T {}

#[async_trait]
pub trait Connector: Send + Sync {
    async fn connect(&self) -> io::Result<Box<dyn IoStream>>;
}

/// Credentials intentionally have no Debug implementation.
pub struct Options {
    pub username: String,
    pub password: String,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
    pub timeout: Duration,
    pub health_check: bool,
}

impl Options {
    pub fn new(username: String, password: String) -> Self {
        Self {
            username,
            password,
            max_connections: 8,
            min_streams: 5,
            max_streams: 128,
            timeout: Duration::from_secs(10),
            health_check: false,
        }
    }
}

struct Inner {
    connector: Arc<dyn Connector>,
    auth: HeaderValue,
    options: Options,
    sessions: Mutex<Vec<Arc<Session>>>,
    creating: AsyncMutex<()>,
    generation: AtomicU64,
    network_cancel: Mutex<CancellationToken>,
}

struct Session {
    sender: h2::client::SendRequest<Bytes>,
    cancel: CancellationToken,
    reusable: AtomicBool,
    active: AtomicUsize,
    /// The peer's acknowledged `SETTINGS_MAX_CONCURRENT_STREAMS`, sampled by
    /// the connection driver. `usize::MAX` until the peer advertises a limit,
    /// which is also HTTP/2's own default — so a dial racing the first
    /// SETTINGS frame is never throttled by a stale zero.
    peer_limit: Arc<AtomicUsize>,
    udp: AsyncMutex<Option<Arc<udp::Mux>>>,
}

impl Session {
    /// How many streams this connection may carry: our own configured
    /// ceiling, capped by the peer's.
    fn ceiling(&self, options: &Options) -> usize {
        options
            .max_streams
            .min(self.peer_limit.load(Ordering::Relaxed))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

struct HandshakeGuard {
    session: Arc<Session>,
    complete: bool,
}
impl Drop for HandshakeGuard {
    fn drop(&mut self) {
        if !self.complete {
            self.session.cancel.cancel();
        }
    }
}

pub(crate) struct Lease(Arc<Session>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone)]
pub struct Client(Arc<Inner>);

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) fn h2_error(error: h2::Error) -> io::Error {
    if error.is_io() {
        error
            .into_io()
            .unwrap_or_else(|| io::Error::other("HTTP/2 transport failed"))
    } else {
        io::Error::other(error)
    }
}

impl Client {
    pub fn new(connector: Arc<dyn Connector>, options: Options) -> io::Result<Self> {
        if options.username.is_empty()
            || options.username.contains(':')
            || options.password.is_empty()
            || options.username.len() + options.password.len() > 4096
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TrustTunnel requires bounded username/password; username cannot contain ':'",
            ));
        }
        if !(1..=16).contains(&options.max_connections)
            || !(1..=512).contains(&options.max_streams)
            || options.min_streams > options.max_streams
            || options.timeout.is_zero()
            || options.timeout > Duration::from_secs(30)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TrustTunnel pool limits",
            ));
        }
        let mut auth = HeaderValue::from_str(&format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", options.username, options.password))
        ))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid credentials"))?;
        auth.set_sensitive(true);
        Ok(Self(Arc::new(Inner {
            connector,
            auth,
            options,
            sessions: Mutex::new(Vec::new()),
            creating: AsyncMutex::new(()),
            generation: AtomicU64::new(1),
            network_cancel: Mutex::new(CancellationToken::new()),
        })))
    }

    pub fn reset(&self) {
        self.0.generation.fetch_add(1, Ordering::AcqRel);
        {
            // Live GOAWAY streams leave the admission pool. Cancel their
            // network generation too, without retaining a session registry.
            let mut network = lock(&self.0.network_cancel);
            network.cancel();
            *network = CancellationToken::new();
        }
        for session in lock(&self.0.sessions).drain(..) {
            session.cancel.cancel();
        }
    }

    #[cfg(test)]
    pub fn session_count(&self) -> usize {
        lock(&self.0.sessions)
            .iter()
            .filter(|s| !s.cancel.is_cancelled())
            .count()
    }

    /// Lease a pooled session that can carry one more stream, skipping
    /// `avoid` — the session a caller was just refused admission on.
    ///
    /// `Ok(None)` means "dial a new connection"; the error means the pool is
    /// out of room on both axes at once.
    fn existing(&self, avoid: Option<&Arc<Session>>) -> io::Result<Option<Lease>> {
        let mut pool = lock(&self.0.sessions);
        pool.retain(|session| {
            !session.cancel.is_cancelled() && session.reusable.load(Ordering::Acquire)
        });
        // Measured over the whole pool, not the filtered candidates: a
        // skipped or full session still occupies a connection slot.
        let at_capacity = pool.len() >= self.0.options.max_connections;
        let candidate = pool
            .iter()
            .filter(|session| !avoid.is_some_and(|busy| Arc::ptr_eq(session, busy)))
            .filter(|session| {
                session.active.load(Ordering::Acquire) < session.ceiling(&self.0.options)
            })
            .min_by_key(|session| session.active.load(Ordering::Acquire));
        let Some(session) = candidate else {
            // Nothing in the pool can take the stream. Below the connection
            // cap that is routine — the caller dials another one. At the cap
            // there is nowhere left to go, and a local-resource error says so
            // without letting `DialFailureTracker` dead-mark a healthy node
            // over our own pool ceiling.
            if at_capacity {
                return Err(meow_common::error::local_resource_limit(
                    "TrustTunnel stream limit reached",
                ));
            }
            return Ok(None);
        };
        // Spread load until every connection carries `min_streams`, then
        // pack — unless the pool cannot grow, where packing is all there is.
        let active = session.active.load(Ordering::Acquire);
        if active == 0 || active < self.0.options.min_streams || at_capacity {
            session.active.fetch_add(1, Ordering::AcqRel);
            return Ok(Some(Lease(Arc::clone(session))));
        }
        Ok(None)
    }

    async fn session(&self, avoid: Option<&Arc<Session>>) -> io::Result<Lease> {
        if let Some(lease) = self.existing(avoid)? {
            return Ok(lease);
        }
        let generation = self.0.generation.load(Ordering::Acquire);
        let _creating = self.0.creating.lock().await;
        if generation != self.0.generation.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "TrustTunnel session was reset",
            ));
        }
        if let Some(lease) = self.existing(avoid)? {
            return Ok(lease);
        }
        let cancel = lock(&self.0.network_cancel).child_token();
        let io = self.0.connector.connect().await?;
        let (sender, connection) = h2::client::Builder::new()
            .initial_window_size(131072)
            .initial_connection_window_size(2 * 1024 * 1024)
            .max_send_buffer_size(128 * 1024)
            .handshake(io)
            .await
            .map_err(h2_error)?;
        let canceled = cancel.clone();
        let peer_limit = Arc::new(AtomicUsize::new(usize::MAX));
        let sampler = Arc::clone(&peer_limit);
        spawn_scoped(async move {
            // h2 exposes the peer's `SETTINGS_MAX_CONCURRENT_STREAMS` only on
            // the connection handle, and the handle is consumed by this task
            // — so sample it here, after every poll, into a slot the pool can
            // read. Without it a connection sitting at the peer's limit is
            // indistinguishable from an idle one: `poll_ready` answers
            // `Ready` whatever the limit says (it only tracks *this* handle's
            // own pending stream), so `send_request` would queue the stream
            // as pending-open and the dial would park in `response.await`
            // until its whole deadline expired — while a sibling connection,
            // or a new one, could have carried it immediately.
            let mut connection = connection;
            let driver = std::future::poll_fn(move |cx| {
                let polled = std::future::Future::poll(std::pin::Pin::new(&mut connection), cx);
                sampler.store(connection.max_concurrent_send_streams(), Ordering::Relaxed);
                polled
            });
            tokio::select! { _ = canceled.cancelled() => {}, _ = driver => {} }
            canceled.cancel();
        });
        let session = Arc::new(Session {
            sender,
            cancel,
            reusable: AtomicBool::new(true),
            active: AtomicUsize::new(1),
            peer_limit,
            udp: AsyncMutex::new(None),
        });
        let lease = Lease(Arc::clone(&session));
        let mut handshake = HandshakeGuard {
            session: Arc::clone(&session),
            complete: false,
        };
        if self.0.options.health_check {
            let check = Lease(Arc::clone(&lease.0));
            check.0.active.fetch_add(1, Ordering::AcqRel);
            // tcp()/udp() own one deadline for pool acquisition, handshake,
            // health check and CONNECT; a second equal-duration timer cannot
            // expire before that outer deadline. No retry here: this session
            // was just handshaked, so a refusal is the connection itself
            // failing, not the recycle `connect` covers.
            let sender = Self::admit(&check)
                .await
                .ok_or_else(Self::admission_refused)?;
            drop(self.open(sender, check, "_check").await?);
        }
        // Publish under the same lock as reset: a late handshake cannot revive
        // a connection belonging to a retired network generation.
        {
            let mut pool = lock(&self.0.sessions);
            if generation != self.0.generation.load(Ordering::Acquire) {
                session.cancel.cancel();
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "TrustTunnel session was reset",
                ));
            }
            pool.push(session);
        }
        handshake.complete = true;
        Ok(lease)
    }

    /// Reserve capacity for one new stream on `lease`'s connection.
    ///
    /// `None` means the peer refused admission — a GOAWAY, or a connection
    /// on its way out — *before* any byte of the request was written. GOAWAY
    /// is unobservable until this point, so `existing()` will have handed
    /// out a session that already stopped accepting streams; the session is
    /// retired here so the caller's retry picks a different one.
    ///
    /// This cannot park on stream capacity: `poll_ready` only waits on a
    /// pending stream belonging to the same `SendRequest` handle, and each
    /// call clones a fresh one. The peer's concurrency limit is handled
    /// where it is observable instead — see `Session::ceiling`.
    async fn admit(lease: &Lease) -> Option<h2::client::SendRequest<Bytes>> {
        match lease.0.sender.clone().ready().await {
            Ok(sender) => Some(sender),
            Err(_) => {
                lease.0.reusable.store(false, Ordering::Release);
                None
            }
        }
    }

    /// Error for a peer that refused admission on two successive sessions.
    fn admission_refused() -> io::Error {
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "TrustTunnel peer refused to admit a new stream",
        )
    }

    /// Open one CONNECT stream, retrying once when the pooled session will
    /// not admit it.
    ///
    /// Retrying is safe precisely because nothing was sent: the "requests
    /// are not replayed" rule covers a request that reached the peer, not
    /// one that never left. Without the retry every routine server-side
    /// connection recycle costs one user-visible dial failure — and since
    /// the error is neither a capability nor a local-resource error, it also
    /// feeds `DialFailureTracker` toward dead-marking a healthy member.
    async fn connect(&self, authority: &str) -> io::Result<TunnelStream> {
        let lease = self.session(None).await?;
        if let Some(sender) = Self::admit(&lease).await {
            return self.open(sender, lease, authority).await;
        }
        // Release the slot before re-electing, so a session that was only
        // full is not counted as one stream busier than it is. `admit`
        // either retired that session (`existing()` drops it) or left it
        // pooled and full (`avoid` skips it) — so `session()` now reuses
        // another pooled connection, dials a fresh one, or reports the
        // stream limit. One retry, not a loop: a peer that declines twice
        // is at its limit, not recycling.
        let declined = Arc::clone(&lease.0);
        drop(lease);
        let lease = self.session(Some(&declined)).await?;
        let sender = Self::admit(&lease)
            .await
            .ok_or_else(Self::admission_refused)?;
        self.open(sender, lease, authority).await
    }

    async fn open(
        &self,
        mut sender: h2::client::SendRequest<Bytes>,
        lease: Lease,
        authority: &str,
    ) -> io::Result<TunnelStream> {
        let uri: http::Uri = authority.parse().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid CONNECT authority")
        })?;
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header("proxy-authorization", self.0.auth.clone())
            .header("user-agent", concat!("meow/", env!("CARGO_PKG_VERSION")))
            .body(())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid CONNECT request"))?;
        let end = authority == "_check";
        let (response, mut send) = sender.send_request(request, end).map_err(h2_error)?;
        let result = response.await.map_err(h2_error)?;
        if result.status() != StatusCode::OK {
            send.send_reset(h2::Reason::CANCEL);
            if result.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                lease.0.cancel.cancel();
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    AuthenticationFailed,
                ));
            }
            return Err(io::Error::other(format!(
                "TrustTunnel CONNECT returned {}",
                result.status().as_u16()
            )));
        }
        Ok(TunnelStream::new(send, result.into_body(), lease, end))
    }

    pub async fn tcp(&self, authority: &str) -> io::Result<TunnelStream> {
        if authority.starts_with('_') || !authority.contains(':') || authority.len() > 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TCP destination",
            ));
        }
        tokio::time::timeout(self.0.options.timeout, self.connect(authority))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TrustTunnel CONNECT timed out"))?
    }

    pub async fn udp(&self) -> io::Result<UdpAssociation> {
        tokio::time::timeout(self.0.options.timeout, async {
            // The same single retry `connect` does, inlined because the
            // `_udp2` mux is cached on the very session this lease names —
            // `connect` could hand back a stream on a different one.
            let mut declined: Option<Arc<Session>> = None;
            for attempt in 0..2 {
                let lease = self.session(declined.as_ref()).await?;
                let session = Arc::clone(&lease.0);
                let mut slot = session.udp.lock().await;
                if let Some(mux) = slot.as_ref().filter(|m| !m.is_closed()) {
                    return mux.associate();
                }
                let Some(sender) = Self::admit(&lease).await else {
                    drop(slot);
                    drop(lease);
                    if attempt == 0 {
                        declined = Some(session);
                        continue;
                    }
                    break;
                };
                let stream = self.open(sender, lease, "_udp2").await?;
                let mux = udp::Mux::new(stream, &session.cancel);
                *slot = Some(Arc::clone(&mux));
                return mux.associate();
            }
            Err(Self::admission_refused())
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TrustTunnel UDP CONNECT timed out"))?
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        lock(&self.network_cancel).cancel();
        for session in lock(&self.sessions).drain(..) {
            session.cancel.cancel();
        }
    }
}

fn spawn_scoped<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    use tracing::instrument::WithSubscriber;
    tokio::spawn(future.with_current_subscriber())
}

#[cfg(test)]
mod tests;
