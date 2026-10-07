//! The HTTP/3 transport against a real HTTP/3 endpoint.
//!
//! The peer below is an actual QUIC server — self-signed certificate,
//! BoringSSL handshake, `quiche::h3` request handling — because that is the
//! only way to cover what this transport actually adds: ALPN, per-connection
//! stream credit, HTTP/3 flow control in both directions, the FIN on each
//! half, and the driver's read/write pumps under backpressure. The protocol
//! above it (the pool, the `_udp2` codec, the CONNECT headers) is shared with
//! HTTP/2 and tested over a mock in `protocol/tests.rs`; what is re-asserted
//! here is only that it reaches the wire unchanged.

use super::QuicConnector;
use crate::trusttunnel::protocol::{Client, ExtraHeaders, Options};
use quiche::h3::{self, NameValue as _};
use std::{
    collections::{hash_map::Entry, HashMap},
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UdpSocket,
};

/// Server→client UDP frames carry no App Name byte (§11.2), unlike the
/// client's own; both sides share the 36-byte address pair.
const HEADER: usize = 36;

/// One CONNECT request as the endpoint received it, pseudo-headers included.
#[derive(Clone, Debug)]
struct Capture {
    authority: String,
    headers: Vec<(String, String)>,
}

impl Capture {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(seen, _)| seen == name)
            .map(|(_, value)| value.as_str())
    }

    fn count(&self, name: &str) -> usize {
        self.headers.iter().filter(|(seen, _)| seen == name).count()
    }
}

/// How the endpoint under test behaves.
#[derive(Clone, Copy, Default)]
struct Behaviour {
    /// Answer every CONNECT with 407 instead of 200.
    reject: bool,
    /// Bidirectional streams the client may open (quiche's own default when
    /// `None`), i.e. the credit the pool has to work with.
    stream_limit: Option<u64>,
    /// Negotiate this ALPN instead of `h3`.
    alpn: Option<&'static [u8]>,
}

struct Endpoint {
    addr: SocketAddr,
    captured: Arc<Mutex<Vec<Capture>>>,
    connections: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Endpoint {
    /// The first CONNECT the endpoint saw for `authority`.
    fn capture(&self, authority: &str) -> Capture {
        let captured = self.captured.lock().unwrap();
        captured
            .iter()
            .find(|capture| capture.authority == authority)
            .unwrap_or_else(|| panic!("no CONNECT for {authority} in {captured:?}"))
            .clone()
    }

    fn captures(&self, authority: &str) -> Vec<Capture> {
        self.captured
            .lock()
            .unwrap()
            .iter()
            .filter(|capture| capture.authority == authority)
            .cloned()
            .collect()
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn endpoint(behaviour: Behaviour) -> Endpoint {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn(serve(
        socket,
        behaviour,
        Arc::clone(&captured),
        Arc::clone(&connections),
    ));
    Endpoint {
        addr,
        captured,
        connections,
        task,
    }
}

fn options() -> Options {
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 1;
    options.timeout = Duration::from_secs(10);
    options
}

/// A client whose pooled connections are QUIC connections to `endpoint`. The
/// certificate is self-signed, hence `skip-cert-verify`; the server name is
/// still sent, and still what quiche would verify against.
fn connect(endpoint: &Endpoint, options: Options) -> Client {
    let connector = QuicConnector::new(
        &endpoint.addr.ip().to_string(),
        endpoint.addr.port(),
        "localhost",
        true,
        options.timeout,
    )
    .unwrap();
    Client::new(Arc::new(connector), options).unwrap()
}

// ---------------------------------------------------------------- the server

struct ServerStream {
    /// `_udp2`: the payload is length-prefixed datagram frames rather than a
    /// byte stream, so it is echoed frame by frame with the tuple swapped.
    udp: bool,
    /// Payload waiting for HTTP/3 send capacity.
    out: Vec<u8>,
    /// Partially received `_udp2` frame.
    frames: Vec<u8>,
    client_fin: bool,
    fin_sent: bool,
}

impl ServerStream {
    fn new(udp: bool) -> Self {
        Self {
            udp,
            out: Vec::new(),
            frames: Vec::new(),
            client_fin: false,
            fin_sent: false,
        }
    }

    fn absorb(&mut self, data: &[u8]) {
        if !self.udp {
            self.out.extend_from_slice(data);
            return;
        }
        self.frames.extend_from_slice(data);
        while self.frames.len() >= 4 {
            let length = u32::from_be_bytes(self.frames[..4].try_into().unwrap()) as usize;
            if self.frames.len() < 4 + length {
                break;
            }
            let body = &self.frames[4..4 + length];
            assert_eq!(body[HEADER], 0, "the client must send an empty App Name");
            let payload = &body[HEADER + 1..];
            // The client's destination is the reply's source: that round trip
            // is how an association recognises its own datagrams.
            let mut frame = Vec::with_capacity(4 + HEADER + payload.len());
            frame.extend_from_slice(&u32::try_from(HEADER + payload.len()).unwrap().to_be_bytes());
            frame.extend_from_slice(&body[18..HEADER]);
            frame.extend_from_slice(&body[..18]);
            frame.extend_from_slice(payload);
            self.out.extend_from_slice(&frame);
            self.frames.drain(..4 + length);
        }
    }
}

struct Peer {
    conn: quiche::Connection,
    h3: Option<h3::Connection>,
    streams: HashMap<u64, ServerStream>,
}

impl Peer {
    fn step(
        &mut self,
        config: &h3::Config,
        behaviour: Behaviour,
        captured: &Mutex<Vec<Capture>>,
        body: &mut [u8],
    ) {
        let Self { conn, h3, streams } = self;
        if h3.is_none() && conn.is_established() {
            *h3 = Some(h3::Connection::with_transport(conn, config).expect("h3 server"));
        }
        let Some(http3) = h3.as_mut() else {
            return;
        };
        loop {
            match http3.poll(conn) {
                Ok((id, h3::Event::Headers { list, .. })) => {
                    assert_eq!(text(&list, b":method"), "CONNECT");
                    let authority = text(&list, b":authority");
                    captured.lock().unwrap().push(Capture {
                        authority: authority.clone(),
                        headers: list
                            .iter()
                            .map(|header| {
                                (
                                    String::from_utf8_lossy(header.name()).into_owned(),
                                    String::from_utf8_lossy(header.value()).into_owned(),
                                )
                            })
                            .collect(),
                    });
                    let status: &[u8] = if behaviour.reject { b"407" } else { b"200" };
                    // A refusal and a health check are both complete answers;
                    // a tunnel's response is only the head of the stream.
                    let fin = behaviour.reject || authority == "_check";
                    http3
                        .send_response(conn, id, &[h3::Header::new(b":status", status)], fin)
                        .expect("send response");
                    if !fin {
                        streams.insert(id, ServerStream::new(authority == "_udp2"));
                    }
                }
                Ok((id, h3::Event::Data)) => loop {
                    match http3.recv_body(conn, id, body) {
                        Ok(read) if read > 0 => {
                            if let Some(stream) = streams.get_mut(&id) {
                                stream.absorb(&body[..read]);
                            }
                        }
                        // Drained, or gone: either way nothing more to read
                        // until HTTP/3 re-arms the event.
                        _ => break,
                    }
                },
                Ok((id, h3::Event::Finished)) => {
                    if let Some(stream) = streams.get_mut(&id) {
                        stream.client_fin = true;
                    }
                }
                Ok((id, h3::Event::Reset(_))) => {
                    streams.remove(&id);
                }
                Ok((_, h3::Event::GoAway | h3::Event::PriorityUpdate)) => {}
                Err(_) => break,
            }
        }
        for (&id, stream) in &mut *streams {
            while !stream.out.is_empty() {
                match http3.send_body(conn, id, &stream.out, false) {
                    Ok(0) | Err(_) => break,
                    Ok(written) => {
                        stream.out.drain(..written);
                    }
                }
            }
            // Echo the client's FIN back once everything it sent is out.
            if stream.out.is_empty() && stream.client_fin && !stream.fin_sent {
                stream.fin_sent = http3.send_body(conn, id, &[], true).is_ok();
            }
        }
        streams.retain(|_, stream| !stream.fin_sent);
    }
}

fn text(list: &[h3::Header], name: &[u8]) -> String {
    list.iter()
        .find(|header| header.name() == name)
        .map(|header| String::from_utf8_lossy(header.value()).into_owned())
        .unwrap_or_default()
}

fn server_config(behaviour: Behaviour) -> quiche::Config {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut ssl = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
    ssl.set_certificate(&boring::x509::X509::from_der(key.cert.der()).unwrap())
        .unwrap();
    ssl.set_private_key(
        &boring::pkey::PKey::private_key_from_der(&key.key_pair.serialize_der()).unwrap(),
    )
    .unwrap();
    let mut config =
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl).unwrap();
    config
        .set_application_protos(&[behaviour.alpn.unwrap_or(super::tls::ALPN_H3)])
        .unwrap();
    config.set_max_idle_timeout(30_000);
    config.set_initial_max_data(16 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(1024 * 1024);
    config.set_initial_max_stream_data_bidi_remote(1024 * 1024);
    config.set_initial_max_stream_data_uni(1024 * 1024);
    config.set_initial_max_streams_bidi(behaviour.stream_limit.unwrap_or(32));
    config.set_initial_max_streams_uni(8);
    config
}

async fn serve(
    socket: UdpSocket,
    behaviour: Behaviour,
    captured: Arc<Mutex<Vec<Capture>>>,
    connections: Arc<AtomicUsize>,
) {
    let local = socket.local_addr().unwrap();
    let mut config = server_config(behaviour);
    let h3_config = h3::Config::new().unwrap();
    // Keyed on the client's address: every connection this client dials owns
    // its own socket, so one entry per connection — which is what lets the
    // tests count connections and serve several at once.
    let mut peers: HashMap<SocketAddr, Peer> = HashMap::new();
    let mut incoming = vec![0u8; 65535];
    let mut outgoing = vec![0u8; 1350];
    let mut body = vec![0u8; 64 * 1024];
    loop {
        let timeout = peers.values().filter_map(|peer| peer.conn.timeout()).min();
        tokio::select! {
            result = socket.recv_from(&mut incoming) => {
                let Ok((n, from)) = result else { continue };
                if let Entry::Vacant(slot) = peers.entry(from) {
                    let Ok(header) =
                        quiche::Header::from_slice(&mut incoming[..n], quiche::MAX_CONN_ID_LEN)
                    else {
                        continue;
                    };
                    if header.ty != quiche::Type::Initial {
                        continue;
                    }
                    let conn = quiche::accept(&header.dcid, None, local, from, &mut config)
                        .expect("accept");
                    connections.fetch_add(1, Ordering::SeqCst);
                    slot.insert(Peer { conn, h3: None, streams: HashMap::new() });
                }
                let peer = peers.get_mut(&from).expect("just inserted");
                let info = quiche::RecvInfo { from, to: local };
                let _ = peer.conn.recv(&mut incoming[..n], info);
            }
            () = sleep_opt(timeout) => {
                for peer in peers.values_mut() {
                    peer.conn.on_timeout();
                }
            }
        }
        for peer in peers.values_mut() {
            peer.step(&h3_config, behaviour, &captured, &mut body);
            while let Ok((written, info)) = peer.conn.send(&mut outgoing) {
                let _ = socket.send_to(&outgoing[..written], info.to).await;
            }
        }
        peers.retain(|_, peer| !peer.conn.is_closed());
    }
}

async fn sleep_opt(timeout: Option<Duration>) {
    match timeout {
        Some(duration) => tokio::time::sleep(duration).await,
        None => std::future::pending().await,
    }
}

// ----------------------------------------------------------------- the tests

/// A tunnelled stream over QUIC, past every window in the path (the driver's
/// 64 KiB write budget, 16 KiB DATA chunks, the peer's 1 MiB stream window),
/// then a half-close in each direction and a second stream on the same
/// connection — the whole read pump, write pump and FIN path in one flow.
#[tokio::test]
async fn tcp_stream_round_trips_through_flow_control_and_half_closes() {
    let endpoint = endpoint(Behaviour::default()).await;
    let client = connect(&endpoint, options());
    let stream = client.tcp("example.test:443").await.unwrap();
    let payload = vec![0x6a; 512 * 1024];
    let expected = payload.clone();
    let (mut read, mut write) = tokio::io::split(stream);
    let sending = tokio::spawn(async move {
        write.write_all(&payload).await.unwrap();
        write.shutdown().await.unwrap();
    });
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), read.read_to_end(&mut received))
        .await
        .expect("echo did not finish")
        .unwrap();
    sending.await.unwrap();
    assert_eq!(received, expected);
    // The connection outlives the stream that just ended on it.
    let mut next = client.tcp("second.test:80").await.unwrap();
    next.write_all(b"still alive").await.unwrap();
    let mut buffer = [0; 11];
    next.read_exact(&mut buffer).await.unwrap();
    assert_eq!(&buffer, b"still alive");
    assert_eq!(endpoint.connections(), 1);
    assert_eq!(client.session_count(), 1);
}

/// The HTTP/3 request carries the same credential, spec-shaped `user-agent`
/// and operator headers as the HTTP/2 one — and, per RFC 9114 §4.4, a CONNECT
/// field section with no `:scheme` and no `:path`.
#[tokio::test]
async fn connect_requests_carry_the_credential_user_agent_and_extra_headers() {
    let mut options = options();
    options.health_check = true;
    options.platform = "ios".into();
    options.app_name = "AdGuard".into();
    options.headers =
        ExtraHeaders::new(&[("x-padding".into(), "<random-string(16)>".into())], 8).unwrap();
    let endpoint = endpoint(Behaviour::default()).await;
    let client = connect(&endpoint, options);
    let _tunnel = client.tcp("example.test:443").await.unwrap();
    let _datagrams = client.udp().await.unwrap();

    let tunnel = endpoint.capture("example.test:443");
    assert_eq!(tunnel.header(":method"), Some("CONNECT"));
    assert_eq!(tunnel.header(":scheme"), None);
    assert_eq!(tunnel.header(":path"), None);
    assert_eq!(
        tunnel.header("proxy-authorization"),
        Some("Basic Zml4dHVyZTpzZWNyZXQ=")
    );
    assert_eq!(tunnel.count("user-agent"), 1);
    assert_eq!(tunnel.header("user-agent"), Some("ios AdGuard"));
    assert_eq!(
        endpoint.capture("_udp2").header("user-agent"),
        Some("ios _udp2")
    );
    assert_eq!(endpoint.capture("_check").header("user-agent"), Some("ios"));
    assert_eq!(tunnel.header("x-padding").map(str::len), Some(16));
    assert_eq!(endpoint.connections(), 1);
}

#[tokio::test]
async fn refused_credentials_report_an_authentication_failure() {
    let endpoint = endpoint(Behaviour {
        reject: true,
        ..Behaviour::default()
    })
    .await;
    let client = connect(&endpoint, options());
    let error = client.tcp("example.test:80").await.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(client.session_count(), 0);
    assert_eq!(endpoint.connections(), 1);
}

/// Both associations share one `_udp2` stream on one QUIC connection, and a
/// reply reaches the association whose minted source tuple it names.
#[tokio::test]
async fn udp_associations_multiplex_over_one_connect_stream() {
    let endpoint = endpoint(Behaviour::default()).await;
    let client = connect(&endpoint, options());
    let a = client.udp().await.unwrap();
    let b = client.udp().await.unwrap();
    assert_ne!(a.local_addr(), b.local_addr());
    for (peer, destination, data) in [
        (
            &a,
            "127.0.0.1:53".parse::<SocketAddr>().unwrap(),
            b"query".to_vec(),
        ),
        (&b, "[2001:db8::2]:53".parse().unwrap(), vec![7; 4096]),
        (&a, "[::1]:53".parse().unwrap(), Vec::new()),
    ] {
        peer.send_to(&data, destination).await.unwrap();
        let mut buffer = vec![0; 65507];
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(10), peer.recv_from(&mut buffer))
                .await
                .expect("no datagram came back")
                .unwrap();
        assert_eq!(source, destination);
        assert_eq!(&buffer[..length], &data[..]);
    }
    assert_eq!(endpoint.captures("_udp2").len(), 1);
    assert_eq!(endpoint.connections(), 1);
}

/// QUIC hands out stream credit, and a connection that has spent its credit
/// is full rather than broken. The pool has to move the dial to another
/// connection, and at the connection cap report its *own* limit — a plain
/// dial failure there would feed `DialFailureTracker` toward dead-marking a
/// perfectly healthy endpoint.
#[tokio::test]
async fn exhausted_stream_credit_spreads_then_reports_a_local_limit() {
    let endpoint = endpoint(Behaviour {
        stream_limit: Some(2),
        ..Behaviour::default()
    })
    .await;
    let mut options = options();
    options.max_connections = 2;
    let client = connect(&endpoint, options);
    let mut held = Vec::new();
    for index in 0..4 {
        let mut stream = client.tcp(&format!("hold{index}.test:443")).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut bytes = [0; 4];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ping");
        held.push(stream);
    }
    assert_eq!(endpoint.connections(), 2, "two streams per connection");
    let error = client.tcp("one.too.many.test:443").await.err().unwrap();
    assert!(
        meow_common::MeowError::Io(error).is_local_resource_error(),
        "a spent stream budget is our own limit, not an unhealthy endpoint"
    );
    assert_eq!(endpoint.connections(), 2);
}

/// PROTOCOL.md §3.2 allows exactly one ALPN. An endpoint that negotiates
/// anything else is refused, and refused as a handshake failure rather than
/// parking the dial until its deadline.
#[tokio::test]
async fn an_endpoint_that_does_not_speak_h3_is_refused() {
    let endpoint = endpoint(Behaviour {
        alpn: Some(b"hq-interop"),
        ..Behaviour::default()
    })
    .await;
    let client = connect(&endpoint, options());
    let error = client.tcp("example.test:443").await.err().unwrap();
    assert_ne!(error.kind(), io::ErrorKind::TimedOut, "{error}");
    assert_eq!(client.session_count(), 0);
    assert_eq!(endpoint.connections(), 1);
}

/// A dial that gives up while the QUIC handshake is still pending must take
/// its driver task with it.
///
/// This transport spawns the driver *before* the handshake resolves — it is
/// what drives the handshake — so an abandoned dial is the one case where the
/// task outlives every handle to it. Nothing else would retire it: dropping
/// the `CancellationToken` does not cancel it, and quiche keeps retransmitting
/// Initial packets at an endpoint nobody is dialling any more. A silent
/// endpoint makes that visible as packets arriving after the dial has failed.
#[tokio::test]
async fn a_dial_abandoned_mid_handshake_leaves_no_driver_behind() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = silent.local_addr().unwrap();
    let seen = Arc::new(AtomicUsize::new(0));
    let counting = Arc::clone(&seen);
    let sink = tokio::spawn(async move {
        let mut buffer = vec![0u8; 2048];
        while silent.recv_from(&mut buffer).await.is_ok() {
            counting.fetch_add(1, Ordering::SeqCst);
        }
    });
    let mut options = options();
    options.timeout = Duration::from_millis(300);
    let connector = QuicConnector::new(
        &addr.ip().to_string(),
        addr.port(),
        "localhost",
        true,
        options.timeout,
    )
    .unwrap();
    let client = Client::new(Arc::new(connector), options).unwrap();
    let error = client.tcp("example.test:443").await.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
    let settled = seen.load(Ordering::SeqCst);
    assert!(settled > 0, "the dial never reached the endpoint");
    // Past quiche's first PTO (~1 s, from its 333 ms initial RTT estimate):
    // a driver still dialling would have retransmitted by now.
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert_eq!(
        seen.load(Ordering::SeqCst),
        settled,
        "an abandoned dial's driver is still talking to the endpoint"
    );
    sink.abort();
}

#[tokio::test]
async fn reset_closes_live_streams_and_the_next_dial_redials() {
    let endpoint = endpoint(Behaviour::default()).await;
    let client = connect(&endpoint, options());
    let association = client.udp().await.unwrap();
    let mut tcp = client.tcp("example.test:80").await.unwrap();
    client.reset();
    let mut buffer = [0; 64];
    assert!(
        tokio::time::timeout(Duration::from_secs(5), association.recv_from(&mut buffer))
            .await
            .expect("the association must not hang")
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut buffer))
            .await
            .expect("the stream must not hang")
            .is_err()
    );
    let _new = client.tcp("example.test:80").await.unwrap();
    assert_eq!(endpoint.connections(), 2);
}
