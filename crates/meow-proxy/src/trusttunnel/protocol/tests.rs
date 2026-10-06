use super::{Client, Connector, IoStream, Options};
use async_trait::async_trait;
use bytes::Bytes;
use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct Mock {
    connections: AtomicUsize,
    reject: bool,
    malformed_udp: bool,
    goaway: bool,
    stall_check: bool,
    check_started: Arc<tokio::sync::Notify>,
    maximum_udp_reply: bool,
    zero_udp_destination: bool,
    peer_stream_limit: Option<u32>,
}
#[async_trait]
impl Connector for Mock {
    async fn connect(&self) -> io::Result<Box<dyn IoStream>> {
        self.connections.fetch_add(1, Ordering::SeqCst);
        let (client, peer) = tokio::io::duplex(8192);
        let reject = self.reject;
        let malformed = self.malformed_udp;
        let goaway = self.goaway;
        let stall_check = self.stall_check;
        let check_started = Arc::clone(&self.check_started);
        let maximum_udp_reply = self.maximum_udp_reply;
        let zero_udp_destination = self.zero_udp_destination;
        let peer_stream_limit = self.peer_stream_limit;
        tokio::spawn(async move {
            let mut builder = h2::server::Builder::new();
            if let Some(limit) = peer_stream_limit {
                builder.max_concurrent_streams(limit);
            }
            let mut server = builder.handshake(peer).await.unwrap();
            while let Some(Ok((request, mut response))) = server.accept().await {
                assert_eq!(request.method(), http::Method::CONNECT);
                assert_eq!(
                    request.headers()["proxy-authorization"],
                    "Basic Zml4dHVyZTpzZWNyZXQ="
                );
                let authority = request.uri().authority().unwrap().as_str().to_owned();
                if stall_check && authority == "_check" {
                    check_started.notify_one();
                    tokio::spawn(async move {
                        let _request = request;
                        let _response = response;
                        std::future::pending::<()>().await;
                    });
                    continue;
                }
                let status = if reject { 407 } else { 200 };
                let reply = http::Response::builder().status(status).body(()).unwrap();
                let mut send = response
                    .send_response(reply, reject || authority == "_check")
                    .unwrap();
                let mut recv = request.into_body();
                if goaway && authority == "drain.test:443" {
                    server.graceful_shutdown();
                }
                tokio::spawn(async move {
                    if reject || authority == "_check" {
                        return;
                    }
                    if authority == "hold.test:443" {
                        // Hold the peer's stream slot for the whole test:
                        // dropping either half would reset the stream and
                        // hand the slot back.
                        let _held = (recv, send);
                        std::future::pending::<()>().await;
                        return;
                    }
                    if authority == "flood.test:80" {
                        // Exceed h2's DATA-frame flood budget (256 frames
                        // per useful frame), without useful payload.
                        for _ in 0..8192 {
                            if send.send_data(Bytes::new(), false).is_err() {
                                break;
                            }
                        }
                        std::future::pending::<()>().await;
                    }
                    if authority == "_udp2" && malformed {
                        // 36-byte header + 65508-byte payload is the largest
                        // legal reply. Keep the stream open: EOF must not
                        // make a missing length guard pass this regression.
                        send.send_data(Bytes::from_static(&[0, 1, 0, 9]), false)
                            .unwrap();
                        std::future::pending::<()>().await;
                    }
                    let mut pending = Vec::new();
                    let mut special_reply_sent = false;
                    while let Some(Ok(data)) = recv.data().await {
                        recv.flow_control().release_capacity(data.len()).unwrap();
                        if authority == "_udp2" {
                            pending.extend_from_slice(&data);
                            while pending.len() >= 4 {
                                let length =
                                    u32::from_be_bytes(pending[..4].try_into().unwrap()) as usize;
                                if pending.len() < length + 4 {
                                    break;
                                }
                                let body = &pending[4..4 + length];
                                let app_len = body[36] as usize;
                                assert_eq!(app_len, 0);
                                let maximum = maximum_udp_reply && !special_reply_sent;
                                let zero_destination = zero_udp_destination && !special_reply_sent;
                                let payload = if maximum {
                                    vec![42; 65508]
                                } else {
                                    body[37 + app_len..].to_vec()
                                };
                                let mut frame = Vec::new();
                                frame.extend_from_slice(
                                    &((36 + payload.len()) as u32).to_be_bytes(),
                                );
                                frame.extend_from_slice(&body[18..36]);
                                if zero_destination {
                                    frame.extend_from_slice(&[0; 18]);
                                } else {
                                    frame.extend_from_slice(&body[..18]);
                                }
                                frame.extend_from_slice(&payload);
                                special_reply_sent = true;
                                send_all(&mut send, Bytes::from(frame)).await;
                                pending.drain(..length + 4);
                            }
                        } else {
                            send_all(&mut send, data).await;
                            if authority == "framing.test:80" {
                                send.send_data(Bytes::new(), false).unwrap();
                            }
                        }
                    }
                    let _ = send.send_data(Bytes::new(), true);
                });
            }
        });
        Ok(Box::new(client))
    }
}
async fn send_all(send: &mut h2::SendStream<Bytes>, mut data: Bytes) {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
            .await
            .unwrap()
            .unwrap();
        if capacity == 0 {
            continue;
        }
        let len = capacity.min(data.len());
        if send.send_data(data.split_to(len), false).is_err() {
            return;
        }
    }
}
fn setup(reject: bool, malformed_udp: bool) -> (Client, Arc<Mock>) {
    let mock = Arc::new(Mock {
        connections: AtomicUsize::new(0),
        reject,
        malformed_udp,
        goaway: false,
        stall_check: false,
        check_started: Arc::new(tokio::sync::Notify::new()),
        ..Mock::default()
    });
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 1;
    options.timeout = Duration::from_secs(2);
    (
        Client::new(Arc::<Mock>::clone(&mock), options).unwrap(),
        mock,
    )
}

/// A server-side connection recycle must cost nothing user-visible. The
/// GOAWAY'd connection stops admitting streams, the dial transparently lands
/// on a fresh one, and the draining stream finishes its work.
///
/// Reading the `live` echo first is the barrier that makes this
/// deterministic: the mock queues the GOAWAY frame before the echo task's
/// DATA, so a client that has read the echo has already processed the GOAWAY.
#[tokio::test]
async fn goaway_recycle_moves_the_dial_to_a_fresh_connection() {
    let mock = Arc::new(Mock {
        connections: AtomicUsize::new(0),
        reject: false,
        malformed_udp: false,
        goaway: true,
        stall_check: false,
        check_started: Arc::new(tokio::sync::Notify::new()),
        ..Mock::default()
    });
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 1;
    let client = Client::new(Arc::<Mock>::clone(&mock), options).unwrap();
    let mut stream = client.tcp("drain.test:443").await.unwrap();
    stream.write_all(b"live").await.unwrap();
    let mut bytes = [0; 4];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"live");
    // Nothing had been written when admission was refused, so re-electing a
    // session is not a request replay — and without it every routine recycle
    // would surface as a dial failure that also feeds `DialFailureTracker`
    // toward dead-marking a healthy member.
    let _next = client
        .tcp("new.test:80")
        .await
        .expect("a recycle must not be a user-visible dial failure");
    assert_eq!(mock.connections.load(Ordering::SeqCst), 2);
    stream.write_all(b"safe").await.unwrap();
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"safe");
    // The second dial reuses the fresh connection rather than growing again.
    let _reused = client.tcp("new.test:80").await.unwrap();
    assert_eq!(mock.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn tcp_large_transfer_half_close_reuse_and_stream_drop_isolation() {
    let (client, mock) = setup(false, false);
    let first = client.tcp("example.test:443").await.unwrap();
    let mut second = client.tcp("[::1]:443").await.unwrap();
    drop(first);
    let payload = vec![0x6a; 1024 * 1024];
    let expected = payload.clone();
    let (mut read, mut write) = tokio::io::split(second);
    let send = tokio::spawn(async move {
        write.write_all(&payload).await.unwrap();
        write.shutdown().await.unwrap();
    });
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), read.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    send.await.unwrap();
    assert_eq!(received, expected);
    assert_eq!(mock.connections.load(Ordering::SeqCst), 1);
    second = client.tcp("new.test:80").await.unwrap();
    second.write_all(b"still alive").await.unwrap();
    let mut buffer = [0; 11];
    second.read_exact(&mut buffer).await.unwrap();
    assert_eq!(&buffer, b"still alive");
}

#[tokio::test]
async fn udp_multiplex_ipv4_ipv6_empty_max_payload_and_duplicate_source() {
    let (client, mock) = setup(false, false);
    let a = client.udp().await.unwrap();
    let b = client.udp().await.unwrap();
    assert_ne!(a.local_addr(), b.local_addr());
    let destinations: [SocketAddr; 3] = [
        "127.0.0.1:53".parse().unwrap(),
        "[2001:db8::2]:53".parse().unwrap(),
        "[::1]:53".parse().unwrap(),
    ];
    for (peer, destination, data) in [
        (&a, destinations[0], vec![]),
        (&b, destinations[1], vec![8; 65434]),
        (&a, destinations[2], b"ipv6 loopback".to_vec()),
    ] {
        peer.send_to(&data, destination).await.unwrap();
        let mut buffer = vec![0; 65507];
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(3), peer.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(source, destination);
        assert_eq!(&buffer[..length], data);
    }
    a.close();
    assert!(a.send_to(b"closed", destinations[0]).await.is_err());
    b.send_to(b"other survives", destinations[1]).await.unwrap();
    let mut buffer = [0; 64];
    let (n, _) = b.recv_from(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..n], b"other survives");
    assert_eq!(mock.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn authentication_failure_retires_session_without_replaying() {
    let (client, mock) = setup(true, false);
    let error = client.tcp("example.test:80").await.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(client.session_count(), 0);
    assert_eq!(mock.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn reset_closes_pending_reads_and_next_dial_creates_new_session() {
    let (client, mock) = setup(false, false);
    let a = client.udp().await.unwrap();
    let mut tcp = client.tcp("example.test:80").await.unwrap();
    client.reset();
    let mut buffer = [0; 64];
    assert!(
        tokio::time::timeout(Duration::from_secs(1), a.recv_from(&mut buffer))
            .await
            .unwrap()
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(1), tcp.read(&mut buffer))
            .await
            .unwrap()
            .is_err()
    );
    let _new = client.tcp("example.test:80").await.unwrap();
    assert_eq!(mock.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn maximum_legal_udp_reply_keeps_other_associations_alive() {
    let mock = Arc::new(Mock {
        maximum_udp_reply: true,
        ..Mock::default()
    });
    let client = Client::new(mock, Options::new("fixture".into(), "secret".into())).unwrap();
    let a = client.udp().await.unwrap();
    let b = client.udp().await.unwrap();
    let target = "[2001:db8::1]:53".parse().unwrap();
    a.send_to(b"maximum reply", target).await.unwrap();
    let mut buffer = vec![0; 65508];
    let (length, source) = tokio::time::timeout(Duration::from_secs(2), a.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source, target);
    assert_eq!(length, 65508);
    assert!(buffer.iter().all(|byte| *byte == 42));
    b.send_to(b"other survives", target).await.unwrap();
    let (length, source) = tokio::time::timeout(Duration::from_secs(1), b.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source, target);
    assert_eq!(&buffer[..length], b"other survives");
    assert_eq!(client.session_count(), 1);
}

#[tokio::test]
async fn oversized_udp_send_is_dropped_without_failing_the_flow() {
    let (client, _) = setup(false, false);
    let association = client.udp().await.unwrap();
    let session = Arc::clone(&super::lock(&client.0.sessions)[0]);
    let mux = Arc::clone(session.udp.lock().await.as_ref().unwrap());
    let target = "192.0.2.2:53".parse().unwrap();
    for length in [65435, 65507, 65508] {
        // Reported as sent, on purpose: `handle_udp` tears the NAT entry
        // down on any `write_packet` error, so one jumbo datagram must not
        // cost every other flow sharing the association.
        let sent = association
            .send_to(&vec![42; length], target)
            .await
            .expect("an undersizable datagram must not fail the association");
        assert_eq!(sent, length);
    }
    assert_eq!(mux.dropped_oversized.load(Ordering::Relaxed), 3);
    association.send_to(b"valid", target).await.unwrap();
    let mut buffer = [0; 16];
    let (length, _) =
        tokio::time::timeout(Duration::from_secs(1), association.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        &buffer[..length],
        b"valid",
        "dropped payload must never enter the send queue"
    );
}

#[tokio::test]
async fn short_udp_buffers_truncate_and_consume_the_whole_datagram() {
    let (client, _) = setup(false, false);
    let association = client.udp().await.unwrap();
    let target = "192.0.2.2:53".parse().unwrap();
    association.send_to(b"abcdefgh", target).await.unwrap();
    let mut buffer = [0; 3];
    let (length, source) = association.recv_from(&mut buffer).await.unwrap();
    assert_eq!((length, source), (3, target));
    assert_eq!(&buffer, b"abc");
    association.send_to(b"discard", target).await.unwrap();
    assert_eq!(association.recv_from(&mut []).await.unwrap(), (0, target));
    association.send_to(b"new", target).await.unwrap();
    let (length, _) = association.recv_from(&mut buffer).await.unwrap();
    assert_eq!((&buffer[..length], length), (b"new".as_slice(), 3));
}

#[tokio::test]
async fn unmatched_udp_reply_is_counted_without_guessing_an_association() {
    let mock = Arc::new(Mock {
        zero_udp_destination: true,
        ..Mock::default()
    });
    let client = Client::new(mock, Options::new("fixture".into(), "secret".into())).unwrap();
    let association = client.udp().await.unwrap();
    let session = Arc::clone(&super::lock(&client.0.sessions)[0]);
    let mux = Arc::clone(session.udp.lock().await.as_ref().unwrap());
    let target = "192.0.2.2:53".parse().unwrap();
    association.send_to(b"unmatched", target).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while mux.dropped_unmatched.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("an unrouteable reply must be observable");
    association.send_to(b"matched", target).await.unwrap();
    let mut buffer = [0; 32];
    let (length, _) =
        tokio::time::timeout(Duration::from_secs(1), association.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(&buffer[..length], b"matched");
    assert_eq!(mux.dropped_unmatched.load(Ordering::Relaxed), 1);
    assert_eq!(client.session_count(), 1);
}

#[tokio::test]
async fn oversized_udp_frame_disconnects_bounded_reader() {
    let (client, _) = setup(false, true);
    let a = client.udp().await.unwrap();
    let mut buffer = [0; 64];
    assert!(
        tokio::time::timeout(Duration::from_secs(1), a.recv_from(&mut buffer))
            .await
            .expect("oversized header must cancel the association without waiting for EOF")
            .is_err()
    );
}

#[tokio::test]
async fn legal_empty_frames_between_payloads_keep_reused_session_alive() {
    let (client, mock) = setup(false, false);
    let mut stream = client.tcp("framing.test:80").await.unwrap();
    let body = [42; 1024];
    for _ in 0..300 {
        stream.write_all(&body).await.unwrap();
        let mut reply = [0; 1024];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, body);
    }
    assert_eq!(mock.connections.load(Ordering::SeqCst), 1);
    client.reset();
}

#[tokio::test]
async fn empty_frame_flood_still_closes_connection_with_bounded_budget() {
    let (client, _) = setup(false, false);
    let mut stream = client.tcp("flood.test:80").await.unwrap();
    let error = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut [0; 1]))
        .await
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("too_many_data_frames"));
}

#[tokio::test]
async fn reset_also_closes_goaway_streams_removed_from_the_admission_pool() {
    let mock = Arc::new(Mock {
        connections: AtomicUsize::new(0),
        reject: false,
        malformed_udp: false,
        goaway: true,
        stall_check: false,
        check_started: Arc::new(tokio::sync::Notify::new()),
        ..Mock::default()
    });
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 1;
    let client = Client::new(mock, options).unwrap();
    let mut stream = client.tcp("drain.test:443").await.unwrap();
    stream.write_all(b"live").await.unwrap();
    stream.read_exact(&mut [0; 4]).await.unwrap();
    let _retired = client.tcp("retire.test:80").await.unwrap();
    let _new = client.tcp("new.test:80").await.unwrap();
    client.reset();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), stream.read(&mut [0; 1]))
            .await
            .expect("retired session survived network reset")
            .is_err()
    );
}

#[tokio::test]
async fn udp_association_limit_is_local_and_recovers_after_drop() {
    let (client, _) = setup(false, false);
    let mut associations = Vec::new();
    for _ in 0..128 {
        associations.push(client.udp().await.unwrap());
    }
    let error = client.udp().await.err().unwrap();
    assert!(meow_common::MeowError::Io(error).is_local_resource_error());
    associations.pop();
    client.udp().await.unwrap();
}

#[tokio::test]
async fn shared_udp_budget_drops_are_counted_and_recover() {
    let (client, _) = setup(false, false);
    let association = client.udp().await.unwrap();
    let session = Arc::clone(&super::lock(&client.0.sessions)[0]);
    let mux = Arc::clone(session.udp.lock().await.as_ref().unwrap());
    let budget = Arc::clone(&mux.budget)
        .try_acquire_many_owned(4 * 1024 * 1024)
        .unwrap();
    let target = "192.0.2.2:53".parse().unwrap();
    association.send_to(b"drop", target).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while mux.dropped_budget.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shared-budget pressure must be observable");
    drop(budget);
    association.send_to(b"live", target).await.unwrap();
    let mut buffer = [0; 16];
    let (length, source) =
        tokio::time::timeout(Duration::from_secs(1), association.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(source, target);
    assert_eq!(&buffer[..length], b"live");
    assert_eq!(mux.dropped_budget.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn stalled_health_check_times_out_without_publishing_a_session() {
    let mock = Arc::new(Mock {
        connections: AtomicUsize::new(0),
        reject: false,
        malformed_udp: false,
        goaway: false,
        stall_check: true,
        check_started: Arc::new(tokio::sync::Notify::new()),
        ..Mock::default()
    });
    let mut options = Options::new("fixture".into(), "secret".into());
    options.health_check = true;
    options.timeout = Duration::from_millis(500);
    let client = Client::new(Arc::<Mock>::clone(&mock), options).unwrap();
    let first = client.tcp("example.test:80");
    tokio::pin!(first);
    tokio::select! {
        result = &mut first => panic!("dial finished before the pending check: {}", result.is_ok()),
        () = mock.check_started.notified() => {},
    }
    assert_eq!(
        client.session_count(),
        0,
        "unchecked session must stay private"
    );
    assert_eq!(mock.connections.load(Ordering::SeqCst), 1);
    let (first, concurrent) = tokio::join!(first, client.tcp("concurrent.test:80"));
    let error = first.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(error.to_string(), "TrustTunnel CONNECT timed out");
    assert_eq!(concurrent.err().unwrap().kind(), io::ErrorKind::TimedOut);
    assert_eq!(client.session_count(), 0);
    let next = tokio::time::timeout(Duration::from_secs(1), client.tcp("next.test:80"))
        .await
        .expect("creation lock must be released after a failed check")
        .err()
        .unwrap();
    assert_eq!(next.kind(), io::ErrorKind::TimedOut);
    assert_eq!(client.session_count(), 0);
}

#[tokio::test]
async fn stalled_udp_health_check_uses_the_outer_connect_deadline() {
    let mock = Arc::new(Mock {
        stall_check: true,
        ..Mock::default()
    });
    let mut options = Options::new("fixture".into(), "secret".into());
    options.health_check = true;
    options.timeout = Duration::from_millis(100);
    let client = Client::new(Arc::<Mock>::clone(&mock), options).unwrap();
    for _ in 0..2 {
        let error = client.udp().await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "TrustTunnel UDP CONNECT timed out");
        assert_eq!(client.session_count(), 0);
    }
    assert_eq!(mock.connections.load(Ordering::SeqCst), 2);
}

/// A connection sitting at the peer's `SETTINGS_MAX_CONCURRENT_STREAMS` is
/// indistinguishable from an idle one in our own accounting, so admission is
/// where the limit shows up. Parking there would spend the caller's entire
/// dial deadline on a connection that cannot serve it while a sibling could:
/// the dial has to move on instead.
#[tokio::test]
async fn peer_stream_limit_moves_the_dial_to_another_connection() {
    let mock = Arc::new(Mock {
        peer_stream_limit: Some(1),
        check_started: Arc::new(tokio::sync::Notify::new()),
        ..Mock::default()
    });
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 2;
    let client = Client::new(Arc::<Mock>::clone(&mock), options).unwrap();
    // Occupy the peer's only stream slot and never release it.
    let _held = client.tcp("hold.test:443").await.unwrap();
    let mut stream = tokio::time::timeout(Duration::from_secs(3), client.tcp("next.test:80"))
        .await
        .expect("a full connection must not burn the whole dial deadline")
        .expect("a sibling connection must carry the dial");
    assert_eq!(mock.connections.load(Ordering::SeqCst), 2);
    stream.write_all(b"second").await.unwrap();
    let mut bytes = [0; 6];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"second");
}

/// Same situation at the connection cap: there is nowhere left to go, and
/// saying so beats a timeout. The distinction matters because
/// `DialFailureTracker` dead-marks a member on an ordinary dial error but
/// not on a local-resource one — a local pool ceiling is not the node being
/// broken.
#[tokio::test]
async fn peer_stream_limit_at_the_connection_cap_is_a_local_resource_error() {
    let mock = Arc::new(Mock {
        peer_stream_limit: Some(1),
        check_started: Arc::new(tokio::sync::Notify::new()),
        ..Mock::default()
    });
    let mut options = Options::new("fixture".into(), "secret".into());
    options.max_connections = 1;
    let client = Client::new(Arc::<Mock>::clone(&mock), options).unwrap();
    let _held = client.tcp("hold.test:443").await.unwrap();
    let error = tokio::time::timeout(Duration::from_secs(3), client.tcp("next.test:80"))
        .await
        .expect("the dial must give up long before its own deadline")
        .err()
        .unwrap();
    assert!(
        meow_common::MeowError::Io(error).is_local_resource_error(),
        "a pool ceiling must not dead-mark the node"
    );
    assert_eq!(mock.connections.load(Ordering::SeqCst), 1);
}
