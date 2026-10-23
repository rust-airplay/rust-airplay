// SPDX-License-Identifier: GPL-3.0-or-later
//! End-to-end checks of the network control service.
//!
//! Every case opens a real TCP connection to a [`Server`] the test bound to an
//! ephemeral port, so the framing, the bounded reads and the connection
//! lifecycle are exercised the way a client exercises them, not through the
//! control layer alone.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rust_airplay::fairplay::FairPlaySession;
use rust_airplay::plist::{self, Plist};
use rust_airplay::server::{DeviceIdentity, RouteHandlers, Server, ServerConfig};
use rust_airplay::server::{
    PairingState, PinMode, RandomError, RandomSource, SessionAuth, SetParameter, SetupPorts,
    SetupStream,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// A bound server plus the address it listens on.
struct TestServer {
    address: std::net::SocketAddr,
    task: tokio::task::JoinHandle<io::Result<()>>,
}

impl TestServer {
    /// Starts a server whose handlers for each connection come from `handlers`.
    async fn start_with<F>(config: ServerConfig, handlers: F) -> Self
    where
        F: Fn() -> RouteHandlers + Send + 'static,
    {
        let server = Server::bind(config).await.expect("bind");
        let address = server.local_addr().expect("local_addr");
        let task = tokio::spawn(async move { server.run(handlers).await });
        Self { address, task }
    }

    /// Starts a server that serves `handlers`' identity and reports feedback.
    async fn start(config: ServerConfig, handlers: RouteHandlers) -> Self {
        let identity = handlers.identity().clone();
        Self::start_with(config, move || {
            let mut handlers = RouteHandlers::new(identity.clone());
            handlers.set_feedback_callback(|| {});
            handlers
        })
        .await
    }

    async fn connect(&self) -> TcpStream {
        TcpStream::connect(self.address).await.expect("connect")
    }

    fn shutdown(self) {
        self.task.abort();
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Reads one complete response from `stream`, keeping unconsumed bytes in
/// `pending`.
///
/// Returns `None` when the server closed the connection, or when nothing
/// arrived within `wait`.
async fn read_response(
    stream: &mut TcpStream,
    pending: &mut Vec<u8>,
    wait: Duration,
) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        if let Some(end) = find(pending, b"\r\n\r\n") {
            let declared = header_value(&pending[..end], "content-length")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            let total = end + 4 + declared;
            if pending.len() >= total {
                let message = pending[..total].to_vec();
                pending.drain(..total);
                return Some(message);
            }
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let mut chunk = [0u8; 4096];
        match timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return None,
            Ok(Ok(read)) => pending.extend_from_slice(&chunk[..read]),
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn header_value<'a>(head: &'a [u8], name: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(head).ok()?;
    text.split("\r\n").skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn identity() -> DeviceIdentity {
    DeviceIdentity::new("aa:bb:cc:dd:ee:ff", "Integration Receiver", vec![9; 32])
}

fn local_config() -> ServerConfig {
    ServerConfig {
        bind: "127.0.0.1:0".parse().expect("address"),
        idle_timeout: Duration::from_secs(60),
        ..ServerConfig::default()
    }
}

/// Measures how many control requests the service answers per second.
///
/// Ignored by default: the numbers depend on the machine, so this is a
/// measurement rather than an assertion. Run it with
/// `cargo test -p airplay-core --test server_spec -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "measurement, not an assertion"]
async fn measures_control_plane_throughput() {
    type Build = fn(usize) -> String;
    let server = TestServer::start(local_config(), RouteHandlers::new(identity())).await;
    let cases: [(&str, usize, Build); 2] = [
        ("OPTIONS (no body)", 4_000, |index| {
            format!("OPTIONS * RTSP/1.0\r\nCSeq: {index}\r\n\r\n")
        }),
        ("GET /info (binary plist)", 1_000, |index| {
            format!("GET /info RTSP/1.0\r\nCSeq: {index}\r\n\r\n")
        }),
    ];
    for (label, count, build) in cases {
        let mut client = server.connect().await;
        let mut requests = Vec::new();
        for index in 0..count {
            requests.extend_from_slice(build(index).as_bytes());
        }
        let started = std::time::Instant::now();
        client.write_all(&requests).await.expect("write");
        client.shutdown().await.expect("shutdown");
        let mut responses = Vec::new();
        client.read_to_end(&mut responses).await.expect("read");
        let elapsed = started.elapsed();
        let answered = responses
            .windows(15)
            .filter(|window| *window == b"RTSP/1.0 200 OK")
            .count();
        assert_eq!(answered, count, "{label}: every request is answered");
        println!(
            "{label}: {answered} requests, {:.1} KiB back, {elapsed:?} total, {:.0} req/s, {:.1} us/request",
            responses.len() as f64 / 1024.0,
            answered as f64 / elapsed.as_secs_f64(),
            elapsed.as_secs_f64() * 1e6 / answered as f64
        );
    }
    server.shutdown();
}

#[tokio::test]
async fn answers_get_info_over_the_socket() {
    let server = TestServer::start(local_config(), RouteHandlers::new(identity())).await;
    let mut client = server.connect().await;
    client
        .write_all(b"GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n")
        .await
        .expect("write");

    let mut pending = Vec::new();
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("response");
    // The body is a binary plist, so only the head is text.
    let head_end = find(&response, b"\r\n\r\n").expect("header terminator");
    assert!(
        response.starts_with(b"RTSP/1.0 200 OK\r\n"),
        "unexpected status line: {}",
        String::from_utf8_lossy(&response[..head_end])
    );
    assert_eq!(
        header_value(&response[..head_end], "Audio-Jack-Status"),
        Some("connected; type=digital")
    );
    assert_eq!(
        header_value(&response[..head_end], "Server"),
        Some("AirTunes/220.68")
    );
    assert_eq!(header_value(&response[..head_end], "CSeq"), Some("1"));
    assert_eq!(
        header_value(&response[..head_end], "Content-Length"),
        Some((response.len() - head_end - 4).to_string().as_str())
    );

    let parsed = Plist::parse(&response[head_end + 4..]).expect("binary plist");
    assert_eq!(
        parsed.get_string("deviceID").expect("deviceID"),
        "aa:bb:cc:dd:ee:ff"
    );
    assert_eq!(parsed.get_data("pk").expect("pk"), vec![9; 32]);
    server.shutdown();
}

#[tokio::test]
async fn frames_two_pipelined_requests_written_at_once() {
    let server = TestServer::start(local_config(), RouteHandlers::new(identity())).await;
    let mut client = server.connect().await;
    client
        .write_all(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\nGET /info RTSP/1.0\r\nCSeq: 2\r\n\r\n")
        .await
        .expect("write");

    let mut pending = Vec::new();
    let first = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("first response");
    let second = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("second response");

    let first = String::from_utf8_lossy(&first).to_string();
    assert!(first.contains("CSeq: 1\r\n"));
    assert!(first.contains(
        "Public: SETUP, RECORD, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER\r\n"
    ));
    let second = String::from_utf8_lossy(&second).to_string();
    assert!(second.contains("CSeq: 2\r\n"));
    assert!(second.contains("Content-Type: application/x-apple-binary-plist\r\n"));
    server.shutdown();
}

#[tokio::test]
async fn waits_for_a_request_split_across_writes() {
    let server = TestServer::start(local_config(), RouteHandlers::new(identity())).await;
    let mut client = server.connect().await;
    client
        .write_all(b"GET /info RTSP/1.0\r\nCSeq: ")
        .await
        .expect("first half");
    let mut pending = Vec::new();
    assert!(
        read_response(&mut client, &mut pending, Duration::from_millis(150))
            .await
            .is_none(),
        "a partial request must not be answered"
    );
    client.write_all(b"7\r\n\r\n").await.expect("second half");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("response");
    assert!(String::from_utf8_lossy(&response).contains("CSeq: 7\r\n"));
    server.shutdown();
}

#[tokio::test]
async fn rejects_an_oversized_head_and_closes() {
    let server = TestServer::start(local_config(), RouteHandlers::new(identity())).await;
    let mut client = server.connect().await;
    let oversized = vec![b'a'; 80 * 1024];
    // The server closes as soon as it rejects the head, so the tail of this
    // write may fail with a broken pipe; the response is what matters.
    let _ = client.write_all(&oversized).await;

    let mut pending = Vec::new();
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("rejection");
    let text = String::from_utf8_lossy(&response).to_string();
    assert!(
        text.starts_with("RTSP/1.0 431 Request Header Fields Too Large\r\n"),
        "{text}"
    );
    assert!(!text.contains("Server:"));
    server.shutdown();
}

#[tokio::test]
async fn rejects_a_malformed_request_and_closes() {
    let server = TestServer::start(local_config(), RouteHandlers::new(identity())).await;
    let mut client = server.connect().await;
    client
        .write_all(b"GET /info RTSP/1.0\r\nBad Header\r\n\r\n")
        .await
        .expect("write");

    let mut pending = Vec::new();
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("rejection");
    assert!(
        String::from_utf8_lossy(&response).starts_with("RTSP/1.0 400 Bad Request\r\n"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    // The connection is closed, so the next read sees end of stream.
    let mut rest = Vec::new();
    assert_eq!(client.read_to_end(&mut rest).await.expect("read"), 0);
    server.shutdown();
}

#[tokio::test]
async fn teardown_closes_the_connection() {
    let server = TestServer::start(local_config(), RouteHandlers::new(identity())).await;
    let mut client = server.connect().await;
    client
        .write_all(b"TEARDOWN * RTSP/1.0\r\nCSeq: 4\r\n\r\n")
        .await
        .expect("write");

    let mut pending = Vec::new();
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("response");
    assert!(String::from_utf8_lossy(&response).contains("Connection: close\r\n"));
    let mut rest = Vec::new();
    assert_eq!(client.read_to_end(&mut rest).await.expect("read"), 0);
    server.shutdown();
}

#[tokio::test]
async fn reports_feedback_to_the_application() {
    let counter = Arc::new(AtomicUsize::new(0));
    let server = Server::bind(local_config()).await.expect("bind");
    let address = server.local_addr().expect("local_addr");
    let task = {
        let counter = Arc::clone(&counter);
        let identity = identity();
        tokio::spawn(async move {
            server
                .run(move || {
                    let mut handlers = RouteHandlers::new(identity.clone());
                    let counter = Arc::clone(&counter);
                    handlers.set_feedback_callback(move || {
                        counter.fetch_add(1, Ordering::SeqCst);
                    });
                    handlers
                })
                .await
        })
    };

    let mut client = TcpStream::connect(address).await.expect("connect");
    client
        .write_all(b"POST /feedback RTSP/1.0\r\nCSeq: 9\r\nContent-Length: 0\r\n\r\n")
        .await
        .expect("write");
    let mut pending = Vec::new();
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("response");
    assert!(String::from_utf8_lossy(&response).starts_with("RTSP/1.0 200 OK\r\n"));
    // The callback runs on the server task, so give it a moment to be observed.
    for _ in 0..50 {
        if counter.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    task.abort();
}

#[tokio::test]
async fn answers_fairplay_setup_with_its_opaque_reply() {
    let server = TestServer::start(local_config(), RouteHandlers::new(identity())).await;
    let mut client = server.connect().await;
    let mut challenge = [0u8; 16];
    challenge[4] = 0x03;
    let mut request = Vec::new();
    request.extend_from_slice(b"POST /fp-setup RTSP/1.0\r\nCSeq: 3\r\nContent-Length: 16\r\n\r\n");
    request.extend_from_slice(&challenge);
    client.write_all(&request).await.expect("write");

    let mut pending = Vec::new();
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("response");
    let head_end = find(&response, b"\r\n\r\n").expect("header terminator");
    assert_eq!(
        header_value(&response[..head_end], "Content-Type"),
        Some("application/octet-stream")
    );
    assert_eq!(response.len() - head_end - 4, 142);
    server.shutdown();
}

#[tokio::test]
async fn serves_no_more_than_the_configured_number_of_connections() {
    let config = ServerConfig {
        max_connections: 1,
        ..local_config()
    };
    let server = TestServer::start(config, RouteHandlers::new(identity())).await;

    // This connection takes the only slot and then stays quiet.
    let mut first = server.connect().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut second = server.connect().await;
    second
        .write_all(b"GET /info RTSP/1.0\r\nCSeq: 5\r\n\r\n")
        .await
        .expect("write");
    let mut pending = Vec::new();
    assert!(
        read_response(&mut second, &mut pending, Duration::from_millis(300))
            .await
            .is_none(),
        "a connection past the limit must not be served"
    );

    // Closing the first connection frees the slot, and the second is served.
    first.shutdown().await.expect("shutdown");
    drop(first);
    let response = read_response(&mut second, &mut pending, Duration::from_secs(5))
        .await
        .expect("response once a slot is free");
    assert!(String::from_utf8_lossy(&response).starts_with("RTSP/1.0 200 OK\r\n"));
    server.shutdown();
}

#[tokio::test]
async fn setup_derives_the_audio_key_and_answers_the_configured_ports() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let ports = SetupPorts {
        timing_port: Some(7011),
        event_port: Some(0),
        data_port: Some(6000),
        control_port: Some(6001),
        mirror_data_port: Some(7100),
    };
    let server = TestServer::start_with(local_config(), {
        let seen = Arc::clone(&seen);
        move || {
            let mut handlers = RouteHandlers::new(identity());
            handlers.set_setup_ports(ports);
            let seen = Arc::clone(&seen);
            handlers.set_setup_callback(move |request| seen.lock().expect("lock").push(request));
            handlers
        }
    })
    .await;
    let mut client = server.connect().await;
    let mut pending = Vec::new();

    // The key the receiver unwraps comes from its own FairPlay session, so the
    // test establishes one over the socket and fingerprints it with a second,
    // independent session fed the same messages.
    let mut challenge = [0u8; 16];
    challenge[4] = 0x03;
    let mut handshake = [0u8; 164];
    handshake[4] = 0x03;
    for request in [&challenge[..], &handshake[..]] {
        client
            .write_all(&request_with_body("POST /fp-setup", "", request))
            .await
            .expect("write");
        read_response(&mut client, &mut pending, Duration::from_secs(5))
            .await
            .expect("fairplay response");
    }
    let mut reference = FairPlaySession::new();
    reference.setup(&challenge).expect("reference setup");
    reference
        .handshake(&handshake)
        .expect("reference handshake");
    let ekey = vec![0x11u8; 72];
    let expected_key = reference.decrypt(&ekey).expect("reference decrypt");

    let body = binary_plist(vec![
        ("ekey", plist::Value::Data(ekey)),
        ("eiv", plist::Value::Data(vec![0x22; 16])),
        (
            "streams",
            plist::Value::Array(vec![plist::dictionary([
                ("type", plist::Value::from(96u64)),
                ("controlPort", plist::Value::from(6000u64)),
            ])]),
        ),
    ]);
    client
        .write_all(&request_with_body(
            "SETUP /stream",
            "Content-Type: application/x-apple-binary-plist\r\n",
            &body,
        ))
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("setup response");
    assert!(
        response.starts_with(b"RTSP/1.0 200 OK\r\n"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let (head, body) = response_parts(&response);
    assert_eq!(
        header_value(head, "Content-Type"),
        Some("application/x-apple-binary-plist")
    );
    let answer = Plist::parse(body).expect("binary plist");
    assert_eq!(answer.get_unsigned("timingPort").expect("timingPort"), 7011);
    assert_eq!(answer.get_unsigned("eventPort").expect("eventPort"), 0);
    let streams = answer.get_array("streams").expect("streams");
    assert_eq!(streams.len(), 1);
    let stream = streams[0].as_dictionary().expect("stream");
    assert_eq!(stream.get("type").unwrap().as_unsigned_integer(), Some(96));
    assert_eq!(
        stream.get("dataPort").unwrap().as_unsigned_integer(),
        Some(6000)
    );
    assert_eq!(
        stream.get("controlPort").unwrap().as_unsigned_integer(),
        Some(6001)
    );

    // The session layer saw the unwrapped key, the IV, the requested stream and
    // the level of pairing this connection reached (none here).
    {
        let seen = seen.lock().expect("lock");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].audio_key, Some(expected_key));
        assert_eq!(seen[0].audio_iv, Some([0x22; 16]));
        assert_eq!(seen[0].authentication, SessionAuth::None);
        assert_eq!(
            seen[0].streams,
            vec![SetupStream {
                kind: 96,
                stream_connection_id: None,
                compression_type: None,
                samples_per_frame: None,
            }]
        );
    }

    // A key of the wrong length is refused instead of answered with a session
    // nobody can use, and a request without a property list is refused too.
    let short_key = binary_plist(vec![
        ("ekey", plist::Value::Data(vec![0u8; 71])),
        ("eiv", plist::Value::Data(vec![0u8; 16])),
    ]);
    for request in [
        request_with_body("SETUP /stream", "", &short_key),
        request_with_body("SETUP /stream", "", b"not a plist"),
    ] {
        client.write_all(&request).await.expect("write");
        let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
            .await
            .expect("rejection");
        assert!(
            String::from_utf8_lossy(&response).starts_with("RTSP/1.0 400 Bad Request\r\n"),
            "{}",
            String::from_utf8_lossy(&response)
        );
    }
    server.shutdown();
}

#[tokio::test]
async fn setup_hashes_the_audio_key_with_a_verified_pairing_secret() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let state = pairing_state(PinMode::Fixed(1234));
    let server = TestServer::start_with(local_config(), {
        let state = Arc::clone(&state);
        let seen = Arc::clone(&seen);
        move || {
            let mut handlers = RouteHandlers::with_pairing(pairing_identity(), Arc::clone(&state));
            let seen = Arc::clone(&seen);
            handlers.set_setup_callback(move |request| seen.lock().expect("lock").push(request));
            handlers
        }
    })
    .await;
    let mut client = server.connect().await;
    let mut pending = Vec::new();

    let mut challenge = [0u8; 16];
    challenge[4] = 0x03;
    let mut handshake = [0u8; 164];
    handshake[4] = 0x03;
    for request in [&challenge[..], &handshake[..]] {
        client
            .write_all(&request_with_body("POST /fp-setup", "", request))
            .await
            .expect("write");
        read_response(&mut client, &mut pending, Duration::from_secs(5))
            .await
            .expect("fairplay response");
    }
    let mut reference = FairPlaySession::new();
    reference.setup(&challenge).expect("reference setup");
    reference
        .handshake(&handshake)
        .expect("reference handshake");

    // Legacy setup opens the key exchange, then the client verifies itself.
    client
        .write_all(&request_with_body("POST /pair-setup", "", &[0u8; 32]))
        .await
        .expect("write");
    read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("setup response");

    let private = [0x21u8; 32];
    let public = rust_airplay::crypto::x25519_public(&private);
    let identity_seed = [0x33u8; 32];
    let identity_public = rust_airplay::crypto::ed25519_public_key(&identity_seed);
    let mut handshake_body = vec![1u8, 0, 0, 0];
    handshake_body.extend_from_slice(&public);
    handshake_body.extend_from_slice(&identity_public);
    client
        .write_all(&request_with_body("POST /pair-verify", "", &handshake_body))
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("handshake response");
    let (_, body) = response_parts(&response);
    let server_ecdh: [u8; 32] = body[..32].try_into().expect("server key");
    let shared = rust_airplay::crypto::x25519_shared(&private, &server_ecdh);

    let keys = rust_airplay::pairing::derive_pair_verify_keys(&shared);
    let mut signature =
        rust_airplay::crypto::ed25519_sign(&identity_seed, &[public, server_ecdh].concat());
    let mut cipher = rust_airplay::crypto::Aes128CtrState::new(&keys.key, &keys.iv).expect("ctr");
    let mut discarded = [0u8; 64];
    cipher.apply(&mut discarded);
    cipher.apply(&mut signature);
    let mut finish = vec![0u8, 0, 0, 0];
    finish.extend_from_slice(&signature);
    client
        .write_all(&request_with_body("POST /pair-verify", "", &finish))
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("finish response");
    assert!(
        response.starts_with(b"RTSP/1.0 200 OK\r\n"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    // Now SETUP has to mix the unwrapped audio key with the verified secret.
    let ekey = vec![0x11u8; 72];
    let fairplay_key = reference.decrypt(&ekey).expect("reference decrypt");
    let body = binary_plist(vec![
        ("ekey", plist::Value::Data(ekey)),
        ("eiv", plist::Value::Data(vec![0x22; 16])),
    ]);
    client
        .write_all(&request_with_body("SETUP /stream", "", &body))
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("setup response");
    assert!(response.starts_with(b"RTSP/1.0 200 OK\r\n"));

    let expected = rust_airplay::crypto::sha512_concat(&[&fairplay_key, &shared]);
    {
        let requests = seen.lock().expect("lock");
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].audio_key,
            Some(expected[..16].try_into().expect("key"))
        );
        assert_eq!(requests[0].authentication, SessionAuth::Verified);
        assert_eq!(requests[0].client_identity, Some(identity_public));
    }

    // The connection's material was handed out, so a second SETUP cannot reuse
    // it: the key stays the plain FairPlay one.
    client
        .write_all(&request_with_body("SETUP /stream", "", &body))
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("second setup");
    assert!(response.starts_with(b"RTSP/1.0 200 OK\r\n"));
    {
        let requests = seen.lock().expect("lock");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].audio_key, Some(fairplay_key));
    }
    server.shutdown();
}

#[tokio::test]
async fn parameters_report_volume_and_progress_and_answer_451_without_a_content_type() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let server = TestServer::start_with(local_config(), {
        let seen = Arc::clone(&seen);
        move || {
            let mut handlers = RouteHandlers::new(identity());
            let seen = Arc::clone(&seen);
            handlers.set_parameter_callback(move |parameter| {
                seen.lock().expect("lock").push(parameter)
            });
            handlers
        }
    })
    .await;
    let mut client = server.connect().await;
    let mut pending = Vec::new();

    // Both routes refuse a request that does not say what it carries
    // (raop_handlers.h:1135-1139 and :1079-1083).
    for method in ["SET_PARAMETER", "GET_PARAMETER"] {
        client
            .write_all(&request_with_body(
                &format!("{method} /stream"),
                "",
                b"volume: 0.5\r\n",
            ))
            .await
            .expect("write");
        let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
            .await
            .expect("response");
        assert_eq!(
            String::from_utf8_lossy(&response)
                .split("\r\n")
                .next()
                .unwrap_or_default(),
            "RTSP/1.0 451 Parameter not understood",
            "{method}"
        );
    }

    // A volume and a progress line reach the session layer.
    for (body, expected) in [
        (&b"volume: -15.0\r\n"[..], SetParameter::Volume(-15.0)),
        (
            &b"progress: 1/2/3\r\n"[..],
            SetParameter::Progress {
                start: 1,
                current: 2,
                end: 3,
            },
        ),
    ] {
        client
            .write_all(&request_with_body(
                "SET_PARAMETER /stream",
                "Content-Type: text/parameters\r\n",
                body,
            ))
            .await
            .expect("write");
        let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
            .await
            .expect("response");
        assert!(response.starts_with(b"RTSP/1.0 200 OK\r\n"));
        assert_eq!(
            *seen.lock().expect("lock").last().expect("reported"),
            expected,
            "{expected:?}"
        );
    }
    let reported = seen.lock().expect("lock").len();

    // Cover art belongs to the media layer, so it is answered without being
    // reported, and a value no media layer could use is not reported either.
    for (content_type, body) in [
        ("Content-Type: image/jpeg\r\n", &b"\xff\xd8\xff"[..]),
        (
            "Content-Type: text/parameters\r\n",
            &b"volume: not a number\r\n"[..],
        ),
    ] {
        client
            .write_all(&request_with_body(
                "SET_PARAMETER /stream",
                content_type,
                body,
            ))
            .await
            .expect("write");
        let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
            .await
            .expect("response");
        assert!(response.starts_with(b"RTSP/1.0 200 OK\r\n"));
    }
    assert_eq!(seen.lock().expect("lock").len(), reported);

    // A client that asks about the volume gets the value upstream falls back to
    // when it has no media callback.
    client
        .write_all(&request_with_body(
            "GET_PARAMETER /stream",
            "Content-Type: text/parameters\r\n",
            b"volume\r\n",
        ))
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("response");
    let (head, body) = response_parts(&response);
    assert_eq!(header_value(head, "Content-Type"), Some("text/parameters"));
    assert_eq!(body, b"volume: -15.000000\r\n");
    server.shutdown();
}

#[tokio::test]
async fn a_trace_reports_what_a_request_asked_and_what_it_got() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let server = TestServer::start_with(local_config(), {
        let seen = Arc::clone(&seen);
        move || {
            let mut handlers = RouteHandlers::new(identity());
            let seen = Arc::clone(&seen);
            handlers.set_trace_callback(move |trace| {
                seen.lock().expect("lock").push((
                    trace.method.to_owned(),
                    trace.target.to_owned(),
                    trace.cseq,
                    trace.content_type.map(str::to_owned),
                    trace.body_len,
                    trace.status,
                    trace.active_remote.map(str::to_owned),
                    trace.dacp_id.map(str::to_owned),
                ));
            });
            handlers
        }
    })
    .await;
    let mut client = server.connect().await;
    let mut pending = Vec::new();

    // A request the control layer answers itself, one a handler serves, and one
    // this handler does not implement: all three are traced.
    for request in [
        request_with_body("OPTIONS *", "", b""),
        request_with_body("GET /info", "Content-Type: text/parameters\r\n", b"body"),
        request_with_body("GET_PARAMETER /stream", "", b""),
        request_with_body(
            "SETUP /stream",
            "Active-Remote: 12345\r\nDACP-ID: dacp-1\r\n",
            b"",
        ),
    ] {
        client.write_all(&request).await.expect("write");
        read_response(&mut client, &mut pending, Duration::from_secs(5))
            .await
            .expect("response");
    }

    let seen = seen.lock().expect("lock");
    assert_eq!(seen.len(), 4, "{seen:?}");
    assert_eq!(seen[0].0, "OPTIONS");
    assert_eq!(seen[0].2, Some(1));
    assert_eq!(seen[0].4, 0);
    assert_eq!(seen[0].5, 200);
    assert_eq!(seen[1].0, "GET");
    assert_eq!(seen[1].1, "/info");
    assert_eq!(seen[1].3.as_deref(), Some("text/parameters"));
    assert_eq!(seen[1].4, 4);
    assert_eq!(seen[1].5, 200);
    // A parameter request that does not say what it carries is refused with
    // upstream's status, and the trace reports what the client got rather than
    // what was intended.
    assert_eq!(seen[2].0, "GET_PARAMETER");
    assert_eq!(seen[2].5, 451);
    // The remote-control identifiers reach the caller, and are reported as what
    // they are: values a client wrote.
    assert_eq!(seen[3].6.as_deref(), Some("12345"));
    assert_eq!(seen[3].7.as_deref(), Some("dacp-1"));
    drop(seen);
    server.shutdown();
}

/// Concurrent connections keep their own pairing state.
///
/// One client's key exchange must not touch another's, and two clients asking at
/// the same time must get two different receiver keys: that is the property the
/// per-connection state exists for, and it is only visible under concurrency.
#[tokio::test]
async fn concurrent_connections_pair_independently() {
    let state = pairing_state(PinMode::Fixed(1234));
    let server = TestServer::start_with(local_config(), pairing_handlers(Arc::clone(&state))).await;

    let mut tasks = Vec::new();
    for index in 0..4u8 {
        let address = server.address;
        tasks.push(tokio::spawn(async move {
            let mut client = TcpStream::connect(address).await.expect("connect");
            let mut pending = Vec::new();
            client
                .write_all(&request_with_body("POST /pair-setup", "", &[0u8; 32]))
                .await
                .expect("write");
            read_response(&mut client, &mut pending, Duration::from_secs(5))
                .await
                .expect("setup response");
            // Each client uses its own key pair, so the shared secret differs;
            // what must differ here is the receiver's ephemeral key.
            let private = [0x40 + index; 32];
            let public = rust_airplay::crypto::x25519_public(&private);
            let identity_seed = [0x50 + index; 32];
            let identity_public = rust_airplay::crypto::ed25519_public_key(&identity_seed);
            let mut handshake = vec![1u8, 0, 0, 0];
            handshake.extend_from_slice(&public);
            handshake.extend_from_slice(&identity_public);
            client
                .write_all(&request_with_body("POST /pair-verify", "", &handshake))
                .await
                .expect("write");
            let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
                .await
                .expect("handshake response");
            assert!(response.starts_with(b"RTSP/1.0 200 OK\r\n"));
            let (_, body) = response_parts(&response);
            (body[..32].to_vec(), identity_public)
        }));
    }

    let mut receiver_keys = Vec::new();
    for task in tasks {
        let (key, _) = task.await.expect("task");
        receiver_keys.push(key);
    }
    receiver_keys.sort();
    receiver_keys.dedup();
    assert_eq!(
        receiver_keys.len(),
        4,
        "every connection must get its own receiver key"
    );
    server.shutdown();
}

/// Failed passwords add up across connections, and the bound stops the guessing
/// even for a client that then presents the right password.
#[tokio::test]
async fn password_failures_are_counted_across_connections() {
    let password = "secret";
    let state = Arc::new(
        PairingState::with_random(
            [0x5a; 32],
            PinMode::Disabled,
            Box::new(FixedRandom { next: 1 }),
        )
        .with_password(password),
    );
    let server = TestServer::start_with(local_config(), pairing_handlers(Arc::clone(&state))).await;

    for attempt in 0..6 {
        let mut client = server.connect().await;
        let mut pending = Vec::new();
        client
            .write_all(&request_with_body("SETUP /stream", "", b"bplist00"))
            .await
            .expect("write");
        let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
            .await
            .expect("challenge");
        let (head, _) = response_parts(&response);
        let nonce = header_value(head, "WWW-Authenticate")
            .and_then(|challenge| challenge.split_once("nonce=\""))
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(nonce, _)| nonce.to_owned())
            .expect("challenge nonce");
        // The last attempt uses the right password: past the bound it must be
        // refused like the others, which is what makes the bound a bound.
        let offered = if attempt < 5 { "wrong" } else { password };
        let digest = rust_airplay::pairing::digest_auth_response(
            "SETUP", "client", "raop", offered, &nonce, "/stream", None, None, None,
        );
        let authorization = format!(
            "Authorization: Digest username=\"client\", realm=\"raop\", nonce=\"{nonce}\", uri=\"/stream\", response=\"{digest}\"\r\n"
        );
        client
            .write_all(&request_with_body(
                "SETUP /stream",
                &authorization,
                b"bplist00",
            ))
            .await
            .expect("write");
        let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
            .await
            .expect("answer");
        assert!(
            response.starts_with(b"RTSP/1.0 401 Unauthorized\r\n"),
            "attempt {attempt}: {}",
            String::from_utf8_lossy(&response)
        );
    }
    assert_eq!(state.password_failures(), 5);
    server.shutdown();
}

/// More connections than the receiver serves wait for a slot instead of being
/// dropped, and are served as soon as one is free.
#[tokio::test]
async fn surplus_connections_wait_for_a_slot() {
    let server = TestServer::start_with(local_config(), || RouteHandlers::new(identity())).await;
    let limit = rust_airplay::server::MAX_CONNECTIONS;

    // Fill every slot and hold the connections open without sending anything.
    let mut holding = Vec::new();
    for _ in 0..limit {
        holding.push(server.connect().await);
    }
    let mut surplus = server.connect().await;
    surplus
        .write_all(&request_with_body("OPTIONS *", "", b""))
        .await
        .expect("write");
    // The connection is queued, not refused: no answer arrives while the slots
    // are taken, and the socket is not closed.
    let mut pending = Vec::new();
    assert!(
        timeout(
            Duration::from_millis(300),
            read_response(&mut surplus, &mut pending, Duration::from_secs(5))
        )
        .await
        .is_err(),
        "a queued connection must not be answered before a slot frees up"
    );

    drop(holding.pop());
    let response = read_response(&mut surplus, &mut pending, Duration::from_secs(5))
        .await
        .expect("the queued connection is served once a slot frees up");
    assert!(response.starts_with(b"RTSP/1.0 200 OK\r\n"));
    server.shutdown();
}

/// Measures the rate of `SETUP` requests on one connection, after the FairPlay
/// handshake they need. Ignored like the other measurement: it asserts nothing
/// and takes seconds.
#[tokio::test]
#[ignore = "measurement, not an assertion"]
async fn measures_setup_throughput() {
    let server = TestServer::start_with(local_config(), || RouteHandlers::new(identity())).await;
    let mut client = server.connect().await;
    let mut pending = Vec::new();
    let mut challenge = [0u8; 16];
    challenge[4] = 0x03;
    let mut handshake = [0u8; 164];
    handshake[4] = 0x03;
    for request in [&challenge[..], &handshake[..]] {
        client
            .write_all(&request_with_body("POST /fp-setup", "", request))
            .await
            .expect("write");
        read_response(&mut client, &mut pending, Duration::from_secs(5))
            .await
            .expect("fairplay response");
    }
    let body = binary_plist(vec![
        ("ekey", plist::Value::Data(vec![0x11; 72])),
        ("eiv", plist::Value::Data(vec![0x22; 16])),
        (
            "streams",
            plist::Value::Array(vec![plist::dictionary([(
                "type",
                plist::Value::from(96u64),
            )])]),
        ),
    ]);
    let request = request_with_body("SETUP /stream", "", &body);
    let iterations = 300;

    let started = std::time::Instant::now();
    for _ in 0..iterations {
        client.write_all(&request).await.expect("write");
        read_response(&mut client, &mut pending, Duration::from_secs(5))
            .await
            .expect("setup response");
    }
    let elapsed = started.elapsed();
    println!(
        "SETUP: {iterations} requests in {elapsed:?} -> {:.1} req/s ({:.1} µs each)",
        f64::from(iterations) / elapsed.as_secs_f64(),
        elapsed.as_secs_f64() * 1e6 / f64::from(iterations)
    );
    server.shutdown();
}

/// Deterministic random source, so a pairing test can predict the PIN, the salt
/// and the ephemeral keys.
struct FixedRandom {
    next: u8,
}

impl RandomSource for FixedRandom {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), RandomError> {
        for byte in output.iter_mut() {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
        Ok(())
    }
}

fn pairing_identity() -> DeviceIdentity {
    DeviceIdentity::new("aa:bb:cc:dd:ee:ff", "Pairing Receiver", Vec::new())
}

fn pairing_state(pin_mode: PinMode) -> Arc<PairingState> {
    Arc::new(PairingState::with_random(
        [0x5a; 32],
        pin_mode,
        Box::new(FixedRandom { next: 1 }),
    ))
}

/// Handler factory that pairs every connection with the same receiver state.
fn pairing_handlers(state: Arc<PairingState>) -> impl Fn() -> RouteHandlers + Send + 'static {
    move || RouteHandlers::with_pairing(pairing_identity(), Arc::clone(&state))
}

#[tokio::test]
async fn setup_asks_for_a_password_once_and_then_accepts_the_digest() {
    let password = "secret";
    let state = Arc::new(
        PairingState::with_random(
            [0x5a; 32],
            PinMode::Disabled,
            Box::new(FixedRandom { next: 1 }),
        )
        .with_password(password),
    );
    let server = TestServer::start_with(local_config(), {
        let state = Arc::clone(&state);
        move || RouteHandlers::with_pairing(pairing_identity(), Arc::clone(&state))
    })
    .await;
    let mut client = server.connect().await;
    let mut pending = Vec::new();

    // The key unwrapping needs a FairPlay session, so establish one first.
    let mut challenge = [0u8; 16];
    challenge[4] = 0x03;
    let mut handshake = [0u8; 164];
    handshake[4] = 0x03;
    for request in [&challenge[..], &handshake[..]] {
        client
            .write_all(&request_with_body("POST /fp-setup", "", request))
            .await
            .expect("write");
        read_response(&mut client, &mut pending, Duration::from_secs(5))
            .await
            .expect("fairplay response");
    }

    // A request without a digest is challenged before its body is looked at: the
    // body here is not even a property list.
    client
        .write_all(&request_with_body("SETUP /stream", "", b"not a plist"))
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("challenge");
    assert!(
        response.starts_with(b"RTSP/1.0 401 Unauthorized\r\n"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let (head, _) = response_parts(&response);
    let challenge = header_value(head, "WWW-Authenticate").expect("challenge header");
    assert!(challenge.starts_with("Digest realm=\"raop\", nonce=\""));
    let nonce = challenge
        .split_once("nonce=\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(nonce, _)| nonce.to_owned())
        .expect("nonce in the challenge");
    assert_eq!(
        nonce.len(),
        32,
        "the challenge carries a 32 character nonce"
    );

    // The client answers with the digest it computes from the same fields.
    let digest = rust_airplay::pairing::digest_auth_response(
        "SETUP", "client", "raop", password, &nonce, "/stream", None, None, None,
    );
    let authorization = format!(
        "Authorization: Digest username=\"client\", realm=\"raop\", nonce=\"{nonce}\", uri=\"/stream\", response=\"{digest}\"\r\n"
    );
    let body = binary_plist(vec![
        ("ekey", plist::Value::Data(vec![0x11; 72])),
        ("eiv", plist::Value::Data(vec![0x22; 16])),
    ]);
    client
        .write_all(&request_with_body("SETUP /stream", &authorization, &body))
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("answer");
    assert!(
        response.starts_with(b"RTSP/1.0 200 OK\r\n"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    // The challenge was single use, but the connection is authenticated now, so
    // the same digest is not needed a second time.
    client
        .write_all(&request_with_body("SETUP /stream", &authorization, &body))
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("repeat");
    assert!(response.starts_with(b"RTSP/1.0 200 OK\r\n"));

    // A wrong password on another connection is refused, and the failure is
    // counted on the shared state.
    let mut other = server.connect().await;
    let mut pending = Vec::new();
    other
        .write_all(&request_with_body("SETUP /stream", "", &body))
        .await
        .expect("write");
    let response = read_response(&mut other, &mut pending, Duration::from_secs(5))
        .await
        .expect("challenge");
    let (head, _) = response_parts(&response);
    let nonce = header_value(head, "WWW-Authenticate")
        .and_then(|challenge| challenge.split_once("nonce=\""))
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(nonce, _)| nonce.to_owned())
        .expect("nonce");
    let wrong = rust_airplay::pairing::digest_auth_response(
        "SETUP", "client", "raop", "wrong", &nonce, "/stream", None, None, None,
    );
    let authorization = format!(
        "Authorization: Digest username=\"client\", realm=\"raop\", nonce=\"{nonce}\", uri=\"/stream\", response=\"{wrong}\"\r\n"
    );
    other
        .write_all(&request_with_body("SETUP /stream", &authorization, &body))
        .await
        .expect("write");
    let response = read_response(&mut other, &mut pending, Duration::from_secs(5))
        .await
        .expect("refusal");
    assert!(response.starts_with(b"RTSP/1.0 401 Unauthorized\r\n"));
    assert_eq!(state.password_failures(), 1);
    server.shutdown();
}

/// Request with a body and optional extra headers, framed like a real client.
fn request_with_body(target: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "{target} RTSP/1.0\r\nCSeq: 1\r\nContent-Length: {}\r\n{extra}\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn binary_plist(entries: Vec<(&str, rust_airplay::plist::Value)>) -> Vec<u8> {
    Plist::from_value(rust_airplay::plist::dictionary(entries))
        .encode_binary()
        .expect("encode")
}

/// Splits a response into its head, its body and the parsed head fields.
fn response_parts(response: &[u8]) -> (&[u8], &[u8]) {
    let head_end = find(response, b"\r\n\r\n").expect("header terminator");
    (&response[..head_end], &response[head_end + 4..])
}

#[tokio::test]
async fn answers_pair_pin_start_with_the_configured_pin() {
    let state = pairing_state(PinMode::Fixed(42));
    let server = TestServer::start_with(local_config(), pairing_handlers(Arc::clone(&state))).await;
    let mut client = server.connect().await;
    client
        .write_all(b"POST /pair-pin-start RTSP/1.0\r\nCSeq: 1\r\n\r\n")
        .await
        .expect("write");

    let mut pending = Vec::new();
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("response");
    let (head, body) = response_parts(&response);
    assert!(response.starts_with(b"RTSP/1.0 200 OK\r\n"));
    assert_eq!(
        header_value(head, "Audio-Jack-Status"),
        Some("connected; type=digital")
    );
    // Upstream adds nothing to this reply, so it carries no content type.
    assert_eq!(header_value(head, "Content-Type"), None);
    assert_eq!(header_value(head, "Content-Length"), None);
    assert!(body.is_empty());
    assert_eq!(state.pending_pin().as_deref(), Some("0042"));
    server.shutdown();
}

#[tokio::test]
async fn refuses_pairing_when_no_pin_is_configured() {
    let state = pairing_state(PinMode::Disabled);
    let server = TestServer::start_with(local_config(), pairing_handlers(Arc::clone(&state))).await;
    let mut client = server.connect().await;
    let mut pending = Vec::new();

    client
        .write_all(b"POST /pair-pin-start RTSP/1.0\r\nCSeq: 1\r\n\r\n")
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("response");
    assert!(
        response.starts_with(b"RTSP/1.0 470 Client Authentication Failure\r\n"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    let body = binary_plist(vec![
        ("method", rust_airplay::plist::Value::from("pin")),
        ("user", rust_airplay::plist::Value::from("client")),
    ]);
    client
        .write_all(&request_with_body(
            "POST /pair-setup-pin",
            "Content-Type: application/x-apple-binary-plist\r\n",
            &body,
        ))
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("response");
    assert!(response.starts_with(b"RTSP/1.0 470 Client Authentication Failure\r\n"));
    server.shutdown();
}

#[tokio::test]
async fn pair_setup_answers_the_receiver_public_key() {
    let state = pairing_state(PinMode::Fixed(1234));
    let server = TestServer::start_with(local_config(), pairing_handlers(Arc::clone(&state))).await;
    let mut client = server.connect().await;
    let mut pending = Vec::new();

    // Upstream ignores the content of the 32-byte body of the legacy setup.
    client
        .write_all(&request_with_body("POST /pair-setup", "", &[0u8; 32]))
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("response");
    let (head, body) = response_parts(&response);
    assert!(response.starts_with(b"RTSP/1.0 200 OK\r\n"));
    assert_eq!(
        header_value(head, "Content-Type"),
        Some("application/octet-stream")
    );
    assert_eq!(body, state.identity_public());

    // The same key is what the receiver advertises in `/info`: a client must
    // never cache one public key and be authenticated with another.
    client
        .write_all(b"GET /info RTSP/1.0\r\nCSeq: 2\r\n\r\n")
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("response");
    let (_, body) = response_parts(&response);
    let info = Plist::parse(body).expect("binary plist");
    assert_eq!(info.get_data("pk").expect("pk"), state.identity_public());

    // A body of another length is answered with the default reply.
    client
        .write_all(&request_with_body("POST /pair-setup", "", &[0u8; 31]))
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("response");
    let (head, body) = response_parts(&response);
    assert!(response.starts_with(b"RTSP/1.0 200 OK\r\n"));
    assert_eq!(header_value(head, "Content-Type"), None);
    assert_eq!(header_value(head, "Content-Length"), None);
    assert!(body.is_empty());
    server.shutdown();
}

#[tokio::test]
async fn pair_setup_pin_needs_a_verified_proof_before_the_third_step() {
    let state = pairing_state(PinMode::Fixed(1234));
    let server = TestServer::start_with(local_config(), pairing_handlers(Arc::clone(&state))).await;
    let mut client = server.connect().await;
    let mut pending = Vec::new();
    let plist_type = "Content-Type: application/x-apple-binary-plist\r\n";

    let step_one = binary_plist(vec![
        ("method", rust_airplay::plist::Value::from("pin")),
        (
            "user",
            rust_airplay::plist::Value::from("AA:BB:CC:DD:EE:FF"),
        ),
    ]);
    client
        .write_all(&request_with_body(
            "POST /pair-setup-pin",
            plist_type,
            &step_one,
        ))
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("response");
    let (head, body) = response_parts(&response);
    assert_eq!(
        header_value(head, "Content-Type"),
        Some("application/x-apple-binary-plist")
    );
    let step_one_reply = Plist::parse(body).expect("binary plist");
    assert_eq!(step_one_reply.get_data("salt").expect("salt").len(), 16);
    let public = step_one_reply.get_data("pk").expect("pk");
    assert!(!public.is_empty() && public.len() <= 256);

    // Skip step 2 and seal a key with the all-zero session key of an SRP
    // context whose proof was never verified. Upstream installs this key.
    let session_key = [0u8; 40];
    let keys = rust_airplay::pairing::derive_pair_setup_keys(&session_key);
    let (decrypt_iv, _) = rust_airplay::pairing::pair_setup_gcm_nonces(&session_key);
    let attacker_key = [0x11u8; 32];
    let (epk, tag) =
        rust_airplay::crypto::aes128_gcm16_encrypt(&keys.key, &decrypt_iv, &attacker_key)
            .expect("seal");
    let step_three = binary_plist(vec![
        ("epk", rust_airplay::plist::Value::Data(epk)),
        ("authTag", rust_airplay::plist::Value::Data(tag.to_vec())),
    ]);
    client
        .write_all(&request_with_body(
            "POST /pair-setup-pin",
            plist_type,
            &step_three,
        ))
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("response");
    assert!(
        response.starts_with(b"RTSP/1.0 470 Client Authentication Failure\r\n"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    // A request without the plist content type is refused as well, and the
    // connection is still usable afterwards.
    client
        .write_all(&request_with_body("POST /pair-setup-pin", "", &step_one))
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("response");
    assert!(response.starts_with(b"RTSP/1.0 470 Client Authentication Failure\r\n"));
    client
        .write_all(b"GET /info RTSP/1.0\r\nCSeq: 3\r\n\r\n")
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("response");
    assert!(response.starts_with(b"RTSP/1.0 200 OK\r\n"));
    server.shutdown();
}

#[tokio::test]
async fn pair_verify_signs_the_exchange_and_closes_on_a_bad_signature() {
    let state = pairing_state(PinMode::Fixed(1234));
    let server = TestServer::start_with(local_config(), pairing_handlers(Arc::clone(&state))).await;
    let mut client = server.connect().await;
    let mut pending = Vec::new();

    // The legacy setup puts the connection into the state the handshake needs.
    client
        .write_all(&request_with_body("POST /pair-setup", "", &[0u8; 32]))
        .await
        .expect("write");
    read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("setup response");

    let private = [0x21u8; 32];
    let public = rust_airplay::crypto::x25519_public(&private);
    let identity_seed = [0x33u8; 32];
    let identity_public = rust_airplay::crypto::ed25519_public_key(&identity_seed);
    let mut handshake = vec![1u8, 0, 0, 0];
    handshake.extend_from_slice(&public);
    handshake.extend_from_slice(&identity_public);
    client
        .write_all(&request_with_body("POST /pair-verify", "", &handshake))
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("response");
    let (head, body) = response_parts(&response);
    assert_eq!(
        header_value(head, "Content-Type"),
        Some("application/octet-stream")
    );
    assert_eq!(body.len(), 96);

    // The client authenticates the receiver with the key it cached.
    let server_ecdh: [u8; 32] = body[..32].try_into().expect("server key");
    let mut signature: [u8; 64] = body[32..].try_into().expect("signature");
    let shared = rust_airplay::crypto::x25519_shared(&private, &server_ecdh);
    let keys = rust_airplay::pairing::derive_pair_verify_keys(&shared);
    let mut cipher = rust_airplay::crypto::Aes128CtrState::new(&keys.key, &keys.iv).expect("ctr");
    cipher.apply(&mut signature);
    assert!(
        rust_airplay::crypto::ed25519_verify(
            &state.identity_public(),
            &[server_ecdh, public].concat(),
            &signature
        ),
        "the receiver's signature must verify with the advertised key"
    );

    // The second step signs the other transcript order, encrypted with the
    // second block of the shared keystream.
    let mut client_signature =
        rust_airplay::crypto::ed25519_sign(&identity_seed, &[public, server_ecdh].concat());
    let mut cipher = rust_airplay::crypto::Aes128CtrState::new(&keys.key, &keys.iv).expect("ctr");
    let mut discarded = [0u8; 64];
    cipher.apply(&mut discarded);
    cipher.apply(&mut client_signature);
    client_signature[7] ^= 0x01;
    let mut finish = vec![0u8, 0, 0, 0];
    finish.extend_from_slice(&client_signature);
    client
        .write_all(&request_with_body("POST /pair-verify", "", &finish))
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("response");
    let (head, body) = response_parts(&response);
    // Upstream returns before it adds the content type, and closes.
    assert!(response.starts_with(b"RTSP/1.0 200 OK\r\n"));
    assert_eq!(header_value(head, "Content-Type"), None);
    assert_eq!(header_value(head, "Content-Length"), None);
    assert!(body.is_empty());
    let mut rest = Vec::new();
    assert_eq!(client.read_to_end(&mut rest).await.expect("read"), 0);
    server.shutdown();
}

#[tokio::test]
async fn pair_verify_without_a_pin_falls_back_to_the_legacy_setup() {
    let state = pairing_state(PinMode::Disabled);
    let server = TestServer::start_with(local_config(), pairing_handlers(Arc::clone(&state))).await;
    let mut client = server.connect().await;
    let mut pending = Vec::new();

    let mut handshake = vec![1u8, 0, 0, 0];
    handshake.extend_from_slice(&[0x21u8; 32]);
    handshake.extend_from_slice(&[0x33u8; 32]);
    client
        .write_all(&request_with_body("POST /pair-verify", "", &handshake))
        .await
        .expect("write");
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("response");
    let (head, body) = response_parts(&response);
    assert!(response.starts_with(b"RTSP/1.0 200 OK\r\n"));
    assert_eq!(header_value(head, "Content-Length"), None);
    assert!(body.is_empty());
    server.shutdown();
}

#[tokio::test]
async fn rejects_a_head_that_breaks_the_upstream_field_bounds() {
    let server = TestServer::start(local_config(), RouteHandlers::new(identity())).await;
    let mut client = server.connect().await;
    // Twenty-one fields stay far below the 64 KiB head bound, but upstream
    // answers them with 431 (`upstream/UxPlay@3dbf7cee:lib/raop.c:225-238`).
    let mut request = String::from("GET /info RTSP/1.0\r\n");
    for index in 0..21 {
        request.push_str(&format!("X-{index}: v\r\n"));
    }
    request.push_str("\r\n");
    client.write_all(request.as_bytes()).await.expect("write");

    let mut pending = Vec::new();
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("rejection");
    let text = String::from_utf8_lossy(&response).to_string();
    assert!(
        text.starts_with("RTSP/1.0 431 Request Header Fields Too Large\r\n"),
        "{text}"
    );
    // The rejection is bare, as it is upstream: it is written before the
    // envelope headers.
    assert!(!text.contains("Server:"));
    let mut rest = Vec::new();
    assert_eq!(client.read_to_end(&mut rest).await.expect("read"), 0);
    server.shutdown();
}

#[tokio::test]
async fn rejects_a_request_that_asks_for_a_transfer_encoding() {
    let server = TestServer::start(local_config(), RouteHandlers::new(identity())).await;
    let mut client = server.connect().await;
    client
        .write_all(b"POST /pair-setup RTSP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        .await
        .expect("write");

    let mut pending = Vec::new();
    let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("rejection");
    assert!(
        String::from_utf8_lossy(&response).starts_with("RTSP/1.0 400 Bad Request\r\n"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let mut rest = Vec::new();
    assert_eq!(client.read_to_end(&mut rest).await.expect("read"), 0);
    server.shutdown();
}

#[tokio::test]
async fn pairing_routes_are_not_implemented_without_a_pairing_state() {
    // The default handlers serve no pairing: a caller that wants it adds a
    // `PairingState` with `RouteHandlers::with_pairing`.
    let server = TestServer::start(local_config(), RouteHandlers::new(identity())).await;
    let mut client = server.connect().await;
    let mut pending = Vec::new();
    for request in [
        &b"POST /pair-pin-start RTSP/1.0\r\nCSeq: 1\r\n\r\n"[..],
        b"POST /pair-setup RTSP/1.0\r\nCSeq: 2\r\n\r\n",
        b"POST /pair-verify RTSP/1.0\r\nCSeq: 3\r\n\r\n",
    ] {
        client.write_all(request).await.expect("write");
        let response = read_response(&mut client, &mut pending, Duration::from_secs(5))
            .await
            .expect("response");
        assert!(
            String::from_utf8_lossy(&response).starts_with("RTSP/1.0 501 Not Implemented\r\n"),
            "{}",
            String::from_utf8_lossy(&response)
        );
    }
    server.shutdown();
}
