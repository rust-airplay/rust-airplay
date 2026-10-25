// SPDX-License-Identifier: GPL-3.0-or-later

//! End-to-end checks of [`rust_airplay::serve`]: a real socket, two sessions and a stop.
//!
//! The protocol tests drive the control layer and the media layer apart. These drive the
//! wiring between them - the key a `SETUP` carries, the loop that decrypts audio, the
//! renderer, the teardown that releases the session and the shutdown that frees the port -
//! which is where a receiver that lives longer than one client actually runs.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rust_airplay::fairplay::FairPlaySession;
use rust_airplay::plist::{self, Plist};
use rust_airplay::server::PinMode;
use rust_airplay::{
    AudioConfig, AudioFrame, AudioStream, Config, RenderError, Renderer, VideoConfig, VideoStream,
    Volume,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// A logger that writes the library's records to stderr while the test runs.
struct TestLogger;

static TEST_LOGGER: TestLogger = TestLogger;

impl log::Log for TestLogger {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        eprintln!("[{}] {}", record.level(), record.args());
    }

    fn flush(&self) {}
}

/// A renderer that records the plaintext of every audio frame it is handed.
#[derive(Debug, Default)]
struct RecordingRenderer {
    streams: AtomicUsize,
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
    flushes: Arc<AtomicUsize>,
}

#[derive(Debug)]
struct RecordingStream {
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
    flushes: Arc<AtomicUsize>,
}

impl Renderer for RecordingRenderer {
    fn open_audio(&self, _config: AudioConfig) -> Result<Box<dyn AudioStream>, RenderError> {
        self.streams.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(RecordingStream {
            frames: Arc::clone(&self.frames),
            flushes: Arc::clone(&self.flushes),
        }))
    }

    fn open_video(&self, _config: VideoConfig) -> Result<Box<dyn VideoStream>, RenderError> {
        Err(RenderError::Unavailable("no video in this test".to_owned()))
    }

    fn set_volume(&self, _volume: Volume) -> Result<(), RenderError> {
        Ok(())
    }
}

impl AudioStream for RecordingStream {
    fn push(&self, frame: AudioFrame) -> Result<(), RenderError> {
        self.frames.lock().expect("frames").push(frame.data);
        Ok(())
    }

    fn flush(&self) -> Result<(), RenderError> {
        self.flushes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn close(&self) -> Result<(), RenderError> {
        Ok(())
    }
}

impl RecordingRenderer {
    fn audio_streams(&self) -> usize {
        self.streams.load(Ordering::Relaxed)
    }

    fn saw(&self, expected: &[u8]) -> bool {
        self.frames
            .lock()
            .expect("frames")
            .iter()
            .any(|frame| frame == expected)
    }

    fn flushes(&self) -> usize {
        self.flushes.load(Ordering::Relaxed)
    }
}

/// A port the test can ask the receiver to bind.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
    listener.local_addr().expect("an address").port()
}

/// One request with a binary-plist body.
fn request(method: &str, target: &str, body: &[u8], cseq: u32) -> Vec<u8> {
    let mut request = format!(
        "{method} {target} RTSP/1.0\r\nCSeq: {cseq}\r\n\
         Content-Type: application/x-apple-binary-plist\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    request
}

/// The `SETUP` body a client sends: one audio stream and the key it will use.
fn setup_body(ekey: &[u8; 72], eiv: &[u8; 16], timing_port: u16, control_port: u16) -> Vec<u8> {
    let mut stream = plist::Dictionary::new();
    stream.insert("type".to_owned(), 96u64.into());
    stream.insert("ct".to_owned(), 2u64.into());
    stream.insert("spf".to_owned(), 352u64.into());
    stream.insert("controlPort".to_owned(), u64::from(control_port).into());
    let mut root = plist::Dictionary::new();
    root.insert("ekey".to_owned(), plist::Value::Data(ekey.to_vec()));
    root.insert("eiv".to_owned(), plist::Value::Data(eiv.to_vec()));
    root.insert("timingPort".to_owned(), u64::from(timing_port).into());
    root.insert(
        "streams".to_owned(),
        plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
    );
    Plist::from_value(plist::Value::Dictionary(root))
        .encode_binary()
        .expect("a setup body")
}

/// Runs the FairPlay handshake on this connection and returns the media key the
/// receiver will derive from `ekey`.
async fn fairplay_key(client: &mut TcpStream, pending: &mut Vec<u8>, ekey: &[u8; 72]) -> [u8; 16] {
    let mut challenge = [0u8; 16];
    challenge[4] = 0x03;
    let mut handshake = [0u8; 164];
    handshake[4] = 0x03;
    for body in [&challenge[..], &handshake[..]] {
        client
            .write_all(&request("POST", "/fp-setup", body, 1))
            .await
            .expect("fairplay");
        let reply = read_response(client, pending, Duration::from_secs(5))
            .await
            .expect("a fairplay reply");
        assert!(
            reply.starts_with(b"RTSP/1.0 200"),
            "{}",
            String::from_utf8_lossy(&reply)
        );
    }
    let mut reference = FairPlaySession::new();
    reference.setup(&challenge).expect("reference setup");
    reference
        .handshake(&handshake)
        .expect("reference handshake");
    reference.decrypt(ekey).expect("reference decrypt")
}

/// One `FLUSH`, with the sequence the client wants to resume at.
fn flush_request(next: u16) -> Vec<u8> {
    format!(
        "FLUSH /stream RTSP/1.0\r\nCSeq: 3\r\nRTP-Info: seq={next}\r\n\
         Content-Length: 0\r\n\r\n"
    )
    .into_bytes()
}

/// Reads one complete response, keeping unconsumed bytes in `pending`.
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
                let response = pending[..total].to_vec();
                pending.drain(..total);
                return Some(response);
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

/// The data port from a `SETUP` response.
fn data_port(response: &[u8]) -> u16 {
    let end = find(response, b"\r\n\r\n").expect("a head");
    let body = &response[end + 4..];
    let value = Plist::parse(body).expect("a setup reply");
    let streams = value.get_array("streams").expect("streams");
    let stream = streams
        .first()
        .and_then(plist::Value::as_dictionary)
        .expect("one stream");
    stream
        .get("dataPort")
        .and_then(plist::Value::as_unsigned_integer)
        .expect("a data port") as u16
}

/// AES-CBC, no padding, exactly as the audio path decrypts it.
fn encrypt(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::NoPadding};
    type Encryptor = cbc::Encryptor<aes::Aes128>;
    let mut buffer = plaintext.to_vec();
    let length = buffer.len();
    Encryptor::new_from_slices(key, iv)
        .expect("a key and iv")
        .encrypt_padded_mut::<NoPadding>(&mut buffer, length)
        .expect("a whole number of blocks")
        .to_vec()
}

/// One RTP audio datagram carrying `payload`.
fn audio_packet(sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 12];
    packet[0] = 0x80;
    packet[1] = 96;
    packet[2..4].copy_from_slice(&sequence.to_be_bytes());
    packet[4..8].copy_from_slice(&480u32.to_be_bytes());
    packet[8..12].copy_from_slice(&0x1234_5678u32.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

async fn send_audio(port: u16, key: [u8; 16], iv: [u8; 16], sequence: u16, plaintext: &[u8]) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("a udp socket");
    let ciphertext = encrypt(&key, &iv, plaintext);
    socket
        .send_to(&audio_packet(sequence, &ciphertext), ("127.0.0.1", port))
        .await
        .expect("an audio datagram");
}

async fn connect(port: u16) -> TcpStream {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(stream) => return stream,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => panic!("connecting to the receiver: {error}"),
        }
    }
}

async fn wait_until(mut condition: impl FnMut() -> bool, what: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// One `SETUP`, one `TEARDOWN`, and a second client that must get a stream of its own.
#[tokio::test]
async fn two_sessions_are_served_and_stop_releases_the_port() {
    let _ = log::set_logger(&TEST_LOGGER);
    log::set_max_level(log::LevelFilter::Info);
    let renderer = Arc::new(RecordingRenderer::default());
    let port = free_port();
    let mut config = Config::new(
        "receiver test",
        [0x42; 32],
        Arc::clone(&renderer) as Arc<dyn Renderer>,
    );
    config.port = port;
    config.bind = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    config.advertise = false;
    config.pin = PinMode::Disabled;

    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(async move {
        rust_airplay::serve(config, async move {
            let _ = stopped.await;
        })
        .await
    });

    // A client that answers the clock exchange: the receiver sends to this port, and
    // a bound socket keeps the network from answering with an ICMP unreachable.
    let timing = UdpSocket::bind(("127.0.0.1", 0))
        .await
        .expect("a timing socket");
    let timing_port = timing.local_addr().expect("a timing address").port();
    // The client's control port: the receiver sends resend requests to it.
    let control = UdpSocket::bind(("127.0.0.1", 0))
        .await
        .expect("a control socket");
    let control_port = control.local_addr().expect("a control address").port();

    // First session: a FairPlay handshake, a key, one frame encrypted with it.
    let mut client = connect(port).await;
    let mut pending = Vec::new();
    let ekey = [0x11u8; 72];
    let eiv = [0x21u8; 16];
    let key = fairplay_key(&mut client, &mut pending, &ekey).await;
    client
        .write_all(&request(
            "SETUP",
            "/stream",
            &setup_body(&ekey, &eiv, timing_port, control_port),
            2,
        ))
        .await
        .expect("setup");
    let reply = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("a setup reply");
    assert!(
        reply.starts_with(b"RTSP/1.0 200"),
        "{}",
        String::from_utf8_lossy(&reply)
    );
    let first_port = data_port(&reply);
    wait_until(|| renderer.audio_streams() == 1, "the first audio stream").await;
    let first_frame = [0xA1u8; 32];
    send_audio(first_port, key, eiv, 0, &first_frame).await;
    wait_until(|| renderer.saw(&first_frame), "the first frame").await;

    // Sequence 1 is dropped. The receiver has to ask for it on the control port,
    // and the frames around the gap must be held until the answer arrives.
    let skipped = [0xC1u8; 32];
    send_audio(first_port, key, eiv, 2, &skipped).await;
    let mut resend = [0u8; 8];
    let length = timeout(Duration::from_secs(2), control.recv(&mut resend))
        .await
        .expect("a resend request")
        .expect("the request datagram");
    assert_eq!(length, 8, "a resend request is eight bytes");
    assert_eq!(
        u16::from_be_bytes([resend[4], resend[5]]),
        1,
        "the request names the missing sequence"
    );
    assert_eq!(
        u16::from_be_bytes([resend[6], resend[7]]),
        1,
        "one packet is wanted"
    );
    let missing = [0xC0u8; 32];
    send_audio(first_port, key, eiv, 1, &missing).await;
    wait_until(
        || renderer.saw(&missing) && renderer.saw(&skipped),
        "the frames around the gap",
    )
    .await;

    // A FLUSH must reach the renderer as well as the reorder window. The writer owns
    // the stream, so the frame sent after the flush is what lets it see the request.
    client.write_all(&flush_request(3)).await.expect("flush");
    let reply = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("a flush reply");
    assert!(
        reply.starts_with(b"RTSP/1.0 200"),
        "{}",
        String::from_utf8_lossy(&reply)
    );
    let after_flush = [0xA3u8; 32];
    send_audio(first_port, key, eiv, 3, &after_flush).await;
    wait_until(|| renderer.flushes() >= 1, "the audio flush").await;

    // The client tears the session down; the receiver has to release the key.
    client
        .write_all(&request("TEARDOWN", "/stream", b"", 4))
        .await
        .expect("teardown");
    let _ = read_response(&mut client, &mut pending, Duration::from_secs(5)).await;
    drop(client);

    // Second session: another client, another FairPlay handshake, another key and
    // another audio stream.
    let mut client = connect(port).await;
    let mut pending = Vec::new();
    let ekey = [0x12u8; 72];
    let eiv = [0x22u8; 16];
    let key = fairplay_key(&mut client, &mut pending, &ekey).await;
    client
        .write_all(&request(
            "SETUP",
            "/stream",
            &setup_body(&ekey, &eiv, timing_port, control_port),
            2,
        ))
        .await
        .expect("setup");
    let reply = read_response(&mut client, &mut pending, Duration::from_secs(5))
        .await
        .expect("a setup reply");
    assert!(
        reply.starts_with(b"RTSP/1.0 200"),
        "{}",
        String::from_utf8_lossy(&reply)
    );
    let second_port = data_port(&reply);
    wait_until(|| renderer.audio_streams() == 2, "the second audio stream").await;
    let second_frame = [0xB2u8; 32];
    send_audio(second_port, key, eiv, 0, &second_frame).await;
    wait_until(|| renderer.saw(&second_frame), "the second frame").await;

    // A stop must make `serve` return instead of leaving the port bound.
    stop.send(()).expect("the shutdown receiver");
    let outcome = timeout(Duration::from_secs(5), serving)
        .await
        .expect("serve returns")
        .expect("the serving task");
    assert!(outcome.is_ok(), "{outcome:?}");
    let rebound = std::net::TcpListener::bind(("127.0.0.1", port));
    assert!(rebound.is_ok(), "the control port was not released");
}
