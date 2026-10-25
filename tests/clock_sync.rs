// SPDX-License-Identifier: GPL-3.0-or-later
//! The clock exchange, over real sockets.
//!
//! The arithmetic has unit tests; this checks the half that is not arithmetic. A request
//! goes out on the timing socket, a client answers it, and the answer has to reach the
//! clock as a usable measurement. Every part of that has failed at some point in this
//! project: a request whose `t1` is not remembered, an answer nobody reads, an answer read
//! but never matched.
//!
//! The client here is synthetic on purpose. It is the only way to test the exchange without
//! a device, and it can place the client's clock a known distance from this machine's,
//! which a device cannot.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rust_airplay::media::ports::MediaSockets;
use rust_airplay::media::timing::{RemoteClock, build_request, parse_response};

/// A response that echoes `t1` and reports the client's own times.
///
/// The client's clock is `offset_seconds` ahead of this machine's. Its receive time `t2`
/// is the moment the request arrived plus that offset, its transmit time `t3` is the same
/// plus `processing_ms`, which is how a real client reports a delay it caused itself.
/// The client's own epoch, in seconds since it booted. A real answer carries this plus the
/// 1900 offset, and this is the number the mirror stream's timestamps count from.
const BOOT_SECONDS: u32 = 8_354;

/// Seconds from 1900, which every timing answer carries and no media timestamp does.
const SECONDS_FROM_1900: u32 = 2_208_988_800;

fn answer(t1: u32, offset_seconds: u32, processing_ms: u32) -> Vec<u8> {
    let mut datagram = vec![0u8; 32];
    datagram[0] = 0x80;
    datagram[1] = 0x53;
    let t2 = BOOT_SECONDS
        .wrapping_add(offset_seconds)
        .wrapping_add(SECONDS_FROM_1900);
    let t3 = t2.wrapping_add(processing_ms / 1_000);
    datagram[8..12].copy_from_slice(&t1.to_be_bytes());
    datagram[16..20].copy_from_slice(&t2.to_be_bytes());
    datagram[24..28].copy_from_slice(&t3.to_be_bytes());
    datagram
}

#[tokio::test]
async fn an_answer_over_the_socket_becomes_a_measurement() {
    let sockets = MediaSockets::bind("127.0.0.1:0".parse().expect("address"))
        .await
        .expect("bind");

    // The client, on a socket of its own, so the exchange is a real one.
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client");
    let client_address = client.local_addr().expect("address");

    let mut clock = RemoteClock::new();

    // This side sends `t1` and remembers it, which is what makes an answer matchable.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock")
        .as_nanos() as u64;
    let request = build_request(now).expect("a request");
    let t1 = u32::from_be_bytes([request[24], request[25], request[26], request[27]]);
    clock.request_sent(t1);
    sockets
        .send_timing_request(client_address, &request)
        .await
        .expect("send");

    // The client answers five seconds ahead of this machine.
    let echoed = tokio::time::timeout(Duration::from_secs(5), async {
        let mut buffer = [0u8; 64];
        let (_length, from) = client.recv_from(&mut buffer).await.expect("recv");
        // A request is not a response: the client reads the send time out of it rather
        // than parsing it, which is what makes the echo meaningful.
        let echoed = u32::from_be_bytes([buffer[24], buffer[25], buffer[26], buffer[27]]);
        assert_eq!(echoed, t1, "the request carries the time it was sent");
        client
            .send_to(&answer(echoed, 5, 0), from)
            .await
            .expect("answer");
        echoed
    })
    .await
    .expect("the client has to receive the request");

    // The receiver reads it on its timing socket, which is the path a live session takes.
    let reply = tokio::time::timeout(Duration::from_secs(5), sockets.receive_timing())
        .await
        .expect("the answer has to arrive")
        .expect("a datagram");
    let response = parse_response(&reply).expect("an answer");
    assert_eq!(echoed, t1);

    let t4 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock")
        .as_nanos() as u64;
    let sample = clock
        .response_received(response.t1, response.t2, response.t3, t4)
        .expect("a matched answer is a measurement");
    assert!(sample.delay > 0.0, "delay {}", sample.delay);
    assert!(
        clock.is_synced(),
        "an exchange over loopback is as clean as it gets"
    );
    assert_eq!(clock.samples_collected(), 1);

    // The conversion has to be usable: a mirror timestamp, which counts from the client's
    // boot in Q32.32, has to land on this machine's clock. The exchange only knows the
    // client's second, so two seconds of tolerance is what it can promise.
    let remote = (u64::from(BOOT_SECONDS) + 5) << 32;
    let local = clock.to_local(remote).expect("a conversion");
    assert!(
        local.abs_diff(t4) < 2_000_000_000,
        "converted {local} against a local time of {t4}"
    );

    // A second answer to the same request is not a second measurement: the `t1` has been
    // used, which is what a replay looks like from here.
    let again = clock.response_received(response.t1, response.t2, response.t3, t4);
    assert_eq!(again, None, "a replayed answer must not move the clock");
}
