// SPDX-License-Identifier: GPL-3.0-or-later
//! Tests for the timing packets and the clock estimate.

use super::*;
use crate::ntp;

#[test]
fn the_request_looks_like_the_expected_one() {
    // A Unix time in this era, with a fraction so the encoding is exercised.
    let send_time = 1_700_000_000 * ntp::NANOS_PER_SECOND + 123_456_789;
    let request = build_request(send_time).expect("request");
    assert_eq!(&request[..4], &[0x80, 0xd2, 0x00, 0x07], "header");
    assert_eq!(request.len(), 32);
    assert!(
        request[4..24].iter().all(|byte| *byte == 0),
        "everything before the transmit time stays clear"
    );
    // The transmit time comes back within the precision the format has: the
    // NTP fraction is 32 bits, which cannot hold every nanosecond.
    let mut timestamp = [0u8; 8];
    timestamp.copy_from_slice(&request[24..32]);
    let decoded = ntp::timestamp_to_unix_nanos(&timestamp).expect("timestamp");
    let difference = decoded.abs_diff(send_time);
    assert!(
        difference <= 2,
        "the round trip is off by {difference} ns, more than the format allows"
    );
}

#[test]
fn reads_the_response_values() {
    let mut response = vec![0u8; 32];
    response[1] = RESPONSE_TYPE | 0x80;
    response[8..12].copy_from_slice(&0x1111_1111u32.to_be_bytes());
    response[16..20].copy_from_slice(&0x2222_2222u32.to_be_bytes());
    response[24..28].copy_from_slice(&0x3333_3333u32.to_be_bytes());
    assert_eq!(
        parse_response(&response).expect("response"),
        TimingResponse {
            t1: 0x1111_1111,
            t2: 0x2222_2222,
            t3: 0x3333_3333,
        }
    );
}

/// A second in NTP's fixed point, which is what a timestamp's high half counts.
const NANOS_PER_TICK: u64 = 1_000_000_000;

fn seconds(count: u64) -> u64 {
    count << 32
}

/// The exchange carries whole seconds, and a test of it has to say so.
///
/// `t1`, `t2` and `t3` are thirty-two bits on the wire, and the protocol truncates `t4` to
/// the same width. So this cannot measure a sub-second offset,
/// and the numbers below are the honest shape of that: a twenty-millisecond round trip
/// vanishes, and the delay falls to the precision floor. What the exchange *can* do is
/// place the client's second counter against this machine's, and the conversion has to
/// stay inside a second of the truth. A device session reported 895 ms of delay for a
/// link with 3 ms of it, which is this quantisation and not a network problem.
#[test]
fn an_exchange_is_only_as_fine_as_the_seconds_it_carries() {
    let mut clock = RemoteClock::new();
    // The client's clock reads five seconds ahead of this machine's.
    // The client booted 8354 seconds ago and its answer adds the 1900 offset, which is
    // what a device was seen to send.
    const BOOT: u32 = 8_354;
    let t2 = BOOT.wrapping_add(2_208_988_800);
    let t3 = t2;
    // This machine's clock, in the same era: Unix seconds plus the same offset.
    let t1_seconds: u32 = 1_792_231_849u32.wrapping_add(2_208_988_800);

    clock.request_sent(t1_seconds);
    // A one-way trip of ten milliseconds, and the client takes none of it processing.
    let t4 = 1_792_231_849_000_000_000 + 2 * 10_000_000;

    let sample = clock
        .response_received(t1_seconds, t2, t3, t4)
        .expect("a sample from a reply that echoes the request");
    // Twenty milliseconds of round trip is invisible at this resolution, so the delay
    // is the floor the arithmetic uses in place of zero.
    assert!(sample.delay > 0.0);
    assert!((sample.delay - 0.02).abs() < 1e-3, "delay {}", sample.delay);
    assert!(clock.is_synced(), "an exchange this clean is a sync");

    // The conversion is what a session uses, and it has to survive the era: the client
    // counts seconds since 1900 in 32 bits, so the fixed offset is what puts its
    // timestamps on this machine's clock.
    // A mirror timestamp in the client's epoch: seconds in the high half.
    let remote = u64::from(BOOT) << 32;
    let local = clock.to_local(remote).expect("a conversion");
    // The exchange only knows the client's second, so the conversion cannot be finer
    // than that: two seconds of tolerance is what the wire allows.
    let tolerance = 2 * NANOS_PER_TICK;
    assert!(
        local.abs_diff(t4) < tolerance,
        "converted {local}, expected about {t4}"
    );
    assert!(clock.to_remote(local).is_some());
    let _ = &remote;
}

#[test]
fn a_real_mirror_timestamp_lands_on_the_local_clock() {
    // Numbers from a device session, kept because they are the only evidence that the
    // unit is what this code says it is: `t2` was 2208997154 (client boot plus the
    // 1900 offset), the answer arrived at Unix 1792231849.253 s, and the first mirror
    // frame carried 35884668244832.
    let mut clock = RemoteClock::new();
    let t1_seconds: u32 = 4_001_220_649;
    clock.request_sent(t1_seconds);
    let t4 = 1_792_231_849_253_621_800;
    clock
        .response_received(t1_seconds, 2_208_997_154, 2_208_997_154, t4)
        .expect("a matched answer");

    // The mirror timestamp decodes as 8355 seconds and a fraction of a second since
    // the client booted, and it has to land within a second of the frame's arrival.
    let frame = 35_884_668_244_832u64;
    assert_eq!(frame >> 32, 8_355, "the high half counts client seconds");
    let local = clock.to_local(frame).expect("a conversion");
    assert!(
        local.abs_diff(t4) < 1_000_000_000,
        "converted {local} against an arrival of {t4}"
    );
}

#[test]
fn consecutive_frames_differ_by_one_frame_of_ticks() {
    // The same session: two frames thirty-three milliseconds apart differed by
    // 143156808 ticks, and a second is 2^32 of them.
    let ticks = 143_156_808u64;
    let seconds = ticks as f64 / 4_294_967_296.0;
    assert!(
        (seconds - 1.0 / 30.0).abs() < 0.001,
        "a frame lasted {seconds} s"
    );
    // And the high half counts seconds: 8355 seconds of boot time is 8355 * 2^32
    // ticks, which is where the observed value's high half sits.
    let observed = 35_884_668_244_832u64;
    assert_eq!(observed >> 32, 8_355);
}
#[test]
fn an_answer_that_echoes_nothing_this_receiver_sent_is_refused() {
    let mut clock = RemoteClock::new();
    clock.request_sent(1_000);
    assert!(
        clock
            .response_received(0xdead_beef, 1, 2, seconds(1_001))
            .is_none(),
        "a reply the receiver never asked for is not a measurement"
    );
    assert!(clock.fixed_offset_nanos().is_none());
}

#[test]
fn the_same_answer_twice_is_ignored() {
    let mut clock = RemoteClock::new();
    let t2: u32 = 8_354u32.wrapping_add(2_208_988_800);
    let t1_seconds: u32 = 1_792_231_849u32.wrapping_add(2_208_988_800);
    clock.request_sent(t1_seconds);
    let first = clock.response_received(t1_seconds, t2, t2, 1_792_231_849_040_000_000);
    assert!(first.is_some());
    assert_eq!(
        clock.response_received(t1_seconds, t2, t2, 1_792_231_849_040_000_000),
        None,
        "a repeated t3 is the same exchange counted twice"
    );
}

#[test]
fn an_impossible_timestamp_saturates_instead_of_overflowing() {
    // A client timestamp is a full 64-bit value, and the conversion adds the fixed
    // offset on top of it. The first version did that in `i64` and overflowed on a
    // timestamp near the top of the range, which is a panic in a debug build and a
    // wrapped time in a release one.
    let mut clock = RemoteClock::new();
    let t1 = 1_792_231_849u32.wrapping_add(2_208_988_800);
    let t2 = t1;
    let t3 = t2;
    clock.request_sent(t1);
    clock
        .response_received(t1, t2, t3, 1_792_231_849_020_000_000)
        .expect("a sample");

    let local = clock.to_local(u64::MAX).expect("a conversion");
    assert!(local > 0, "the conversion produced a value");
    let remote = clock.to_remote(u64::MAX).expect("a conversion");
    assert!(remote > 0);
}

#[test]
fn nothing_is_converted_before_an_exchange() {
    let clock = RemoteClock::new();
    assert_eq!(clock.to_local(seconds(10)), None);
    assert_eq!(clock.to_remote(seconds(10)), None);
    assert!(!clock.is_synced());
    assert_eq!(clock.root_distance_nanos(), u64::MAX);
}
#[test]
fn refuses_what_it_cannot_read() {
    assert_eq!(parse_response(&[]), Err(TimingError::TooShort));
    assert_eq!(parse_response(&[0x80]), Err(TimingError::TooShort));
    // A request is not a response.
    let request = build_request(1_700_000_000 * ntp::NANOS_PER_SECOND).expect("request");
    assert_eq!(
        parse_response(&request),
        Err(TimingError::NotAResponse { kind: 0x52 })
    );
    // The right type, but nothing to read in it.
    assert_eq!(
        parse_response(&[0x80, RESPONSE_TYPE | 0x80]),
        Err(TimingError::TooShort)
    );
}
