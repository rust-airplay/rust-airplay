// SPDX-License-Identifier: GPL-3.0-or-later
//! Tests for the receiver's internal helpers.

use super::runtime::{ClockProbe, client_gain, describe_report};
use super::state::{FreshestFrames, QUEUED_FRAMES, QueuedVideo, STARTUP_QUEUED_FRAMES};

#[test]
fn a_streaming_report_is_written_out_as_xml() {
    // The protocol prints these as XML when `-FPSdata` is on;
    // the point is that a person can read what the client says about its own stream.
    let mut report = plist::Dictionary::new();
    report.insert("fps".to_owned(), plist::Value::from(30u64));
    let payload = crate::plist::Plist::from_value(plist::Value::Dictionary(report))
        .encode_binary()
        .expect("a report");
    let text = describe_report(&payload);
    assert!(text.contains("<key>fps</key>"), "{text}");
    assert!(text.contains("<integer>30</integer>"), "{text}");

    // Anything that is not a plist is still evidence, so it is summarised rather than
    // silently dropped.
    let text = describe_report(&[0xff, 0x00]);
    assert!(text.contains("not a plist"), "{text}");
}

fn frame(timestamp: u64) -> QueuedVideo {
    frame_with(timestamp, true, 0)
}

fn frame_with(timestamp: u64, idr: bool, received: u64) -> QueuedVideo {
    (
        vec![0u8; 4],
        timestamp,
        idr,
        received,
        crate::render::VideoCodec::H264,
        None,
    )
}

#[test]
fn a_client_s_decibels_become_the_gain_a_renderer_plays_at() {
    // The path from `SET_PARAMETER volume` to `Renderer::set_volume`: what a client
    // sends is decibels, and what a sound card takes is a linear gain.
    use crate::VolumeCurve;
    let flat = VolumeCurve::default();
    assert!((client_gain(0.0, flat) - 1.0).abs() < 1e-12);
    assert_eq!(client_gain(-30.0, flat), 0.0);
    assert_eq!(client_gain(-144.0, flat), 0.0);
    // Half the slider is -15 dB, about 0.178 of the amplitude.
    assert!((client_gain(-15.0, flat) - 10f64.powf(-0.75)).abs() < 1e-12);
    // A positive value is a slider position rather than decibels: a fraction is used
    // as it stands, a percentage is divided by a hundred.
    assert!((client_gain(0.5, flat) - flat.gain(0.5)).abs() < 1e-12);
    assert!((client_gain(50.0, flat) - flat.gain(0.5)).abs() < 1e-12);
    // And one out of range cannot become louder than full volume.
    assert!((client_gain(1000.0, flat) - 1.0).abs() < 1e-12);
}

#[test]
fn a_flush_drops_what_was_queued_and_tells_the_writer() {
    // `FLUSH` is the client saying the picture it is about to send is not the one on
    // screen. The writer owns the renderer's stream, so it has to be told too - that is
    // what the generation is for.
    let queue = FreshestFrames::new();
    assert_eq!(queue.put(frame(1), true).0, 1);
    assert_eq!(queue.put(frame(2), true).0, 2);
    let before = queue.generation();

    let after = queue.clear();
    assert_eq!(after, before + 1, "a flush is one generation");
    assert_eq!(queue.generation(), after);
    // Nothing is left to take, and the queue is not ended: frames after a flush are
    // the ones that should play.
    assert!(queue.try_take().is_none());
    assert_eq!(queue.put(frame(3), true).0, 1);
    assert!(queue.try_take().is_some());
}

#[test]
fn a_startup_backlog_is_bounded_and_restarts_on_a_key_frame() {
    // The stream has not opened yet, so frames may queue; the startup allowance is the
    // smaller of thirty frames and five hundred milliseconds. Overflowing it clears the
    // queued group and accepts the next key frame instead of playing a broken one.
    let queue = FreshestFrames::new();
    for timestamp in 0..STARTUP_QUEUED_FRAMES as u64 {
        let (_, dropped) = queue.put(frame(timestamp), false);
        assert!(!dropped, "the startup allowance accepts {timestamp}");
    }
    assert_eq!(queue.depth(), STARTUP_QUEUED_FRAMES);

    let (depth, dropped) = queue.put(frame(30), false);
    assert!(dropped, "the startup allowance is bounded");
    assert_eq!(depth, 1, "the key frame is kept");
    assert_eq!(
        queue.dropped(),
        STARTUP_QUEUED_FRAMES as u64,
        "the cleared group is counted"
    );
    assert_eq!(queue.try_take().expect("the key frame").1, 30);
}

#[test]
fn a_startup_backlog_is_measured_in_time_too() {
    let queue = FreshestFrames::new();
    assert!(!queue.put(frame_with(0, true, 0), false).1);
    assert!(!queue.put(frame_with(1, true, 100_000_000), false).1);
    // Five hundred milliseconds is the other half of the startup allowance.
    let (depth, dropped) = queue.put(frame_with(2, true, 600_000_000), false);
    assert!(dropped);
    assert_eq!(depth, 1);
    assert_eq!(queue.dropped(), 2);
    assert_eq!(queue.try_take().expect("the key frame").1, 2);
}

#[test]
fn an_overflow_waits_for_a_key_frame() {
    // A P frame refers to frames the decoder already has. Once one is missing, dropping
    // only the oldest frame leaves every later frame referring to a picture that was
    // never decoded. The queue clears instead, and only a key frame restarts delivery.
    let queue = FreshestFrames::new();
    for timestamp in 0..QUEUED_FRAMES as u64 {
        let (_, dropped) = queue.put(frame_with(timestamp, true, 0), true);
        assert!(!dropped);
    }
    assert_eq!(queue.depth(), QUEUED_FRAMES);

    let (depth, dropped) = queue.put(frame_with(8, false, 0), true);
    assert!(dropped);
    assert_eq!(depth, 0, "a P frame cannot restart a cleared group");
    assert!(queue.try_take().is_none());

    let (depth, dropped) = queue.put(frame_with(9, false, 0), true);
    assert!(dropped);
    assert_eq!(depth, 0, "the next P frame is dropped too");

    let (depth, dropped) = queue.put(frame_with(10, true, 0), true);
    assert!(!dropped);
    assert_eq!(depth, 1, "an IDR restarts delivery");
    assert_eq!(queue.try_take().expect("the key frame").1, 10);
}

#[test]
fn a_ninety_kilohertz_video_clock_is_recognised() {
    // Audio at 44.1 kHz and video at 90 kHz describe the same instants if the numbers
    // are what they claim: one second of samples is 44100, and one second of the video
    // clock is 90000. The arrivals have to tell the same story.
    let mut probe = ClockProbe {
        audio: Some((44_100, 1_000_000_000)),
        video: Some((90_000, 1_000_000_000)),
        ..ClockProbe::default()
    };
    let (name, residual) = probe.agreement().expect("the two agree");
    assert_eq!(name, "90000");
    assert!(residual.abs() < 1e-9, "residual {residual}");

    // A stream that starts later has to be described by its timestamp, not by when it
    // arrived: two seconds of arrival difference and one second of timestamp
    // difference is a disagreement, and the probe must not claim otherwise.
    probe.audio = Some((44_100 * 2, 1_000_000_000));
    assert!(probe.agreement().is_none());
}
