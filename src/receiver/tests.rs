// SPDX-License-Identifier: GPL-3.0-or-later
//! Tests for the receiver's internal helpers.

use super::runtime::{ClockProbe, client_gain, describe_report};
use super::state::{FreshestFrames, QUEUED_FRAMES, QueuedVideo};

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
    (
        vec![0u8; 4],
        timestamp,
        true,
        0,
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
fn a_slow_start_grows_the_queue_and_a_drain_comes_back_to_its_depth() {
    // The frames that wait for the pipeline to open are not an overflow: at sixty a
    // second, a quarter of a second of opening is fifteen of them, and the first version
    // of this limit dropped that whole opening burst. The queue may grow while the
    // stream is closed, and is only limited again once it has drained.
    let queue = FreshestFrames::new();
    for timestamp in 0..30u64 {
        let (depth, dropped) = queue.put(frame(timestamp), false);
        assert!(!dropped, "a closed stream must not drop frames");
        assert_eq!(depth as u64, timestamp + 1);
    }
    // Opening the stream does not judge that backlog as an overflow either.
    let (depth, dropped) = queue.put(frame(30), true);
    assert!(!dropped);
    assert_eq!(depth, 31);

    // Draining back down to the steady depth happens by taking frames; once below it,
    // the strict depth applies and the oldest frame goes.
    while queue.try_take().is_some() {}
    for timestamp in 40..48u64 {
        assert!(!queue.put(frame(timestamp), true).1);
    }
    let (depth, dropped) = queue.put(frame(48), true);
    assert!(dropped, "the steady depth drops the oldest frame");
    assert_eq!(depth, QUEUED_FRAMES);
    assert_eq!(queue.try_take().expect("a frame").1, 41);
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
