// SPDX-License-Identifier: GPL-3.0-or-later
//! The backend boundary, and a renderer that accepts everything.
//!
//! The receiver stops at coded frames: a renderer receives an audio payload or a video access
//! unit and is responsible for decoding and playback. The interface exists so a media backend
//! can be replaced without touching the protocol, and so a backend can be tested without a
//! device. Nothing here decodes, opens a device or links a media library: [`NullRenderer`]
//! accepts everything and plays nothing, which is what a session runs against without a sound
//! card.
//!
//! [`Renderer`] is implemented by a backend crate; `docs/BACKEND.md` describes the contract in
//! the order a backend meets it.

mod codec;
mod frames;
mod null;
mod traits;
mod volume;

pub use codec::{AudioCodec, AudioConfig, VideoCodec, VideoConfig};
pub use frames::{AudioFrame, RenderError, VideoFrame};
pub use null::NullRenderer;
pub use traits::{AudioStream, Renderer, VideoStream};
pub use volume::{Volume, VolumeCurve, airplay_db_to_fraction};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_is_clamped_to_what_a_device_can_play() {
        assert_eq!(Volume::default(), Volume::FULL);
        assert_eq!(Volume::new(0.5).level(), 0.5);
        assert_eq!(
            Volume::new(-1.0).level(),
            0.0,
            "a client cannot ask for less"
        );
        assert_eq!(Volume::new(4.0).level(), 1.0, "nor for more");
        assert_eq!(
            Volume::new(f64::NAN).level(),
            1.0,
            "a volume that is not a number is not silence"
        );
    }

    #[test]
    fn the_null_renderer_takes_what_a_session_sends_it() {
        let renderer = NullRenderer::new();
        renderer.set_volume(Volume::new(0.25)).expect("a volume");
        assert_eq!(renderer.volume().level(), 0.25);

        let audio = renderer
            .open_audio(AudioConfig::default())
            .expect("an audio stream");
        audio
            .push(AudioFrame {
                data: vec![0u8; 100],
                timestamp: 1,
            })
            .expect("a frame");
        audio
            .push(AudioFrame {
                data: vec![0u8; 50],
                timestamp: 2,
            })
            .expect("another");
        audio.flush().expect("a flush");
        audio.close().expect("a close");

        let video = renderer
            .open_video(VideoConfig {
                width: Some(1920),
                height: Some(1080),
                codec: VideoCodec::H264,
            })
            .expect("a video stream");
        video
            .push(VideoFrame {
                data: vec![0u8; 200],
                timestamp: 3,
                keyframe: true,
            })
            .expect("a frame");
        video.close().expect("a close");

        assert_eq!(renderer.audio_streams(), 1);
        assert_eq!(renderer.audio_frames(), 2);
        assert_eq!(renderer.audio_bytes(), 150);
        assert_eq!(renderer.video_streams(), 1);
        assert_eq!(renderer.video_frames(), 1);
        assert_eq!(renderer.flushes(), 1);
        assert_eq!(renderer.closed(), 2);
    }

    #[test]
    fn a_clients_decibels_are_where_the_slider_is() {
        // -30 dB is silence, 0 dB is full volume, and -144 is the client's mute signal;
        // anything below the low end is silence and anything above the high end is full.
        assert_eq!(airplay_db_to_fraction(-144.0), 0.0);
        assert_eq!(airplay_db_to_fraction(-30.0), 0.0);
        assert_eq!(airplay_db_to_fraction(0.0), 1.0);
        assert_eq!(airplay_db_to_fraction(5.0), 1.0);
        assert!((airplay_db_to_fraction(-15.0) - 0.5).abs() < 1e-9);
        // The two ends and the middle were right in the first version and the rest was
        // mirrored: -8 dB is louder than -15 and must be higher up the slider, not lower.
        assert!((airplay_db_to_fraction(-8.0) - 22.0 / 30.0).abs() < 1e-9);
        assert!((airplay_db_to_fraction(-22.0) - 8.0 / 30.0).abs() < 1e-9);
        assert!(airplay_db_to_fraction(-8.0) > airplay_db_to_fraction(-15.0));
        assert!(airplay_db_to_fraction(-15.0) > airplay_db_to_fraction(-22.0));
    }

    #[test]
    fn the_flat_curve_is_a_straight_line_and_the_taper_is_not() {
        let flat = VolumeCurve::default();
        assert!((flat.gain(1.0) - 1.0).abs() < 1e-9);
        assert_eq!(flat.gain(0.0), 0.0);
        // Half the slider flat: -15 dB, which is about 0.178 of the amplitude.
        assert!((flat.gain(0.5) - 10f64.powf(-0.75)).abs() < 1e-12);
        // Half the slider tapered: -10 dB, about 0.316.
        let tapered = VolumeCurve {
            taper: true,
            ..VolumeCurve::default()
        };
        assert!((tapered.gain(0.5) - 10f64.powf(-0.5)).abs() < 1e-12);
        // And the taper is never quieter than the flat curve at the same position.
        for tenth in 0..=10 {
            let fraction = f64::from(tenth) / 10.0;
            assert!(tapered.db_for_fraction(fraction) >= flat.db_for_fraction(fraction));
        }
    }

    #[test]
    fn a_client_s_compression_type_names_its_coding() {
        // The two codings a client states, and nothing invented for the others: a
        // receiver that guessed at `ct = 3` would feed a decoder a stream it cannot read.
        assert_eq!(AudioCodec::from_compression_type(2), Some(AudioCodec::Alac));
        assert_eq!(
            AudioCodec::from_compression_type(8),
            Some(AudioCodec::AacEld)
        );
        assert_eq!(AudioCodec::from_compression_type(0), None);
        assert_eq!(AudioCodec::from_compression_type(3), None);
        assert_eq!(AudioCodec::from_compression_type(255), None);
    }

    #[test]
    fn the_two_streams_of_one_renderer_are_counted_apart() {
        // A session can have audio without video and the other way round, so a backend
        // that shared one counter between them could not be checked against what a
        // client actually sent.
        let renderer = NullRenderer::new();
        let audio = renderer
            .open_audio(AudioConfig {
                codec: AudioCodec::AacEld,
                sample_rate: 44_100,
                channels: 1,
                samples_per_frame: 480,
            })
            .expect("audio");
        audio
            .push(AudioFrame {
                data: vec![1, 2, 3],
                timestamp: 0,
            })
            .expect("a frame");
        assert_eq!(renderer.audio_frames(), 1);
        assert_eq!(renderer.video_frames(), 0);
        assert_eq!(renderer.video_streams(), 0);
        assert_eq!(AudioCodec::AacEld.name(), "aac-eld");
        assert_eq!(AudioCodec::Alac.name(), "alac");
    }

    #[test]
    fn debug_does_not_print_frame_bytes() {
        let audio = AudioFrame {
            data: vec![0xab; 4],
            timestamp: 7,
        };
        let debug = format!("{audio:?}");
        assert!(!debug.contains("171"), "{debug}");
        assert!(debug.contains("<4 bytes>"), "{debug}");

        let video = VideoFrame {
            data: vec![0xcd; 4],
            timestamp: 9,
            keyframe: true,
        };
        let debug = format!("{video:?}");
        assert!(!debug.contains("205"), "{debug}");
        assert!(debug.contains("<4 bytes>"), "{debug}");
    }
}
