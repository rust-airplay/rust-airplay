// SPDX-License-Identifier: GPL-3.0-or-later
//! The codings and the stream configurations a backend receives.

/// The audio coding a stream carries.
///
/// A client states it as `ct` in the `SETUP` that names its audio stream - `2` for [`Alac`],
/// `8` for [`AacEld`] - and the receiver passes that declaration to the backend. The value on
/// [`crate::receiver::Config`] is only the fallback for a client that never says.
///
/// The distinction matters because the two codings are not interchangeable: a decoder fed one
/// kind of frame as the other reports a stream it cannot read, and nothing in the audio alone
/// says which choice was wrong.
///
/// [`Alac`]: AudioCodec::Alac
/// [`AacEld`]: AudioCodec::AacEld
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioCodec {
    /// Apple Lossless, which is what AirPlay 1 clients send.
    Alac,
    /// MPEG-4 AAC Enhanced Low Delay, which is what a mirroring client sends
    /// alongside its video.
    AacEld,
}

impl AudioCodec {
    /// Every coding this receiver can decode.
    ///
    /// The `cn` record in the mDNS text record is built from this list, so a client is
    /// only offered codings that a renderer here can actually take. The list is short on
    /// purpose: a receiver that advertises PCM or plain AAC and then feeds those frames
    /// to an ELD decoder produces noise, and a client has no way to notice.
    pub const ALL: [Self; 2] = [Self::Alac, Self::AacEld];

    /// The number this coding is known by in the `cn` record.
    ///
    /// `0` is PCM, `1` ALAC, `2` AAC and `3` AAC-ELD
    #[must_use]
    pub fn codec_number(self) -> u8 {
        match self {
            Self::Alac => 1,
            Self::AacEld => 3,
        }
    }

    /// The coding a client's `ct` names, when it names one this crate decodes.
    ///
    /// `2` is ALAC and `8` is AAC-ELD. A client states one or the
    /// other in `SETUP`, and the protocol takes its decoder from that rather than from a
    /// setting: both are compressed, and a decoder handed the wrong one reports a stream it
    /// cannot read rather than the mix-up.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_airplay::AudioCodec;
    ///
    /// assert_eq!(AudioCodec::from_compression_type(2), Some(AudioCodec::Alac));
    /// assert_eq!(AudioCodec::from_compression_type(8), Some(AudioCodec::AacEld));
    /// assert_eq!(AudioCodec::from_compression_type(3), None);
    /// ```
    #[must_use]
    pub fn from_compression_type(compression_type: u16) -> Option<Self> {
        match compression_type {
            2 => Some(Self::Alac),
            8 => Some(Self::AacEld),
            _ => None,
        }
    }

    /// The name GStreamer and FFmpeg know this coding by, which a backend needs for
    /// its pipeline and a log needs to be readable.
    pub fn name(self) -> &'static str {
        match self {
            Self::Alac => "alac",
            Self::AacEld => "aac-eld",
        }
    }
}

/// What an audio stream is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioConfig {
    /// The coding of its frames.
    pub codec: AudioCodec,
    /// Samples a second, which AirPlay sends at 44.1 kHz.
    pub sample_rate: u32,
    /// Channels per frame.
    pub channels: u8,
    /// Samples in one coded frame, which a client states as `spf` in `SETUP`.
    ///
    /// It matters to a decoder that has to know where a frame ends: ALAC and AAC-ELD
    /// frames are not the same length, and a backend told only the coding can still be
    /// wrong about the frame.
    pub samples_per_frame: u16,
}

impl Default for AudioConfig {
    fn default() -> Self {
        Self {
            codec: AudioCodec::Alac,
            sample_rate: 44_100,
            channels: 2,
            samples_per_frame: 480,
        }
    }
}

/// What a video stream is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoConfig {
    /// Width in pixels, when the client has said.
    pub width: Option<u32>,
    /// Height in pixels, when the client has said.
    pub height: Option<u32>,
    /// The coding the frames will be in.
    ///
    /// A backend has to know this before it chooses a decoder: `h264parse` cannot read an
    /// HEVC unit and an HEVC decoder cannot read H.264, and a stream that picks the wrong
    /// one shows nothing at all rather than something wrong. The core decrypts and frames
    /// the stream but does not decode it, so this is part of the contract between them.
    pub codec: VideoCodec,
}

/// The coding a mirror stream carries.
///
/// A client sends one of the two and does not change mid-session, and the two need
/// different parsers and decoders. The protocol keeps the same distinction as a flag
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VideoCodec {
    /// H.264, which is what every client sends unless told otherwise.
    #[default]
    H264,
    /// HEVC, which a 4K-capable client sends when the receiver asks for it.
    H265,
}

impl VideoCodec {
    /// The name GStreamer and FFmpeg know this coding by.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::H264 => "h264",
            Self::H265 => "h265",
        }
    }
}
