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

use std::fmt;

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

/// The volume an AirPlay client means by the number it sends.
///
/// A client states volume in decibels over `-30` to `0`, and `-144` is its mute signal
/// A renderer wants a linear gain, so the two scales meet here:
/// the fraction is how far up the slider the client is, and the curve turns that into the
/// gain a sound card understands.
///
/// The direction matters: `-30` is silence and `0` is full, so an `-8` decibel value must land
/// high on the slider and a `-22` one low. The first version of this function computed the
/// two ends and the middle correctly and mirrored everything between them, which is a volume
/// that is quiet near the top and loud near the bottom.
///
/// # Examples
///
/// ```
/// use rust_airplay::airplay_db_to_fraction;
///
/// assert_eq!(airplay_db_to_fraction(0.0), 1.0, "0 dB is full volume");
/// assert_eq!(airplay_db_to_fraction(-30.0), 0.0, "-30 dB is silence");
/// assert_eq!(airplay_db_to_fraction(-144.0), 0.0, "-144 is the mute signal");
/// assert!((airplay_db_to_fraction(-15.0) - 0.5).abs() < 1e-9);
/// assert!(airplay_db_to_fraction(-8.0) > airplay_db_to_fraction(-22.0));
/// ```
#[must_use]
pub fn airplay_db_to_fraction(db: f64) -> f64 {
    const MUTE: f64 = -144.0;
    const LOW_DB: f64 = -30.0;
    const HIGH_DB: f64 = 0.0;
    if db == MUTE || db <= LOW_DB {
        return 0.0;
    }
    if db >= HIGH_DB {
        return 1.0;
    }
    ((db - LOW_DB) / (HIGH_DB - LOW_DB)).clamp(0.0, 1.0)
}

/// How a client's slider position becomes a gain.
///
/// This is the protocol's `-db` and `-taper` together. Flat rescaled the `-30..0` decibel range
/// onto `low_db..high_db`; tapered makes each halving of the remaining slider length a
/// halving of loudness (ten decibels), which is how several AirPlay senders behave
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VolumeCurve {
    /// Use the tapered profile rather than the flat one.
    pub taper: bool,
    /// Attenuation, in decibels, at the bottom of the slider.
    pub low_db: f64,
    /// Attenuation, in decibels, at the top of the slider.
    pub high_db: f64,
}

impl Default for VolumeCurve {
    fn default() -> Self {
        Self {
            taper: false,
            low_db: -30.0,
            high_db: 0.0,
        }
    }
}

impl VolumeCurve {
    /// The decibels this curve gives a slider position.
    #[must_use]
    pub fn db_for_fraction(self, fraction: f64) -> f64 {
        let fraction = fraction.clamp(0.0, 1.0);
        if fraction <= 0.0 {
            return self.low_db;
        }
        let flat = self.low_db + (self.high_db - self.low_db) * fraction;
        if self.taper {
            let tapered = self.high_db + 10.0 * fraction.log2();
            // The taper is never quieter than the flat mapping at the same position.
            tapered.max(flat)
        } else {
            flat
        }
    }

    /// The linear gain a renderer plays at for a slider position.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_airplay::VolumeCurve;
    ///
    /// let flat = VolumeCurve::default();
    /// assert!((flat.gain(1.0) - 1.0).abs() < 1e-12);
    /// assert_eq!(flat.gain(0.0), 0.0);
    ///
    /// // The tapered profile is louder than the flat one in the middle of the slider.
    /// let tapered = VolumeCurve {
    /// taper: true,
    /// ..VolumeCurve::default()
    /// };
    /// assert!(tapered.gain(0.5) > flat.gain(0.5));
    /// ```
    #[must_use]
    pub fn gain(self, fraction: f64) -> f64 {
        if fraction <= 0.0 {
            return 0.0;
        }
        // Decibels to a linear scale: `10 ** (0.05 * db)`.
        10f64.powf(0.05 * self.db_for_fraction(fraction))
    }
}

/// The volume a renderer plays at, from silence to full.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Volume(f64);

impl Volume {
    /// Full volume, which is what a session starts at: a client that says nothing
    /// about volume is not asking for silence.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_airplay::Volume;
    ///
    /// assert_eq!(Volume::new(0.5).fraction(), 0.5);
    /// assert_eq!(Volume::new(2.0), Volume::FULL, "a gain above unity is clamped");
    /// assert_eq!(Volume::new(-1.0).fraction(), 0.0);
    /// ```
    pub const FULL: Self = Self(1.0);

    /// The volume as a number from `0.0` to `1.0`, which is what a backend's own volume
    /// control takes.
    #[must_use]
    pub fn fraction(self) -> f64 {
        self.0
    }

    /// A volume, clamped to the range a client can ask for.
    ///
    /// AirPlay sends volume in decibels, where `0` is full scale and lower values are
    /// quieter; a value above full scale is not something to pass on to a device.
    #[must_use]
    pub fn new(level: f64) -> Self {
        if level.is_nan() {
            return Self::FULL;
        }
        Self(level.clamp(0.0, 1.0))
    }

    /// The level, from zero to one.
    pub fn level(self) -> f64 {
        self.0
    }
}

impl Default for Volume {
    fn default() -> Self {
        Self::FULL
    }
}

/// One audio frame, coded as its stream's codec.
#[derive(Clone, PartialEq, Eq)]
pub struct AudioFrame {
    /// The coded frame, as it arrived.
    pub data: Vec<u8>,
    /// The client's timestamp for it, in the remote clock the session is on. A renderer
    /// that plays in step with video needs it; one that plays audio alone may ignore
    /// it.
    pub timestamp: u64,
}

impl std::fmt::Debug for AudioFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AudioFrame")
            .field("data", &format!("<{} bytes>", self.data.len()))
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

/// One video frame, in Annex-B form.
#[derive(Clone, PartialEq, Eq)]
pub struct VideoFrame {
    /// The frame's units, each behind an `00 00 00 01` start code.
    pub data: Vec<u8>,
    /// The client's timestamp, which is the wall-clock time the frame belongs to.
    pub timestamp: u64,
    /// Whether this is a key frame, which a decoder needs to start.
    pub keyframe: bool,
}

impl std::fmt::Debug for VideoFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VideoFrame")
            .field("data", &format!("<{} bytes>", self.data.len()))
            .field("timestamp", &self.timestamp)
            .field("keyframe", &self.keyframe)
            .finish()
    }
}

/// Why a renderer refused to open, or stopped.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// The backend is not available on this machine, with what is missing.
    ///
    /// A missing decoder or sink is an environment problem, not a protocol one
    /// ([the architecture document](../../../docs/ARCHITECTURE.md)), so it is reported
    /// rather than worked around: a receiver that silently plays nothing is worse
    /// than one that says why.
    Unavailable(String),
    /// The backend failed at something it was asked to do.
    Failed(String),
}

impl fmt::Display for RenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(formatter, "the renderer is unavailable: {reason}"),
            Self::Failed(reason) => write!(formatter, "the renderer failed: {reason}"),
        }
    }
}

impl std::error::Error for RenderError {}

/// What renders a session's media.
///
/// A backend implements this; the application injects it; the protocol core never sees
/// it (the architecture document rule 2). The two streams are separate because a session can have one
/// without the other — an audio-only client never opens a video stream — and because
/// two backends can serve one session, one per stream (the architecture document rule 4).
///
/// Every method takes `&self` rather than `&mut self` so that a session can hold the
/// renderer while its receive loop holds the streams; a backend that needs mutable
/// state keeps it behind its own lock, which is also what lets a real one be driven
/// from a media thread while the protocol thread reads it.
pub trait Renderer: fmt::Debug + Send + Sync {
    /// Prepares to render an audio stream.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError`] when the backend cannot serve this configuration, which
    /// a caller reports and a session continues without audio.
    fn open_audio(&self, config: AudioConfig) -> Result<Box<dyn AudioStream>, RenderError>;

    /// Prepares to render a video stream.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError`] when the backend cannot serve this configuration.
    fn open_video(&self, config: VideoConfig) -> Result<Box<dyn VideoStream>, RenderError>;

    /// Sets the volume every stream plays at.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError`] when the backend cannot apply it.
    fn set_volume(&self, volume: Volume) -> Result<(), RenderError>;
}

/// An open audio stream.
pub trait AudioStream: fmt::Debug + Send + Sync {
    /// Hands one frame to the backend.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError`] when the backend cannot take it, which a caller reports
    /// and the session continues: one frame a decoder refuses is not a reason to drop
    /// a client.
    fn push(&self, frame: AudioFrame) -> Result<(), RenderError>;

    /// Drops what has not been played, as a flush or a seek does.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError`] when the backend cannot flush.
    fn flush(&self) -> Result<(), RenderError>;

    /// Ends the stream.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError`] when the backend cannot close it cleanly.
    fn close(&self) -> Result<(), RenderError>;
}

/// An open video stream.
pub trait VideoStream: fmt::Debug + Send + Sync {
    /// Hands one frame to the backend.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError`] when the backend cannot take it.
    fn push(&self, frame: VideoFrame) -> Result<(), RenderError>;

    /// Reports the spacing the stream is arriving at, so a backend can play at the
    /// rate a client sent rather than as fast as it can read.
    ///
    /// This matters more than it looks. A mirror stream is one key frame followed
    /// by frames that only describe how the picture *changed*, so a receiver that
    /// decodes faster than real time loses frames the rest of the stream depends
    /// on, and nothing in a later frame can repair that — the picture stays partly
    /// wrong for the whole session. A backend that simply reads as fast as it can
    /// therefore shows a picture that is only partly decoded, which is exactly what
    /// one did until this existed.
    ///
    /// The value is the interval since the previous frame, which is the spacing the
    /// stream has been arriving at. Called before a frame when [`crate::Config::pace_video`]
    /// is off; when the receiver paces itself it does the waiting and does not call
    /// this. The default does nothing, because a backend that decodes on its own
    /// schedule (or plays nothing) has no use for it.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError`] when the backend cannot apply it.
    fn set_pace(&self, interval_seconds: f64) -> Result<(), RenderError> {
        let _ = interval_seconds;
        Ok(())
    }

    /// Drops what has not been played.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError`] when the backend cannot flush.
    fn flush(&self) -> Result<(), RenderError>;
    /// Holds the picture where it is, when the client says it stopped sending.
    ///
    /// A mirroring client that stops, or an app that covers the screen, says so in a codec
    /// packet. A backend that owns a window can freeze it
    /// here; the default does nothing, because a pipeline that simply stops receiving
    /// frames already holds its last one.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError`] when the backend cannot hold the picture.
    fn pause(&self) -> Result<(), RenderError> {
        Ok(())
    }

    /// Starts the picture again after [`VideoStream::pause`].
    ///
    /// # Errors
    ///
    /// Returns [`RenderError`] when the backend cannot resume.
    fn resume(&self) -> Result<(), RenderError> {
        Ok(())
    }

    /// Ends the stream.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError`] when the backend cannot close it cleanly.
    fn close(&self) -> Result<(), RenderError>;
}

/// A renderer that accepts everything and plays nothing.
///
/// It exists for the two jobs a fake is for: a session can run end to end without a
/// media library ([`docs/ARCHITECTURE.md`] asks for exactly that), and a backend can be
/// compared against a known-good consumer of the interface.
///
/// What it counts is what a test asserts on, and a count is all it is: no timestamps
/// are ordered and no frame is decoded, so it says nothing about whether what arrived
/// would play.
///
/// [`docs/ARCHITECTURE.md`]: ../../../docs/ARCHITECTURE.md
#[derive(Debug, Default)]
pub struct NullRenderer {
    audio: std::sync::Arc<Counters>,
    video: std::sync::Arc<Counters>,
    volume: std::sync::Mutex<Volume>,
}

/// What one stream of [`NullRenderer`] has been handed.
#[derive(Debug, Default)]
struct Counters {
    opened: std::sync::atomic::AtomicUsize,
    frames: std::sync::atomic::AtomicUsize,
    bytes: std::sync::atomic::AtomicUsize,
    flushed: std::sync::atomic::AtomicUsize,
    closed: std::sync::atomic::AtomicUsize,
}

impl NullRenderer {
    /// A renderer that has rendered nothing yet.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// use rust_airplay::{AudioConfig, AudioFrame, NullRenderer, Renderer};
    ///
    /// let renderer = Arc::new(NullRenderer::new());
    /// let stream = renderer.open_audio(AudioConfig::default()).expect("a stream");
    /// stream
    /// .push(AudioFrame {
    /// data: vec![0; 4],
    /// timestamp: 0,
    /// })
    /// .expect("a frame");
    /// assert_eq!(renderer.audio_frames(), 1);
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Audio streams opened so far.
    pub fn audio_streams(&self) -> usize {
        self.audio.opened.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Audio frames handed to it so far.
    pub fn audio_frames(&self) -> usize {
        self.audio.frames.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Audio bytes handed to it so far.
    pub fn audio_bytes(&self) -> usize {
        self.audio.bytes.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Video streams opened so far.
    pub fn video_streams(&self) -> usize {
        self.video.opened.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Video frames handed to it so far.
    pub fn video_frames(&self) -> usize {
        self.video.frames.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Flushes a stream of either kind has been asked for.
    pub fn flushes(&self) -> usize {
        self.audio
            .flushed
            .load(std::sync::atomic::Ordering::Relaxed)
            + self
                .video
                .flushed
                .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Streams of either kind that have been closed.
    pub fn closed(&self) -> usize {
        self.audio.closed.load(std::sync::atomic::Ordering::Relaxed)
            + self.video.closed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The volume its streams play at.
    pub fn volume(&self) -> Volume {
        *self
            .volume
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Renderer for NullRenderer {
    fn open_audio(&self, _config: AudioConfig) -> Result<Box<dyn AudioStream>, RenderError> {
        self.audio
            .opened
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(Box::new(NullAudio {
            counters: std::sync::Arc::clone(&self.audio),
        }))
    }

    fn open_video(&self, _config: VideoConfig) -> Result<Box<dyn VideoStream>, RenderError> {
        self.video
            .opened
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(Box::new(NullVideo {
            counters: std::sync::Arc::clone(&self.video),
        }))
    }

    fn set_volume(&self, volume: Volume) -> Result<(), RenderError> {
        *self
            .volume
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = volume;
        Ok(())
    }
}

/// One audio stream of [`NullRenderer`].
struct NullAudio {
    counters: std::sync::Arc<Counters>,
}

impl fmt::Debug for NullAudio {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NullAudio")
            .field(
                "frames",
                &self
                    .counters
                    .frames
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
            .finish()
    }
}

impl AudioStream for NullAudio {
    fn push(&self, frame: AudioFrame) -> Result<(), RenderError> {
        self.counters
            .frames
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.counters
            .bytes
            .fetch_add(frame.data.len(), std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn flush(&self) -> Result<(), RenderError> {
        self.counters
            .flushed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn close(&self) -> Result<(), RenderError> {
        self.counters
            .closed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

/// One video stream of [`NullRenderer`].
struct NullVideo {
    counters: std::sync::Arc<Counters>,
}

impl fmt::Debug for NullVideo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NullVideo")
            .field(
                "frames",
                &self
                    .counters
                    .frames
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
            .finish()
    }
}

impl VideoStream for NullVideo {
    fn push(&self, frame: VideoFrame) -> Result<(), RenderError> {
        self.counters
            .frames
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.counters
            .bytes
            .fetch_add(frame.data.len(), std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn flush(&self) -> Result<(), RenderError> {
        self.counters
            .flushed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn close(&self) -> Result<(), RenderError> {
        self.counters
            .closed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

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
