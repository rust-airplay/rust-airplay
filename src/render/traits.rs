// SPDX-License-Identifier: GPL-3.0-or-later
//! The renderer boundary: the traits a media backend implements.

use std::fmt;

use super::*;

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
    /// stream has been arriving at. A backend that implements pacing must keep a
    /// **cumulative deadline**: add the interval to the previous deadline, sleep only
    /// until that deadline, and if the deadline has already passed, re-anchor on the
    /// current time instead of sleeping a fixed interval after every frame. Sleeping
    /// `interval` after each frame accumulates the scheduling error, so a stream that
    /// should be stable slowly falls behind.
    ///
    /// The receiver does not call this: when [`crate::Config::pace_video`] is off it
    /// pushes frames at full speed and lets the backend's own backpressure decide the
    /// rate; when it is on the receiver does the waiting itself. The method remains for
    /// a caller that drives the trait directly. The default does nothing, because a
    /// backend that decodes on its own schedule (or plays nothing) has no use for it.
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
