// SPDX-License-Identifier: GPL-3.0-or-later
//! A renderer that accepts everything, counts it and plays nothing.

use std::fmt;

use super::*;

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
