// SPDX-License-Identifier: GPL-3.0-or-later
//! A playback backend that writes what it receives to files.
//!
//! This is the smallest complete implementation of [`rust_airplay::Renderer`]: it opens both
//! streams, appends every frame to a file, and drops the file when the stream ends. It plays
//! nothing, which is the point - the shape of a real backend is the same, with a decoder and
//! a device where the `File` is.
//!
//! Run a receiver with it by handing it to the configuration:
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use rust_airplay::Config;
//!
//! let renderer = Arc::new(Recorder::new());
//! let config = Config::new("Living room", [0x2a; 32], renderer);
//! // From an async context: rust_airplay::run(config).await
//! ```

use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex};

use rust_airplay::{
    AudioConfig, AudioFrame, AudioStream, RenderError, Renderer, VideoConfig, VideoFrame,
    VideoStream, Volume,
};

/// A renderer whose two streams are files.
#[derive(Debug)]
pub struct Recorder {
    audio: Arc<Mutex<Option<File>>>,
    video: Arc<Mutex<Option<File>>>,
    volume: Mutex<Volume>,
}

impl Recorder {
    /// A recorder that has not opened a stream yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            audio: Arc::new(Mutex::new(None)),
            video: Arc::new(Mutex::new(None)),
            volume: Mutex::new(Volume::FULL),
        }
    }
}

impl Default for Recorder {
    fn default() -> Self {
        Self::new()
    }
}

/// One of the recorder's streams, which is a file it appends to.
#[derive(Debug)]
pub struct RecordingStream {
    file: Arc<Mutex<Option<File>>>,
}

impl RecordingStream {
    fn write(&self, bytes: &[u8]) -> Result<(), RenderError> {
        let mut slot = self.file.lock().expect("the recorder lock");
        let Some(file) = slot.as_mut() else {
            // The stream was closed while a frame was in flight; dropping the frame is the
            // same answer a backend gives when its device has gone.
            return Ok(());
        };
        file.write_all(bytes)
            .map_err(|error| RenderError::Failed(error.to_string()))
    }

    fn finish(&self) {
        *self.file.lock().expect("the recorder lock") = None;
    }
}

impl AudioStream for RecordingStream {
    fn push(&self, frame: AudioFrame) -> Result<(), RenderError> {
        self.write(&frame.data)
    }

    fn flush(&self) -> Result<(), RenderError> {
        // A file is append-only history; there is nothing queued to drop.
        Ok(())
    }

    fn close(&self) -> Result<(), RenderError> {
        self.finish();
        Ok(())
    }
}

impl VideoStream for RecordingStream {
    fn push(&self, frame: VideoFrame) -> Result<(), RenderError> {
        self.write(&frame.data)
    }

    fn flush(&self) -> Result<(), RenderError> {
        Ok(())
    }

    fn close(&self) -> Result<(), RenderError> {
        self.finish();
        Ok(())
    }
}

impl Renderer for Recorder {
    fn open_audio(&self, _config: AudioConfig) -> Result<Box<dyn AudioStream>, RenderError> {
        let file = File::create("audio.aac")
            .map_err(|error| RenderError::Unavailable(error.to_string()))?;
        *self.audio.lock().expect("the recorder lock") = Some(file);
        Ok(Box::new(RecordingStream {
            file: Arc::clone(&self.audio),
        }))
    }

    fn open_video(&self, _config: VideoConfig) -> Result<Box<dyn VideoStream>, RenderError> {
        let file = File::create("video.h264")
            .map_err(|error| RenderError::Unavailable(error.to_string()))?;
        *self.video.lock().expect("the recorder lock") = Some(file);
        Ok(Box::new(RecordingStream {
            file: Arc::clone(&self.video),
        }))
    }

    fn set_volume(&self, volume: Volume) -> Result<(), RenderError> {
        *self.volume.lock().expect("the volume lock") = volume;
        Ok(())
    }
}

fn main() {
    // A program hands this to `Config::new` and calls `rust_airplay::run`. Building it here
    // keeps the example runnable without opening a socket.
    let renderer = Arc::new(Recorder::new());
    let _: Arc<dyn Renderer> = renderer;
}
