// SPDX-License-Identifier: GPL-3.0-or-later
//! The coded frames and the error a backend reports.

use std::fmt;

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
