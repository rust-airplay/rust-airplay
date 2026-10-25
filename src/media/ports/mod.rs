// SPDX-License-Identifier: GPL-3.0-or-later
//! The sockets one media session listens on.
//!
//! A client does not send media anywhere it likes: `SETUP` tells it which ports
//! to use, and until now this crate told it nothing, because nothing was
//! listening. This module binds the three sockets an audio session needs and
//! drives the receive path over them, so the ports a receiver advertises are the
//! ports that answer:
//!
//! - the **timing** port, where the clock exchange happens ([`super::timing`]),
//! - the **control** port, where resends and sync packets arrive ([`super::control`]),
//! - the **data** port, where the audio datagrams arrive ([`super::audio`]).
//!
//! The protocol opens exactly these three for an audio session
//! (, which binds a control and
//! a data socket beside the timing socket of). The mirror stream
//! adds a TCP listener, and arrives with its own slice.
//!
//! Nothing here decides policy: the key and IV come from the `SETUP` that a
//! caller accepted, and frames go to a caller's callback, which is where a
//! renderer plugs in ([the architecture document](../../../docs/ARCHITECTURE.md)).

mod mirror;
mod sockets;

pub use mirror::MirrorStream;
pub use sockets::{MAX_DATAGRAM, MediaPorts, MediaSockets, Received};

/// Creates a session for a `SETUP` that carried `key` and `iv`.
pub fn session(key: [u8; 16], iv: [u8; 16]) -> super::audio::AudioSession {
    super::audio::AudioSession::new(key, iv, super::audio::WINDOW_CAPACITY)
}

/// Why serving a mirror stream stopped.
///
/// The two cases are kept apart because they mean different things to a caller: a
/// connection that failed can be retried, while a stream this receiver has lost
/// cannot be picked up again by reading more packets.
#[derive(Debug)]
pub enum ServeError {
    /// The connection itself failed, or the client sent something that is not a
    /// packet at all.
    Connection(std::io::Error),
    /// A packet could not be placed in the stream.
    Frame(crate::media::mirror::FrameError),
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connection(error) => write!(formatter, "the mirror connection: {error}"),
            Self::Frame(error) => write!(formatter, "the mirror stream: {error}"),
        }
    }
}

impl std::error::Error for ServeError {}

impl From<std::io::Error> for ServeError {
    fn from(error: std::io::Error) -> Self {
        Self::Connection(error)
    }
}

#[cfg(test)]
mod tests;
