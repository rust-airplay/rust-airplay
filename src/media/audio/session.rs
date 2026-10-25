// SPDX-License-Identifier: GPL-3.0-or-later
//! One session's audio stream: decryption state, flush requests and errors.

use crate::crypto::CryptoError;

use super::packet::{AudioPacketError, AudioPayloadKind, decrypt_payload, parse_audio_packet};
use super::reorder::{AudioFrame, ReorderWindow};
use crate::media::control::{self, ControlError};

/// One audio stream of one session: the datagrams a client sends, decrypted and
/// put back in order.
///
/// The key and IV are the ones `SETUP` handed over (`SetupRequest::audio_key` and
/// `audio_iv`); a receiver that has not set a session up has neither, and must
/// not build one of these.
pub struct AudioSession {
    key: [u8; 16],
    iv: [u8; 16],
    window: ReorderWindow,
    /// A flush asked for by a control connection, waiting to be applied.
    ///
    /// `FLUSH` arrives on the control socket, but the window lives here, on the task
    /// that drains the data socket. A slot with at most one request is all that is
    /// needed: applying the newest request is what flushing means.
    flush_request: std::sync::Arc<std::sync::Mutex<Option<u16>>>,
}

impl std::fmt::Debug for AudioSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key and IV decrypt every frame of the stream; a debug print is the most
        // common way for a secret to reach a log.
        formatter
            .debug_struct("AudioSession")
            .field("key", &"<redacted>")
            .field("iv", &"<redacted>")
            .field("window", &self.window)
            .field("flush_request", &self.flush_request)
            .finish()
    }
}

/// A way to ask a session to flush, held by whoever serves `FLUSH`.
#[derive(Debug, Clone)]
pub struct FlushHandle(std::sync::Arc<std::sync::Mutex<Option<u16>>>);

impl FlushHandle {
    /// Asks the session to restart delivery at `next`.
    pub fn request(&self, next: u16) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(next);
        }
    }
}

impl AudioSession {
    /// Creates a session that holds at most `capacity` reordered packets.
    pub fn new(key: [u8; 16], iv: [u8; 16], capacity: usize) -> Self {
        Self {
            key,
            iv,
            window: ReorderWindow::new(capacity),
            flush_request: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// A handle a control connection can use to flush this session.
    pub fn flush_handle(&self) -> FlushHandle {
        FlushHandle(std::sync::Arc::clone(&self.flush_request))
    }

    /// Applies a flush that arrived since the last datagram.
    ///
    /// Returns the sequence the window restarted at, which is worth logging once: a
    /// flush that arrives mid-stream is either a pause or a seek, and the log is the only
    /// place that distinction is visible.
    pub fn apply_flush(&mut self) -> Option<u16> {
        let next = self
            .flush_request
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        if let Some(next) = next {
            self.window.flush(next);
        }
        next
    }

    /// Discards everything buffered and expects `next` to be the next sequence number.
    pub fn flush(&mut self, next: u16) {
        self.window.flush(next);
    }

    /// Reads one datagram and returns the frames that are ready for a renderer.
    ///
    /// The marker an AAC-ELD stream starts with is delivered undecrypted:
    /// the protocol treats it as a packet with no audio in it, so decrypting it would
    /// produce nonsense.
    ///
    /// # Errors
    ///
    /// Returns [`AudioSessionError`] for a datagram this stream cannot use, or
    /// when the payload does not decrypt.
    pub fn receive(&mut self, datagram: &[u8]) -> Result<Vec<AudioFrame>, AudioSessionError> {
        self.apply_flush();
        let packet = parse_audio_packet(datagram)?;
        let payload = match packet.kind {
            AudioPayloadKind::NoDataMarker => packet.payload.to_vec(),
            AudioPayloadKind::Data => decrypt_payload(&self.key, &self.iv, packet.payload)?,
        };
        Ok(self.window.accept(AudioFrame {
            sequence: packet.sequence,
            timestamp: packet.timestamp,
            payload,
            kind: packet.kind,
        }))
    }

    /// Reads one control datagram and returns any audio it delivered.
    ///
    /// A client answers a resend request by sending the audio packet again on the
    /// control port, wrapped in four bytes the protocol skips
    /// The audio
    /// inside goes through the same path as a packet that arrived on the data
    /// port, so a resend fills the gap the window is waiting for instead of being
    /// treated as a duplicate.
    ///
    /// A sync packet is read and reported as "nothing to deliver": the timing
    /// service that consumes it is the next slice.
    ///
    /// # Errors
    ///
    /// Returns [`AudioSessionError`] for a control packet this session cannot
    /// read, or when a resent audio packet does not decrypt.
    pub fn receive_control(
        &mut self,
        datagram: &[u8],
    ) -> Result<Vec<AudioFrame>, AudioSessionError> {
        match control::parse_control_packet(datagram)? {
            control::ControlPacket::ResentAudio { packet, .. } => self.receive(packet),
            control::ControlPacket::Sync { .. } | control::ControlPacket::Other { .. } => {
                Ok(Vec::new())
            }
        }
    }

    /// Sequence numbers given up on since they were last taken.
    pub fn take_lost(&mut self) -> Vec<u16> {
        self.window.take_lost()
    }

    /// Sequence numbers to ask the client to send again.
    pub fn take_resend_requests(&mut self, limit: usize) -> Vec<u16> {
        self.window.take_resend_requests(limit)
    }
}

/// Why a datagram could not be turned into audio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioSessionError {
    /// The datagram was not an audio packet.
    Packet(AudioPacketError),
    /// The payload could not be decrypted.
    Decrypt(CryptoError),
    /// The control packet could not be read.
    Control(ControlError),
}

impl From<AudioPacketError> for AudioSessionError {
    fn from(error: AudioPacketError) -> Self {
        Self::Packet(error)
    }
}

impl From<ControlError> for AudioSessionError {
    fn from(error: ControlError) -> Self {
        Self::Control(error)
    }
}

impl From<CryptoError> for AudioSessionError {
    fn from(error: CryptoError) -> Self {
        Self::Decrypt(error)
    }
}

impl std::fmt::Display for AudioSessionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Packet(error) => write!(formatter, "{error}"),
            Self::Decrypt(error) => write!(formatter, "the payload did not decrypt: {error:?}"),
            Self::Control(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for AudioSessionError {}
