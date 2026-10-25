// SPDX-License-Identifier: GPL-3.0-or-later
//! One audio datagram: its RTP header, payload kind and decryption.

use crate::crypto::{self, CryptoError};
use crate::rtp;
use crate::wire::ParseError;

/// Payload type the protocol names for audio.
pub const AUDIO_PAYLOAD_TYPE: u8 = 96;

/// The marker an AAC-ELD stream sends in place of audio while it starts
pub const NO_DATA_MARKER: [u8; 4] = [0x00, 0x68, 0x34, 0x00];

/// Datagrams a reorder window holds before it gives up on a gap.
///
/// The protocol's buffer is sized for the same purpose: it has to absorb the
/// reordering a network produces without keeping a client able to make a
/// receiver allocate without bound.
pub const WINDOW_CAPACITY: usize = 512;

/// What one audio datagram turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioPacket<'a> {
    /// Sequence number from the RTP header.
    pub sequence: u16,
    /// RTP timestamp from the RTP header, in the audio clock.
    pub timestamp: u32,
    /// Payload, still encrypted.
    pub payload: &'a [u8],
    /// What the payload is, as far as this receiver can tell before decryption.
    pub kind: AudioPayloadKind,
}

/// The payload of an audio datagram, before it is decrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioPayloadKind {
    /// Audio, which the renderer plays once it is decrypted.
    Data,
    /// The four byte marker an AAC-ELD stream sends while it starts.
    NoDataMarker,
}

/// Why a datagram could not be read as audio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioPacketError {
    /// Shorter than the twelve byte header; the protocol ignores these
    TooShort,
    /// The RTP header itself did not parse.
    Header(ParseError),
    /// A payload type this receiver does not know how to play.
    UnexpectedPayloadType(u8),
}

impl std::fmt::Display for AudioPacketError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(formatter, "the datagram is shorter than an RTP header"),
            Self::Header(error) => write!(formatter, "the RTP header did not parse: {error:?}"),
            Self::UnexpectedPayloadType(payload_type) => {
                write!(formatter, "payload type {payload_type} is not audio")
            }
        }
    }
}

impl std::error::Error for AudioPacketError {}

/// Reads one audio datagram.
///
/// # Errors
///
/// Returns [`AudioPacketError`] for a datagram shorter than a header, one whose
/// RTP header does not parse, or one that carries a payload type other than
/// [`AUDIO_PAYLOAD_TYPE`].
pub fn parse_audio_packet(datagram: &[u8]) -> Result<AudioPacket<'_>, AudioPacketError> {
    if datagram.len() < 12 {
        return Err(AudioPacketError::TooShort);
    }
    let packet = rtp::parse(datagram).map_err(AudioPacketError::Header)?;
    if packet.payload_type != AUDIO_PAYLOAD_TYPE {
        return Err(AudioPacketError::UnexpectedPayloadType(packet.payload_type));
    }
    let kind = if packet.payload == NO_DATA_MARKER {
        AudioPayloadKind::NoDataMarker
    } else {
        AudioPayloadKind::Data
    };
    Ok(AudioPacket {
        sequence: packet.sequence,
        timestamp: packet.timestamp,
        payload: packet.payload,
        kind,
    })
}

/// Decrypts one audio payload the way the protocol does
///
/// Two details there are easy to get wrong and are therefore stated here:
///
/// - Only the part that fills whole blocks is encrypted: the receiver decrypts
///   `payload_size / 16 * 16` bytes and copies the remaining tail through unchanged, so a
///   payload whose length is not a multiple of sixteen ends in clear bytes rather than being
///   padded.
/// - The cipher is reset for every packet, which makes each packet start from the same IV that
///   `SETUP` carried. Nothing chains across packets, so a receiver that decrypted them as one
///   stream would produce noise.
///
/// # Errors
///
/// Returns [`CryptoError`] when the key or IV has the wrong length; an empty
/// encrypted prefix is not an error, it is a payload that is entirely clear.
pub fn decrypt_payload(
    key: &[u8; 16],
    iv: &[u8; 16],
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let encrypted = payload.len() / 16 * 16;
    let mut output = Vec::with_capacity(payload.len());
    if encrypted > 0 {
        output.extend_from_slice(&crypto::aes128_cbc_decrypt(key, iv, &payload[..encrypted])?);
    }
    output.extend_from_slice(&payload[encrypted..]);
    Ok(output)
}
