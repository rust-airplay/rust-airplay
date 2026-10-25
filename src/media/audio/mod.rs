// SPDX-License-Identifier: GPL-3.0-or-later
//! The audio stream a client sends after `SETUP`.
//!
//! The receiver receives audio datagrams, unwraps the RTP header, decrypts the payload and
//! hands the result to a renderer in sequence order, with buffering and loss detection. This
//! module is that path: it parses a datagram, decrypts the payload, and delivers frames in
//! sequence order through a bounded reorder window, recording what went missing so a resend can
//! be asked for.
//!
//! # What a datagram looks like
//!
//! The layout is:
//!
//! ```text
//! packet[0] 0x80
//! packet[1] 0x60, that is payload type 96
//! packet[2:3] sequence number, big endian
//! packet[4:7] RTP timestamp, big endian
//! packet[8:11] 0x00 0x00 0x00 0x00
//! packet[12..] encrypted audio payload
//! ```
//!
//! A datagram shorter than twelve bytes is not a packet at all
//! Two shapes of "not audio yet" exist in a stream that
//! is starting: an AAC-ELD stream begins with length-16 packets whose payload is
//! the marker `00 68 34 00` instead of audio, and an ALAC
//! stream begins with length-44 packets whose payload carries format information
//! rather than samples. Both are reported as what they
//! are, so a renderer never plays a marker as sound.
//!
//! Decryption is [`decrypt_payload`], and it is not a plain CBC over the payload:
//! only the bytes that fill whole blocks are encrypted, the tail stays in clear,
//! and the cipher is reset for every packet. Those three facts are what a
//! receiver that decrypts the stream as one cipher stream gets wrong.

mod packet;
mod reorder;
mod session;

pub use packet::WINDOW_CAPACITY;
pub use packet::{
    AUDIO_PAYLOAD_TYPE, AudioPacket, AudioPacketError, AudioPayloadKind, NO_DATA_MARKER,
    decrypt_payload, parse_audio_packet,
};
pub use reorder::{AudioFrame, ReorderWindow};
pub use session::{AudioSession, AudioSessionError, FlushHandle};

#[cfg(test)]
mod tests;
