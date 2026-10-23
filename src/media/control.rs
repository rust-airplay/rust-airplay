// SPDX-License-Identifier: GPL-3.0-or-later
//! The control channel of an audio session.
//!
//! Beside the port that carries audio datagrams, a session has a control port.
//! Three things travel over it, all of them documented in upstream's source:
//!
//! - **A resend request**, from this receiver to the client, when audio went
//!   missing: eight bytes, and the client answers by sending the audio packets
//!   again (`upstream/UxPlay@3dbf7cee:lib/raop_rtp.c:203-233`).
//! - **A resent audio packet**, from the client, carrying the audio packet at
//!   offset four (`raop_rtp.c:...`, the `type_c == 0x56` branch).
//! - **A sync packet**, which says where the stream is in RTP time and in the
//!   client's clock (`raop_rtp.c:...`, the `type_c == 0x54` branch):
//!
//!   ```text
//!   packet[0]      0x80, or 0x90 for the first one
//!   packet[1]      0xd4, whose type is 0x54
//!   packet[2:3]    0x00 0x04
//!   packet[4:7]    sync_rtp, big endian
//!   packet[8:15]   the client's NTP timestamp, big endian
//!   packet[16:19]  next_rtp, big endian
//!   ```
//!
//! The type of a control packet is `packet[1] & !0x80`, which is why the bytes
//! above look like 0xd5 and 0xd4 rather than 0x55 and 0x54.

/// The first byte of every packet this receiver sends on the control channel
/// (`raop_rtp.c:219`).
const CONTROL_MARKER: u8 = 0x80;

/// Type of a resend request, before the marker bit is added
/// (`raop_rtp.c:220`).
const TYPE_RESEND_REQUEST: u8 = 0x55;

/// Type of a resent audio packet (`raop_rtp.c`, the `0x56` branch).
const TYPE_RESENT_AUDIO: u8 = 0x56;

/// Type of a sync packet (`raop_rtp.c`, the `0x54` branch).
const TYPE_SYNC: u8 = 0x54;

/// Where a resent audio packet carries the audio packet itself
/// (`raop_rtp.c`, `resent_packet = &packet[4]`).
const RESENT_OFFSET: usize = 4;

/// A control packet this receiver understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlPacket<'a> {
    /// An audio packet the client sent again after a resend request.
    ResentAudio {
        /// Sequence number of the audio packet.
        sequence: u16,
        /// The audio packet itself, header included.
        packet: &'a [u8],
    },
    /// Where the stream stands, in RTP time and in the client's clock.
    Sync {
        /// Whether the client marked this as the first sync of the stream.
        first: bool,
        /// RTP timestamp the stream is at.
        sync_rtp: u32,
        /// The client's NTP timestamp at that point.
        remote_ntp: u64,
        /// RTP timestamp the client will send next.
        next_rtp: u32,
    },
    /// A packet this receiver has no use for, reported with its type so a caller
    /// can log it without guessing.
    Other {
        /// Type from `packet[1] & !0x80`.
        kind: u8,
    },
}

/// Why a control packet could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlError {
    /// Shorter than the two bytes every control packet has.
    TooShort,
    /// A packet whose type promises more bytes than it carries.
    Truncated {
        /// Type the packet claimed.
        kind: u8,
        /// Length it would need.
        needed: usize,
        /// Length it had.
        length: usize,
    },
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(formatter, "the control packet is too short to have a type"),
            Self::Truncated {
                kind,
                needed,
                length,
            } => write!(
                formatter,
                "control packet of type {kind:#04x} needs {needed} bytes but has {length}"
            ),
        }
    }
}

impl std::error::Error for ControlError {}

/// Reads one control packet.
///
/// Upstream reads `packet[1]` without looking at the length first; this crate
/// refuses what it cannot read instead of reading past the datagram.
///
/// # Errors
///
/// Returns [`ControlError`] for a datagram too short to hold a type, or one whose
/// type promises more bytes than it carries.
pub fn parse_control_packet(datagram: &[u8]) -> Result<ControlPacket<'_>, ControlError> {
    let Some(&second) = datagram.get(1) else {
        return Err(ControlError::TooShort);
    };
    let kind = second & !CONTROL_MARKER;
    match kind {
        TYPE_RESENT_AUDIO => {
            if datagram.len() < 8 {
                return Err(ControlError::Truncated {
                    kind,
                    needed: 8,
                    length: datagram.len(),
                });
            }
            let packet = &datagram[RESENT_OFFSET..];
            let Some(sequence) = packet.get(2..4).and_then(read_u16) else {
                return Err(ControlError::Truncated {
                    kind,
                    needed: RESENT_OFFSET + 4,
                    length: datagram.len(),
                });
            };
            Ok(ControlPacket::ResentAudio { sequence, packet })
        }
        TYPE_SYNC => {
            if datagram.len() < 20 {
                return Err(ControlError::Truncated {
                    kind,
                    needed: 20,
                    length: datagram.len(),
                });
            }
            Ok(ControlPacket::Sync {
                first: datagram[0] & 0x10 != 0,
                sync_rtp: read_u32(&datagram[4..8]).unwrap_or_default(),
                remote_ntp: read_u64(&datagram[8..16]).unwrap_or_default(),
                next_rtp: read_u32(&datagram[16..20]).unwrap_or_default(),
            })
        }
        kind => Ok(ControlPacket::Other { kind }),
    }
}

/// Builds the request that asks a client to send audio again
/// (`upstream/UxPlay@3dbf7cee:lib/raop_rtp.c:203-233`).
///
/// `control_sequence` counts the requests this receiver has sent, `sequence` is
/// the first audio packet wanted and `count` how many of them, so a client can
/// answer with one request's worth of audio.
pub fn resend_request(control_sequence: u16, sequence: u16, count: u16) -> [u8; 8] {
    let mut request = [0u8; 8];
    request[0] = CONTROL_MARKER;
    request[1] = TYPE_RESEND_REQUEST | CONTROL_MARKER;
    request[2..4].copy_from_slice(&control_sequence.to_be_bytes());
    request[4..6].copy_from_slice(&sequence.to_be_bytes());
    request[6..8].copy_from_slice(&count.to_be_bytes());
    request
}

fn read_u16(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.try_into().ok()?))
}

fn read_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

fn read_u64(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(bytes.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A resent audio packet with `audio` at offset four, as upstream reads it.
    fn resent(sequence: u16, audio: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x80, TYPE_RESENT_AUDIO | CONTROL_MARKER, 0x00, 0x00];
        bytes.extend_from_slice(audio);
        // The copy inside carries the sequence at its own offset two.
        if bytes.len() >= 8 {
            bytes[RESENT_OFFSET + 2..RESENT_OFFSET + 4].copy_from_slice(&sequence.to_be_bytes());
        }
        bytes
    }

    #[test]
    fn reads_a_resent_audio_packet() {
        let audio = vec![0x80, 0x60, 0x00, 0x2a, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4];
        let packet = resent(42, &audio);
        let parsed = parse_control_packet(&packet).expect("control packet");
        match parsed {
            ControlPacket::ResentAudio { sequence, packet } => {
                assert_eq!(sequence, 42);
                assert_eq!(packet, &audio[..], "the audio packet starts at offset four");
            }
            other => panic!("expected resent audio, got {other:?}"),
        }
    }

    #[test]
    fn reads_a_sync_packet() {
        let mut packet = vec![0x90, TYPE_SYNC | CONTROL_MARKER, 0x00, 0x04];
        packet.extend_from_slice(&0x0000_1234u32.to_be_bytes());
        packet.extend_from_slice(&0x1122_3344_5566_7788u64.to_be_bytes());
        packet.extend_from_slice(&0x0000_abcd_u32.to_be_bytes());
        let parsed = parse_control_packet(&packet).expect("sync");
        assert_eq!(
            parsed,
            ControlPacket::Sync {
                first: true,
                sync_rtp: 0x1234,
                remote_ntp: 0x1122_3344_5566_7788,
                next_rtp: 0xabcd,
            }
        );
        // The same packet with the first-sync bit clear.
        packet[0] = 0x80;
        match parse_control_packet(&packet).expect("sync") {
            ControlPacket::Sync { first, .. } => assert!(!first),
            other => panic!("expected sync, got {other:?}"),
        }
    }

    #[test]
    fn refuses_what_it_cannot_read() {
        assert_eq!(parse_control_packet(&[]), Err(ControlError::TooShort));
        assert_eq!(parse_control_packet(&[0x80]), Err(ControlError::TooShort));
        assert_eq!(
            parse_control_packet(&[0x80, TYPE_RESENT_AUDIO | CONTROL_MARKER, 0, 0]),
            Err(ControlError::Truncated {
                kind: TYPE_RESENT_AUDIO,
                needed: 8,
                length: 4
            })
        );
        assert!(matches!(
            parse_control_packet(&[0x80, TYPE_SYNC | CONTROL_MARKER, 0, 4]),
            Err(ControlError::Truncated {
                kind: TYPE_SYNC,
                needed: 20,
                ..
            })
        ));
        // A type this receiver does not use is reported, not refused.
        assert_eq!(
            parse_control_packet(&[0x80, 0x82, 0, 0]).expect("other"),
            ControlPacket::Other { kind: 0x02 }
        );
    }

    #[test]
    fn builds_the_resend_request_upstream_builds() {
        let request = resend_request(7, 0x1234, 3);
        assert_eq!(&request[..2], &[0x80, 0xd5], "marker and type");
        assert_eq!(&request[2..4], &7u16.to_be_bytes(), "control sequence");
        assert_eq!(&request[4..6], &0x1234u16.to_be_bytes(), "first wanted");
        assert_eq!(&request[6..8], &3u16.to_be_bytes(), "how many");
        assert_eq!(request.len(), 8, "upstream sends exactly eight bytes");
    }
}
