// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded RTP packet parsing for AirPlay audio.
//!
//! One audio frame arrives as one RTP packet `[12-byte header][payload]`; the payload is the
//! coded frame and the header's `sequence` and `timestamp` are what a receiver needs to order
//! and pace it. Only the features an AirPlay client uses are implemented: version 2, an
//! optional CSRC list, an optional extension and optional padding all parse, while anything
//! outside the bounds here is refused rather than guessed at.
//!
//! # Examples
//!
//! ```
//! use rust_airplay::rtp;
//!
//! // A twelve-byte header: version 2, payload type 96, sequence 1, timestamp 480.
//! let packet = [
//!     0x80, 96, 0x00, 0x01, 0x00, 0x00, 0x01, 0xe0, 0, 0, 0, 0, 1, 2, 3, 4,
//! ];
//! let parsed = rtp::parse(&packet).expect("an audio packet");
//! assert_eq!(parsed.version, 2);
//! assert_eq!(parsed.sequence, 1);
//! assert_eq!(parsed.timestamp, 480);
//! assert_eq!(parsed.payload, [1, 2, 3, 4]);
//! ```

use crate::wire::ParseError;

/// One parsed RTP packet, borrowing its payload from the datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket<'a> {
    /// RTP version, always 2 for a packet this parser accepts.
    pub version: u8,
    /// Marker bit, which an audio stream sets on the first packet after a silence.
    pub marker: bool,
    /// Payload type, which AirPlay uses to distinguish media from retransmission requests.
    pub payload_type: u8,
    /// Sequence number, one more than the previous packet of the stream modulo 2^16.
    pub sequence: u16,
    /// The client's RTP timestamp: for audio it counts samples at the stream's rate.
    pub timestamp: u32,
    /// Synchronisation source of the stream.
    pub ssrc: u32,
    /// The coded frame, with the header, CSRC list, extension and padding removed.
    pub payload: &'a [u8],
}

/// Parses one RTP packet.
///
/// # Errors
///
/// Returns [`ParseError::Incomplete`] when the datagram is shorter than its own header
/// describes, and [`ParseError::Invalid`] for a version other than 2, an extension or padding
/// length that does not fit the datagram, or padding that would remove the whole payload.
pub fn parse(packet: &[u8]) -> Result<RtpPacket<'_>, ParseError> {
    if packet.len() < 12 {
        return Err(ParseError::Incomplete);
    }
    let first = packet[0];
    if first >> 6 != 2 {
        return Err(ParseError::Invalid("RTP version"));
    }
    let csrc_count = (first & 0x0f) as usize;
    let mut offset = 12usize
        .checked_add(
            csrc_count
                .checked_mul(4)
                .ok_or(ParseError::Invalid("CSRC count"))?,
        )
        .ok_or(ParseError::Invalid("RTP header"))?;
    if packet.len() < offset {
        return Err(ParseError::Incomplete);
    }
    if first & 0x10 != 0 {
        if packet.len() - offset < 4 {
            return Err(ParseError::Incomplete);
        }
        let words = u16::from_be_bytes(
            packet[offset + 2..offset + 4]
                .try_into()
                .map_err(|_| ParseError::Invalid("extension length"))?,
        ) as usize;
        offset = offset
            .checked_add(
                4usize
                    .checked_add(
                        words
                            .checked_mul(4)
                            .ok_or(ParseError::Invalid("extension length"))?,
                    )
                    .ok_or(ParseError::Invalid("extension size"))?,
            )
            .ok_or(ParseError::Invalid("extension size"))?;
        if packet.len() < offset {
            return Err(ParseError::Incomplete);
        }
    }
    let end = if first & 0x20 != 0 {
        let padding = *packet.last().ok_or(ParseError::Incomplete)? as usize;
        if padding == 0 || padding > packet.len() - offset {
            return Err(ParseError::Invalid("RTP padding"));
        }
        packet.len() - padding
    } else {
        packet.len()
    };
    if end < offset {
        return Err(ParseError::Invalid("RTP payload"));
    }
    Ok(RtpPacket {
        version: 2,
        marker: packet[1] & 0x80 != 0,
        payload_type: packet[1] & 0x7f,
        sequence: u16::from_be_bytes(
            packet[2..4]
                .try_into()
                .map_err(|_| ParseError::Invalid("sequence"))?,
        ),
        timestamp: u32::from_be_bytes(
            packet[4..8]
                .try_into()
                .map_err(|_| ParseError::Invalid("timestamp"))?,
        ),
        ssrc: u32::from_be_bytes(
            packet[8..12]
                .try_into()
                .map_err(|_| ParseError::Invalid("SSRC"))?,
        ),
        payload: &packet[offset..end],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_rtp_header() {
        let packet = [0x80, 0xe0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 2, 1, 2, 3];
        let parsed = parse(&packet).unwrap();
        assert_eq!((parsed.sequence, parsed.timestamp, parsed.ssrc), (9, 1, 2));
        assert!(parsed.marker);
        assert_eq!(parsed.payload, &[1, 2, 3]);
    }
    #[test]
    fn validates_version_and_padding() {
        assert_eq!(parse(&[0x40; 12]), Err(ParseError::Invalid("RTP version")));
        assert_eq!(
            parse(&[0xa0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(ParseError::Invalid("RTP padding"))
        );
    }
}
