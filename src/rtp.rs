// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(missing_docs)]
// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded RTP packet parsing for AirPlay audio.

use crate::wire::ParseError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket<'a> {
    pub version: u8,
    pub marker: bool,
    pub payload_type: u8,
    pub sequence: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub payload: &'a [u8],
}

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
