// SPDX-License-Identifier: GPL-3.0-or-later
//! Rewriting a mirror payload's length prefixes into Annex-B start codes.

/// The Annex-B start code that replaces a length prefix
pub const START_CODE: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// Why a decrypted payload is not a sequence of NAL units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NalError {
    /// A length prefix claims bytes the payload does not have.
    LengthOutOfRange {
        /// Offset the prefix was read at.
        offset: usize,
        /// Length it claimed.
        claimed: usize,
        /// Bytes actually left after the prefix.
        available: usize,
    },
    /// The first byte of a unit has the bit set that has to be zero.
    ForbiddenBit {
        /// Offset of the unit's first byte.
        offset: usize,
    },
}

impl std::fmt::Display for NalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LengthOutOfRange {
                offset,
                claimed,
                available,
            } => write!(
                formatter,
                "the unit at {offset} claims {claimed} bytes but {available} are left"
            ),
            Self::ForbiddenBit { offset } => {
                write!(formatter, "the unit at {offset} has its forbidden bit set")
            }
        }
    }
}

impl std::error::Error for NalError {}

/// Rewrites the length prefixes of a decrypted mirror payload into Annex-B start
/// codes, in place, and reports how many units it holds.
///
/// The AirPlay mirror protocol prefixes every NAL unit with its length, which a
/// decoder does not expect; the protocol replaces each prefix with `00 00 00 01`
/// while it checks the unit
/// Doing the same
/// here means a caller hands the payload to a decoder unchanged after this.
///
/// The checks are the protocol's, and they matter: a length read out of the payload
/// is only a length if the unit it claims fits in what is left, and a unit whose
/// first byte has the forbidden bit set is not a unit at all. A payload that
/// fails either check is reported instead of being passed on, because a decoder
/// fed a wrong byte stream does not fail cleanly.
///
/// # Errors
///
/// Returns [`NalError`] for a payload that is not a sequence of units.
pub fn into_annex_b(payload: &mut [u8]) -> Result<usize, NalError> {
    let mut offset = 0;
    let mut units = 0;
    while offset < payload.len() {
        if offset + 4 > payload.len() {
            return Err(NalError::LengthOutOfRange {
                offset,
                claimed: 0,
                available: payload.len() - offset,
            });
        }
        let claimed =
            u32::from_be_bytes(payload[offset..offset + 4].try_into().expect("four")) as usize;
        let available = payload.len() - offset - 4;
        if claimed > available {
            return Err(NalError::LengthOutOfRange {
                offset,
                claimed,
                available,
            });
        }
        payload[offset..offset + 4].copy_from_slice(&START_CODE);
        offset += 4;
        units += 1;
        // The first bit of an H.264 unit has to be zero. The protocol reads the byte
        // even for a unit of length zero, so this does too.
        let first = payload.get(offset).copied().unwrap_or_default();
        if first & 0x80 != 0 {
            return Err(NalError::ForbiddenBit { offset });
        }
        offset += claimed;
    }
    Ok(units)
}
