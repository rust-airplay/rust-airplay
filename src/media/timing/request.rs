// SPDX-License-Identifier: GPL-3.0-or-later
//! The timing request and response packets.

use crate::ntp;

/// Length of a timing request, which the protocol sends in full.
pub const TIMING_REQUEST_LEN: usize = 32;

/// The first two bytes of a request.
const REQUEST_HEADER: [u8; 4] = [0x80, 0xd2, 0x00, 0x07];

/// Where a request carries the time it was sent.
const REQUEST_TRANSMIT_OFFSET: usize = 24;

/// Type of a timing response, which is a request whose type bit changed
///.
pub const RESPONSE_TYPE: u8 = 0x53;

/// Where a response carries the three values the protocol reads
const RESPONSE_T1_OFFSET: usize = 8;
const RESPONSE_T2_OFFSET: usize = 16;
const RESPONSE_T3_OFFSET: usize = 24;

/// Shortest response this module can read.
pub const RESPONSE_MIN_LEN: usize = RESPONSE_T3_OFFSET + 4;

/// Builds the timing request a receiver sends to a client's timing port.
///
/// `send_time` is the local time in the nanosecond form [`crate::ntp`] works
/// with; it is written where the protocol writes it, so a response can be matched to
/// the request that caused it.
///
/// # Errors
///
/// Returns the error of [`ntp::unix_nanos_to_timestamp`] when the time cannot be
/// represented in the NTP era this crate uses.
pub fn build_request(send_time: u64) -> Result<[u8; TIMING_REQUEST_LEN], crate::wire::ParseError> {
    let mut request = [0u8; TIMING_REQUEST_LEN];
    request[..REQUEST_HEADER.len()].copy_from_slice(&REQUEST_HEADER);
    let timestamp = ntp::unix_nanos_to_timestamp(send_time)?;
    request[REQUEST_TRANSMIT_OFFSET..REQUEST_TRANSMIT_OFFSET + 8].copy_from_slice(&timestamp);
    Ok(request)
}

/// The values a timing response carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimingResponse {
    /// 32 bits at offset eight, the value the protocol keeps as `t1`.
    pub t1: u32,
    /// 32 bits at offset sixteen, the client's receive time.
    pub t2: u32,
    /// 32 bits at offset twenty-four, the client's transmit time.
    pub t3: u32,
}

/// Why a datagram could not be read as a timing response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingError {
    /// Shorter than the values it has to carry.
    TooShort,
    /// Not an answer to a timing request.
    NotAResponse {
        /// Type the datagram carried, from `packet[1] & !0x80`.
        kind: u8,
    },
}

impl std::fmt::Display for TimingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(formatter, "the timing response is too short"),
            Self::NotAResponse { kind } => {
                write!(formatter, "type {kind:#04x} is not a timing response")
            }
        }
    }
}

impl std::error::Error for TimingError {}

/// Reads a timing response.
///
/// # Errors
///
/// Returns [`TimingError`] for a datagram too short to carry the values, or one
/// whose type is not [`RESPONSE_TYPE`].
pub fn parse_response(datagram: &[u8]) -> Result<TimingResponse, TimingError> {
    let Some(&second) = datagram.get(1) else {
        return Err(TimingError::TooShort);
    };
    if second & !0x80 != RESPONSE_TYPE {
        return Err(TimingError::NotAResponse {
            kind: second & !0x80,
        });
    }
    if datagram.len() < RESPONSE_MIN_LEN {
        return Err(TimingError::TooShort);
    }
    Ok(TimingResponse {
        t1: read_u32(&datagram[RESPONSE_T1_OFFSET..]),
        t2: read_u32(&datagram[RESPONSE_T2_OFFSET..]),
        t3: read_u32(&datagram[RESPONSE_T3_OFFSET..]),
    })
}

fn read_u32(bytes: &[u8]) -> u32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(&bytes[..4]);
    u32::from_be_bytes(value)
}
