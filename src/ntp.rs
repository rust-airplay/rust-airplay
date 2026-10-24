// SPDX-License-Identifier: GPL-3.0-or-later
//! NTP wire timestamps, and their conversion to and from Unix nanoseconds.
//!
//! AirPlay's timing exchange and every media timestamp use the 64-bit NTP format: 32 bits of
//! seconds since 1900-01-01 and 32 bits of binary fraction. It is not a `SystemTime`, and the
//! two are not interchangeable: the wire format counts from 1900, wraps every 2^32 seconds and
//! carries a 1/2^32-second fraction, while the crate's internal time is Unix nanoseconds.
//!
//! The conversion is exact in both directions: the fraction is scaled with integer arithmetic,
//! so a timestamp survives a round trip to within the precision the wire format can carry.

use crate::wire::ParseError;

/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
pub const NTP_UNIX_EPOCH_SECONDS: u64 = 2_208_988_800;
/// Nanoseconds in one second, the unit the rest of the crate counts time in.
pub const NANOS_PER_SECOND: u64 = 1_000_000_000;
/// Length of one NTP era in seconds. Era 0 covers 1900-01-01 through
/// 2036-02-07; the 32-bit wire field cannot express a later instant.
pub const NTP_ERA_SECONDS: u64 = 1 << 32;

/// Converts an 8-byte era-0 NTP timestamp into Unix nanoseconds.
///
/// Returns [`ParseError::Incomplete`] for fewer than eight bytes and
/// [`ParseError::Invalid`] for a timestamp before the Unix epoch or one whose
/// nanoseconds do not fit in `u64`.
pub fn timestamp_to_unix_nanos(bytes: &[u8]) -> Result<u64, ParseError> {
    if bytes.len() < 8 {
        return Err(ParseError::Incomplete);
    }
    let seconds = u32::from_be_bytes(
        bytes[..4]
            .try_into()
            .map_err(|_| ParseError::Invalid("NTP seconds"))?,
    ) as u64;
    let fraction = u32::from_be_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| ParseError::Invalid("NTP fraction"))?,
    ) as u64;
    if seconds < NTP_UNIX_EPOCH_SECONDS {
        return Err(ParseError::Invalid("NTP timestamp before Unix epoch"));
    }
    let unix_seconds = seconds - NTP_UNIX_EPOCH_SECONDS;
    let whole = unix_seconds
        .checked_mul(NANOS_PER_SECOND)
        .ok_or(ParseError::Invalid("NTP timestamp overflow"))?;
    // The fraction counts 2^32 seconds of a second, so scale it exactly without
    // a floating point step; `fraction < 2^32` and `NANOS_PER_SECOND < 2^30`
    // keep the product below `u64::MAX`.
    let fraction_nanos = (fraction * NANOS_PER_SECOND) >> 32;
    whole
        .checked_add(fraction_nanos)
        .ok_or(ParseError::Invalid("NTP timestamp overflow"))
}

/// Encodes Unix nanoseconds as an era-0 NTP timestamp.
///
/// Returns [`ParseError::Invalid`] once the instant reaches the 2036-02-07 era
/// boundary (Unix second 2_085_978_496) because the 32-bit wire field cannot
/// hold it without wrapping; callers that need a later era must translate to it
/// explicitly instead of relying on silent truncation.
pub fn unix_nanos_to_timestamp(nanos: u64) -> Result<[u8; 8], ParseError> {
    let seconds = nanos / NANOS_PER_SECOND + NTP_UNIX_EPOCH_SECONDS;
    if seconds >= NTP_ERA_SECONDS {
        return Err(ParseError::Invalid("NTP timestamp outside era 0"));
    }
    let fraction = ((nanos % NANOS_PER_SECOND) << 32) / NANOS_PER_SECOND;
    let mut output = [0; 8];
    output[..4].copy_from_slice(&(seconds as u32).to_be_bytes());
    output[4..].copy_from_slice(&(fraction as u32).to_be_bytes());
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trips_ntp_epoch_conversion() {
        let timestamp = unix_nanos_to_timestamp(1_700_000_000_123_456_789).unwrap();
        let decoded = timestamp_to_unix_nanos(&timestamp).unwrap();
        assert!((decoded as i128 - 1_700_000_000_123_456_789i128).abs() < 2);
    }
    #[test]
    fn accepts_the_last_era_zero_second_and_rejects_the_era_boundary() {
        let last_second = NTP_ERA_SECONDS - NTP_UNIX_EPOCH_SECONDS - 1;
        let last_nanos = last_second * NANOS_PER_SECOND;
        let timestamp = unix_nanos_to_timestamp(last_nanos).unwrap();
        assert_eq!(timestamp_to_unix_nanos(&timestamp).unwrap(), last_nanos);
        // 2036-02-07T06:28:16Z is one second past the last representable value.
        assert_eq!(
            unix_nanos_to_timestamp(last_nanos + NANOS_PER_SECOND),
            Err(ParseError::Invalid("NTP timestamp outside era 0"))
        );
        assert_eq!(
            unix_nanos_to_timestamp(u64::MAX),
            Err(ParseError::Invalid("NTP timestamp outside era 0"))
        );
    }
    #[test]
    fn rejects_short_and_pre_epoch_values() {
        assert_eq!(
            timestamp_to_unix_nanos(&[0; 7]),
            Err(ParseError::Incomplete)
        );
        assert_eq!(
            timestamp_to_unix_nanos(&[0; 8]),
            Err(ParseError::Invalid("NTP timestamp before Unix epoch"))
        );
    }
}
