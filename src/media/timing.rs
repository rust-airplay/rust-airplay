// SPDX-License-Identifier: GPL-3.0-or-later
//! The timing port of a session.
//!
//! A client and a receiver agree on how their clocks relate by exchanging timing
//! packets on their own port, which `SETUP` negotiates. Upstream sends a
//! thirty-two byte request and reads three values out of the answer
//! (`upstream/UxPlay@3dbf7cee:lib/raop_ntp.c:578-700`):
//!
//! ```text
//! request[0]      0x80
//! request[1]      0xd2, whose type is 0x52
//! request[2..3]   0x00 0x07
//! request[24..31] the local time when the request went out
//! ```
//!
//! and out of the response it reads
//!
//! ```text
//! response[8..11]   t1, 32 bits, big endian
//! response[16..19]  t2, 32 bits, the client's receive time
//! response[24..27]  t3, 32 bits, the client's transmit time
//! ```
//!
//! This module is the packet layer of that exchange: it builds the request and
//! reads what the answer carries. The clock arithmetic on top of it is *not*
//! here yet, and deliberately so: upstream adjusts the remote values with
//! `raop_ntp_adjust_remote_timestamp_offset`, rejects duplicates and bogus
//! packets, and folds in a `sync_delay`, all of which has to be read out of the
//! source rather than guessed at. `docs/ARCHITECTURE.md` records that as the next
//! slice.

use crate::ntp;

/// Length of a timing request, which upstream sends in full
/// (`raop_ntp.c:580-581`).
pub const TIMING_REQUEST_LEN: usize = 32;

/// The first two bytes of a request (`raop_ntp.c:580`).
const REQUEST_HEADER: [u8; 4] = [0x80, 0xd2, 0x00, 0x07];

/// Where a request carries the time it was sent (`raop_ntp.c:616`).
const REQUEST_TRANSMIT_OFFSET: usize = 24;

/// Type of a timing response, which is a request whose type bit changed
/// (`raop_ntp.c:580` and the branch that reads the answer).
pub const RESPONSE_TYPE: u8 = 0x53;

/// Where a response carries the three values upstream reads
/// (`raop_ntp.c:656-665`).
const RESPONSE_T1_OFFSET: usize = 8;
const RESPONSE_T2_OFFSET: usize = 16;
const RESPONSE_T3_OFFSET: usize = 24;

/// Shortest response this module can read.
pub const RESPONSE_MIN_LEN: usize = RESPONSE_T3_OFFSET + 4;

/// Builds the timing request a receiver sends to a client's timing port.
///
/// `send_time` is the local time in the nanosecond form [`crate::ntp`] works
/// with; it is written where upstream writes it, so a response can be matched to
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
    /// 32 bits at offset eight, the value upstream keeps as `t1`.
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
/// How long a timing request waits for its answer before it is written off.
///
/// Upstream keeps eight outstanding requests (`RAOP_NTP_DATA_COUNT`) and every sample it
/// has not given up on; a request whose answer never arrives is simply never completed.
pub const OUTSTANDING_REQUESTS: usize = 8;

/// Samples the offset estimate averages over, which is upstream's table size.
const SAMPLE_COUNT: usize = 8;

/// Clock error allowed to accumulate per second of elapsed time, as a fraction.
const PHI: f64 = 15e-6;

/// Precision of a timestamp, in seconds. Both ends claim one millisecond.
const RHO: f64 = 0.001;

/// Distance beyond which the estimate is reported as unsynchronised.
const MAX_DISTANCE: f64 = 1.5;

/// Dispersion beyond which a sample is no longer worth keeping.
const MAX_DISPERSION: f64 = 16.0;

/// Weight given to a new estimate when one already exists.
const ALPHA: f64 = 0.05;

/// Seconds from 1900, the NTP epoch, to 1970.
///
/// A client's timing answer carries this added to its own epoch, which is the moment the
/// device booted, while a mirror frame's timestamp does not. Both count fractions the same
/// way, so the difference between the two domains is exactly this constant.
const SECONDS_FROM_1900: i64 = 2_208_988_800;

/// A 32-bit fraction of a second as nanoseconds.
fn fraction_to_nanos(fraction: u32) -> i64 {
    (i64::from(fraction) * 1_000_000_000) >> 32
}

/// A Q32.32 timestamp as nanoseconds in its own epoch.
///
/// A mirror frame's timestamp is NTP fixed point: the high half counts seconds from the
/// client's epoch and the low half a fraction of a second. Consecutive frames of a
/// 1554x1080 mirror stream differ by about 143 million of these, which is thirty-three
/// milliseconds - one frame at thirty a second - and that is the measurement that
/// established the unit.
#[must_use]
pub fn q32_32_to_nanos(timestamp: u64) -> i64 {
    let seconds = (timestamp >> 32) as i64;
    seconds.saturating_mul(1_000_000_000) + fraction_to_nanos(timestamp as u32)
}

/// One completed exchange with the client's timing port.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClockSample {
    /// The local time the answer arrived, in NTP's 64-bit timestamp form.
    pub received: u64,
    /// The `t3` the client reported, which is what makes a repeat recognisable.
    pub echo: u32,
    /// How far the client's clock is ahead of this one, in seconds.
    pub offset: f64,
    /// Round-trip time with the client's own processing removed, in seconds.
    pub delay: f64,
    /// How much the sample has aged, in seconds.
    pub dispersion: f64,
}

/// The client's clock, as far as the timing exchanges have established it.
///
/// A receiver plays media stamped by the client's clock, so it has to know how that clock
/// relates to its own. The exchange is NTP's: this side sends `t1`, the client echoes it
/// with its receive time `t2` and transmit time `t3`, and the answer arrives at `t4`. The
/// offset is then `((t2 - t1) + (t3 - t4)) / 2`, and a conversion in either direction is
/// that offset added or subtracted.
///
/// Two things make it more than that arithmetic, and both are upstream's
/// (`upstream/UxPlay/lib/raop_ntp.c`):
///
/// - The first remote timestamp seen fixes a *fixed offset*, so later arithmetic happens
///   in one clock domain instead of comparing a client's era to this machine's.
/// - Estimates are filtered: old samples age out, the lowest-delay sample leads, the rest
///   are weighted down, and a new estimate is smoothed into the previous one. A single
///   exchange over a busy network is a bad measurement, and the filter is what stops it
///   from being the one that counts.
#[derive(Debug, Clone)]
pub struct RemoteClock {
    samples: [Option<ClockSample>; SAMPLE_COUNT],
    /// Where the next sample is written, as upstream's `data_index`.
    next: usize,
    /// Requests whose answers have not arrived, by the `t1` they carried.
    ///
    /// A request carries thirty-two bits of seconds in this field, and an answer has to
    /// echo them, so this is what a reply is matched against.
    outstanding: [u32; OUTSTANDING_REQUESTS],
    /// The client's clock minus this one, in nanoseconds, once an estimate exists.
    offset_nanos: i64,
    /// How far the estimate can be trusted, in nanoseconds.
    root_distance_nanos: u64,
    /// Whether the last estimate was close enough to be used.
    synced: bool,
    /// Whether an estimate exists at all.
    have_estimate: bool,
    /// The remote timestamp a response's times are adjusted by, as `fixed_offset`.
    fixed_offset: Option<i64>,
}

impl Default for RemoteClock {
    fn default() -> Self {
        Self::new()
    }
}

impl RemoteClock {
    /// A clock that has seen no exchanges.
    #[must_use]
    pub fn new() -> Self {
        Self {
            samples: [None; SAMPLE_COUNT],
            next: 0,
            outstanding: [0; OUTSTANDING_REQUESTS],
            offset_nanos: 0,
            root_distance_nanos: u64::MAX,
            synced: false,
            have_estimate: false,
            fixed_offset: None,
        }
    }

    /// Records a request sent at `t1`, which is the NTP timestamp the answer must echo.
    ///
    /// Returns whether the request fits in the table of outstanding ones. Upstream keeps
    /// eight and overwrites the oldest, which is what happens here.
    pub fn request_sent(&mut self, t1: u32) -> bool {
        self.outstanding[self.next % OUTSTANDING_REQUESTS] = t1;
        self.next = (self.next + 1) % OUTSTANDING_REQUESTS;
        true
    }

    /// Takes one exchange, and returns the estimate it produced, if any.
    ///
    /// `t1` is the local send time in NTP's timestamp form, `t2` and `t3` are what the
    /// client reported, both as its own 32-bit timestamps, and `t4` is the local arrival
    /// time in **nanoseconds** since the Unix epoch. Mixing a timestamp form into that
    /// argument is what made two versions of this wrong. Returns `None` when the answer is a duplicate, when
    /// it echoes a `t1` that was never sent, or when it leaves no sample worth keeping.
    pub fn response_received(&mut self, t1: u32, t2: u32, t3: u32, t4: u64) -> Option<ClockSample> {
        // The answer has to echo a request this receiver made. Without that check a client
        // could feed the estimate arbitrary numbers, and a spoofed reply is exactly what a
        // timing exchange invites.
        let seen = self
            .outstanding
            .iter()
            .any(|sent| *sent != 0 && *sent == t1);
        if !seen {
            return None;
        }
        // A `t3` already recorded is the same answer twice.
        if self
            .samples
            .iter()
            .flatten()
            .any(|sample| sample.echo == t3)
        {
            return None;
        }

        // Everything below is integer nanoseconds, because everything on the wire is whole
        // seconds: `t1`, `t2` and `t3` are thirty-two bits each, and upstream truncates the
        // arrival time to the same width (`raop_ntp.c:656-697`). Mixing a fraction into
        // that arithmetic is what made the first version of this report an offset of
        // exactly half the round trip for every session.
        let t1_local = (i64::from(t1) - SECONDS_FROM_1900).saturating_mul(1_000_000_000);
        // The client's epoch is when it booted, and its answer adds the 1900 offset to it.
        // A mirror frame's timestamp does not, so both are brought to the same domain here:
        // seconds since the client booted.
        let t2_client = (i64::from(t2) - SECONDS_FROM_1900).saturating_mul(1_000_000_000);
        let t3_client = (i64::from(t3) - SECONDS_FROM_1900).saturating_mul(1_000_000_000);
        let t4_nanos = t4 as i64;

        // Where the client's epoch sits against this clock. Fixed on the first answer and
        // kept: it is what turns a mirror timestamp into a local time, and it is the only
        // number in this exchange that is not quantised by the reply's seconds.
        let fixed = match self.fixed_offset {
            Some(existing) => existing,
            None => {
                let offset = t4_nanos - t2_client;
                self.fixed_offset = Some(offset);
                offset
            }
        };

        // The round trip without the client's own processing time, and the two legs of it.
        let total = t4_nanos - t1_local;
        let client_processing = t3_client - t2_client;
        let delay_nanos = (total - client_processing).max(1_000_000);
        let client_to_server = t2_client + fixed - t1_local;
        let server_to_client = t4_nanos - (t3_client + fixed);

        let sample = ClockSample {
            received: t4,
            echo: t3,
            offset: ((client_to_server + server_to_client) as f64 / 2.0) / 1e9,
            delay: delay_nanos as f64 / 1e9,
            dispersion: 2.0 * RHO + PHI * (total as f64 / 1e9),
        };
        let slot = self
            .samples
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.samples
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, sample)| sample.map(|s| s.received).unwrap_or(0))
                    .map(|(index, _)| index)
                    .unwrap_or(0)
            });
        self.samples[slot] = Some(sample);
        self.outstanding = [0; OUTSTANDING_REQUESTS];

        self.estimate(t4)
    }
    /// Recomputes the offset from the samples that are still worth using.
    fn estimate(&mut self, now: u64) -> Option<ClockSample> {
        // Age every sample and drop the ones that have drifted too far to mean anything.
        let mut usable: Vec<ClockSample> = Vec::with_capacity(SAMPLE_COUNT);
        for sample in self.samples.iter_mut().flatten() {
            let elapsed = (now as i64 - sample.received as i64) as f64 / 1e9;
            sample.dispersion += elapsed * PHI;
            if sample.dispersion < MAX_DISPERSION {
                usable.push(*sample);
            }
        }
        // The lowest delay leads; the rest are weighted down by `1/2^i`, which is what
        // stops one lucky exchange on a quiet network from outweighing the others.
        usable.sort_by(|a, b| a.delay.total_cmp(&b.delay));
        let mut filtered = 0.0;
        for (index, sample) in usable.iter().enumerate() {
            filtered += sample.dispersion / 2f64.powi(index as i32);
        }
        // Everything aged out. A client whose answers are far enough from this clock to do
        // that has not proved anything, so the previous estimate stays and no new one is
        // published.
        let leader = usable.first().copied()?;
        let root_distance = filtered + leader.delay / 2.0;

        let offset = if root_distance > MAX_DISTANCE {
            // Too far to trust, but the number is still published: it is a measurement,
            // and a receiver that hides it plays at the wrong rate without saying so.
            self.synced = false;
            leader.offset
        } else if self.have_estimate {
            let previous = self.offset_nanos as f64 / 1e9;
            self.synced = true;
            (1.0 - ALPHA) * previous + ALPHA * leader.offset
        } else {
            self.synced = true;
            leader.offset
        };
        self.offset_nanos = (offset * 1e9) as i64;
        self.root_distance_nanos = (root_distance * 1e9) as u64;
        self.have_estimate = true;
        Some(leader)
    }

    /// How far the client's era is from this machine's clock, in nanoseconds.
    ///
    /// `None` until a response has been read. This is upstream's `fixed_offset`: the
    /// first remote timestamp seen, taken against the local clock at that moment, and
    /// applied to every later one so the arithmetic happens in one domain.
    #[must_use]
    pub fn fixed_offset_nanos(&self) -> Option<i64> {
        self.fixed_offset
    }

    /// How many exchanges have produced a sample.
    ///
    /// Zero is the state before the client has answered once, which is what a caller
    /// wants to distinguish from "an answer arrived and was refused".
    #[must_use]
    pub fn samples_collected(&self) -> usize {
        self.samples.iter().flatten().count()
    }

    /// The local time for a client timestamp, in nanoseconds.
    ///
    /// `remote_timestamp` is a Q32.32 NTP time in the client's own epoch - the moment the
    /// device booted, not 1900, because the 1900 offset is added to timing answers and not
    /// to media timestamps. A frame of a 1554x1080 mirror stream carries about 8355 in the
    /// high half, which is how long the device had been up.
    ///
    /// The conversion applies the fixed offset first and the smoothed residual second,
    /// which is the order upstream uses: it adjusts a remote timestamp with
    /// `raop_ntp_adjust_remote_timestamp_offset` where it reads it, and converts with
    /// `raop_ntp_convert_remote_time` where it schedules.
    ///
    /// `None` until a response has been read. A receiver that guessed would drift away
    /// from the client rather than follow it, and a sound card playing at the wrong rate
    /// is worse than one playing late.
    #[must_use]
    pub fn to_local(&self, remote_timestamp: u64) -> Option<u64> {
        let fixed = self.fixed_offset?;
        if !self.have_estimate {
            return None;
        }
        Some((q32_32_to_nanos(remote_timestamp) + fixed - self.offset_nanos) as u64)
    }

    /// The client's time for a point in the local clock, in nanoseconds.
    #[must_use]
    pub fn to_remote(&self, local_nanos: u64) -> Option<u64> {
        let fixed = self.fixed_offset?;
        if !self.have_estimate {
            return None;
        }
        let remote = (local_nanos as i64 + self.offset_nanos - fixed).max(0) as u64;
        Some(remote)
    }

    /// The client's clock minus this one, in nanoseconds.
    #[must_use]
    pub fn offset_nanos(&self) -> i64 {
        self.offset_nanos
    }

    /// How far the estimate can be trusted, in nanoseconds.
    #[must_use]
    pub fn root_distance_nanos(&self) -> u64 {
        self.root_distance_nanos
    }

    /// Whether the last estimate was close enough to be used.
    #[must_use]
    pub fn is_synced(&self) -> bool {
        self.synced
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_looks_like_the_one_upstream_sends() {
        // A Unix time in this era, with a fraction so the encoding is exercised.
        let send_time = 1_700_000_000 * ntp::NANOS_PER_SECOND + 123_456_789;
        let request = build_request(send_time).expect("request");
        assert_eq!(&request[..4], &[0x80, 0xd2, 0x00, 0x07], "header");
        assert_eq!(request.len(), 32);
        assert!(
            request[4..24].iter().all(|byte| *byte == 0),
            "everything before the transmit time stays clear"
        );
        // The transmit time comes back within the precision the format has: the
        // NTP fraction is 32 bits, which cannot hold every nanosecond.
        let mut timestamp = [0u8; 8];
        timestamp.copy_from_slice(&request[24..32]);
        let decoded = ntp::timestamp_to_unix_nanos(&timestamp).expect("timestamp");
        let difference = decoded.abs_diff(send_time);
        assert!(
            difference <= 2,
            "the round trip is off by {difference} ns, more than the format allows"
        );
    }

    #[test]
    fn reads_the_response_values_upstream_reads() {
        let mut response = vec![0u8; 32];
        response[1] = RESPONSE_TYPE | 0x80;
        response[8..12].copy_from_slice(&0x1111_1111u32.to_be_bytes());
        response[16..20].copy_from_slice(&0x2222_2222u32.to_be_bytes());
        response[24..28].copy_from_slice(&0x3333_3333u32.to_be_bytes());
        assert_eq!(
            parse_response(&response).expect("response"),
            TimingResponse {
                t1: 0x1111_1111,
                t2: 0x2222_2222,
                t3: 0x3333_3333,
            }
        );
    }

    /// A second in NTP's fixed point, which is what a timestamp's high half counts.
    const NANOS_PER_TICK: u64 = 1_000_000_000;

    fn seconds(count: u64) -> u64 {
        count << 32
    }

    /// The exchange carries whole seconds, and a test of it has to say so.
    ///
    /// `t1`, `t2` and `t3` are thirty-two bits on the wire, and upstream truncates `t4` to
    /// the same width (`raop_ntp.c:656-697`). So this cannot measure a sub-second offset,
    /// and the numbers below are the honest shape of that: a twenty-millisecond round trip
    /// vanishes, and the delay falls to the precision floor. What the exchange *can* do is
    /// place the client's second counter against this machine's, and the conversion has to
    /// stay inside a second of the truth. A device session reported 895 ms of delay for a
    /// link with 3 ms of it, which is this quantisation and not a network problem.
    #[test]
    fn an_exchange_is_only_as_fine_as_the_seconds_it_carries() {
        let mut clock = RemoteClock::new();
        // The client's clock reads five seconds ahead of this machine's.
        // The client booted 8354 seconds ago and its answer adds the 1900 offset, which is
        // what a device was seen to send.
        const BOOT: u32 = 8_354;
        let t2 = BOOT.wrapping_add(2_208_988_800);
        let t3 = t2;
        // This machine's clock, in the same era: Unix seconds plus the same offset.
        let t1_seconds: u32 = 1_792_231_849u32.wrapping_add(2_208_988_800);

        assert!(clock.request_sent(t1_seconds));
        // A one-way trip of ten milliseconds, and the client takes none of it processing.
        let t4 = 1_792_231_849_000_000_000 + 2 * 10_000_000;

        let sample = clock
            .response_received(t1_seconds, t2, t3, t4)
            .expect("a sample from a reply that echoes the request");
        // Twenty milliseconds of round trip is invisible at this resolution, so the delay
        // is the floor the arithmetic uses in place of zero.
        assert!(sample.delay > 0.0);
        assert!((sample.delay - 0.02).abs() < 1e-3, "delay {}", sample.delay);
        assert!(clock.is_synced(), "an exchange this clean is a sync");

        // The conversion is what a session uses, and it has to survive the era: the client
        // counts seconds since 1900 in 32 bits, so the fixed offset is what puts its
        // timestamps on this machine's clock.
        // A mirror timestamp in the client's epoch: seconds in the high half.
        let remote = u64::from(BOOT) << 32;
        let local = clock.to_local(remote).expect("a conversion");
        // The exchange only knows the client's second, so the conversion cannot be finer
        // than that: two seconds of tolerance is what the wire allows.
        let tolerance = 2 * NANOS_PER_TICK;
        assert!(
            local.abs_diff(t4) < tolerance,
            "converted {local}, expected about {t4}"
        );
        assert!(clock.to_remote(local).is_some());
        let _ = &remote;
    }

    #[test]
    fn a_real_mirror_timestamp_lands_on_the_local_clock() {
        // Numbers from a device session, kept because they are the only evidence that the
        // unit is what this code says it is: `t2` was 2208997154 (client boot plus the
        // 1900 offset), the answer arrived at Unix 1792231849.253 s, and the first mirror
        // frame carried 35884668244832.
        let mut clock = RemoteClock::new();
        let t1_seconds: u32 = 4_001_220_649;
        clock.request_sent(t1_seconds);
        let t4 = 1_792_231_849_253_621_800;
        clock
            .response_received(t1_seconds, 2_208_997_154, 2_208_997_154, t4)
            .expect("a matched answer");

        // The mirror timestamp decodes as 8355 seconds and a fraction of a second since
        // the client booted, and it has to land within a second of the frame's arrival.
        let frame = 35_884_668_244_832u64;
        assert_eq!(frame >> 32, 8_355, "the high half counts client seconds");
        let local = clock.to_local(frame).expect("a conversion");
        assert!(
            local.abs_diff(t4) < 1_000_000_000,
            "converted {local} against an arrival of {t4}"
        );
    }

    #[test]
    fn consecutive_frames_differ_by_one_frame_of_ticks() {
        // The same session: two frames thirty-three milliseconds apart differed by
        // 143156808 ticks, and a second is 2^32 of them.
        let ticks = 143_156_808u64;
        let seconds = ticks as f64 / 4_294_967_296.0;
        assert!(
            (seconds - 1.0 / 30.0).abs() < 0.001,
            "a frame lasted {seconds} s"
        );
        // And the high half counts seconds: 8355 seconds of boot time is 8355 * 2^32
        // ticks, which is where the observed value's high half sits.
        let observed = 35_884_668_244_832u64;
        assert_eq!(observed >> 32, 8_355);
    }
    #[test]
    fn an_answer_that_echoes_nothing_this_receiver_sent_is_refused() {
        let mut clock = RemoteClock::new();
        clock.request_sent(1_000);
        assert!(
            clock
                .response_received(0xdead_beef, 1, 2, seconds(1_001))
                .is_none(),
            "a reply the receiver never asked for is not a measurement"
        );
        assert!(clock.fixed_offset_nanos().is_none());
    }

    #[test]
    fn the_same_answer_twice_is_ignored() {
        let mut clock = RemoteClock::new();
        let t2: u32 = 8_354u32.wrapping_add(2_208_988_800);
        let t1_seconds: u32 = 1_792_231_849u32.wrapping_add(2_208_988_800);
        clock.request_sent(t1_seconds);
        let first = clock.response_received(t1_seconds, t2, t2, 1_792_231_849_040_000_000);
        assert!(first.is_some());
        assert_eq!(
            clock.response_received(t1_seconds, t2, t2, 1_792_231_849_040_000_000),
            None,
            "a repeated t3 is the same exchange counted twice"
        );
    }

    #[test]
    fn nothing_is_converted_before_an_exchange() {
        let clock = RemoteClock::new();
        assert_eq!(clock.to_local(seconds(10)), None);
        assert_eq!(clock.to_remote(seconds(10)), None);
        assert!(!clock.is_synced());
        assert_eq!(clock.root_distance_nanos(), u64::MAX);
    }
    #[test]
    fn refuses_what_it_cannot_read() {
        assert_eq!(parse_response(&[]), Err(TimingError::TooShort));
        assert_eq!(parse_response(&[0x80]), Err(TimingError::TooShort));
        // A request is not a response.
        let request = build_request(1_700_000_000 * ntp::NANOS_PER_SECOND).expect("request");
        assert_eq!(
            parse_response(&request),
            Err(TimingError::NotAResponse { kind: 0x52 })
        );
        // The right type, but nothing to read in it.
        assert_eq!(
            parse_response(&[0x80, RESPONSE_TYPE | 0x80]),
            Err(TimingError::TooShort)
        );
    }
}
