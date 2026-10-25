// SPDX-License-Identifier: GPL-3.0-or-later
//! The filtered clock estimate built from timing exchanges.

/// How long a timing request waits for its answer before it is written off.
///
/// The protocol keeps eight outstanding requests (`RAOP_NTP_DATA_COUNT`) and every sample it
/// has not given up on; a request whose answer never arrives is simply never completed.
pub const OUTSTANDING_REQUESTS: usize = 8;

/// Samples the offset estimate averages over, which is the protocol's table size.
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
    /// Local arrival time of the answer, in nanoseconds since the Unix epoch.
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
/// Two things make it more than that arithmetic:
///
/// - The first remote timestamp seen fixes a *fixed offset*, so later arithmetic happens in
///   one clock domain instead of comparing a client's era to this machine's.
/// - Estimates are filtered: old samples age out, the lowest-delay sample leads, the rest are
///   weighted down, and a new estimate is smoothed into the previous one. A single exchange
///   over a busy network is a bad measurement, and the filter is what stops it from being the
///   one that counts.
#[derive(Debug, Clone)]
pub struct RemoteClock {
    samples: [Option<ClockSample>; SAMPLE_COUNT],
    /// Where the next sample is written, as the protocol's `data_index`.
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
    /// The table holds [`OUTSTANDING_REQUESTS`] entries and the oldest is overwritten, as
    /// the protocol does. An answer that echoes none of them is not this receiver's, and
    /// [`RemoteClock::response_received`] refuses it.
    pub fn request_sent(&mut self, t1: u32) {
        self.outstanding[self.next % OUTSTANDING_REQUESTS] = t1;
        self.next = (self.next + 1) % OUTSTANDING_REQUESTS;
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
        // seconds: `t1`, `t2` and `t3` are thirty-two bits each, and the protocol truncates the
        // arrival time to the same width. Mixing a fraction into
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
    /// `None` until a response has been read. This is the protocol's `fixed_offset`: the
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
    /// which is the order the protocol uses: it adjusts a remote timestamp with
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
        let nanos = i128::from(q32_32_to_nanos(remote_timestamp)) + i128::from(fixed)
            - i128::from(self.offset_nanos);
        Some(nanos.clamp(0, i128::from(u64::MAX)) as u64)
    }

    /// The client's time for a point in the local clock, in nanoseconds.
    #[must_use]
    pub fn to_remote(&self, local_nanos: u64) -> Option<u64> {
        let fixed = self.fixed_offset?;
        if !self.have_estimate {
            return None;
        }
        let remote = i128::from(local_nanos) + i128::from(self.offset_nanos) - i128::from(fixed);
        Some(remote.clamp(0, i128::from(u64::MAX)) as u64)
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
