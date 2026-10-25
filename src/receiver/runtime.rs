// SPDX-License-Identifier: GPL-3.0-or-later
//! The clock probe, the report formatter and the receiver's error.

/// What the two streams' first frames say about their shared clock.
///
/// A session has to put audio and video on one timeline before either can be scheduled,
/// and the question that decides how is whether the two streams' timestamps count the same
/// thing. The audio timestamp counts samples, so it is unambiguous once the rate is known;
/// the video timestamp's unit is not written down anywhere in the protocol. Rather than
/// assume one, this records the first frame of each stream with the moment it arrived and
/// reports which candidate makes the two agree: if the timestamps share a clock, the
/// difference between them and the difference between the arrivals are the same number.
#[derive(Debug, Default)]
pub(super) struct ClockProbe {
    pub(super) audio: Option<(u64, u128)>,
    pub(super) video: Option<(u64, u128)>,
    /// The previous mirror frame, for the tick rate its deltas imply.
    pub(super) video_previous: Option<(u64, u128)>,
    /// How many mirror frames have been measured, so the log stays short.
    pub(super) video_measured: u32,
}

impl ClockProbe {
    /// The local time now, which is what a frame's arrival is measured against.
    pub(super) fn now() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or(0)
    }

    /// Records the first audio frame, and reports the pair when the video side is known.
    pub(super) fn audio(&mut self, samples: u64, rate: u32) {
        if self.audio.is_some() {
            return;
        }
        let arrival = Self::now();
        self.audio = Some((samples, arrival));
        log::info!(
            "clock     audio first frame: ts {} samples ({} s at {rate} Hz), arrived at {} ns",
            samples,
            samples as f64 / f64::from(rate.max(1)),
            arrival
        );
        self.report();
    }

    /// Measures the mirror stream's tick rate from two frames.
    ///
    /// The absolute epoch of a mirror timestamp is the start of the stream, which this
    /// receiver has no independent measure of, so comparing it with anything else is
    /// meaningless. What it does describe is how much time passed between two frames, and
    /// dividing that by the time the two frames actually arrived apart gives the rate in
    /// ticks per second. Three frames are measured and the median-ish middle one is what
    /// the log reports, because one measurement of a network arrival is not a measurement.
    pub(super) fn video_tick_rate(&mut self, timestamp: u64) {
        let arrival = Self::now();
        let Some((previous, previous_arrival)) = self.video_previous.replace((timestamp, arrival))
        else {
            return;
        };
        self.video_measured += 1;
        if self.video_measured > 4 {
            return;
        }
        let ticks = timestamp.saturating_sub(previous) as f64;
        let seconds = (arrival as i64 - previous_arrival as i64) as f64 / 1e9;
        if seconds <= 0.0 || ticks <= 0.0 {
            return;
        }
        // A Q32.32 timestamp ticks 2^32 times a second, so this is also a check on the
        // unit: a delta that divides by 2^32 into one frame interval is fixed point, and
        // one that divides into nothing is some other unit.
        log::info!(
            "clock     video delta {ticks:.0} ticks in {seconds:.6} s -> {:.0} Hz, \
             {:.3} frame intervals at 2^32 ticks a second",
            ticks / seconds,
            seconds * 4_294_967_296.0 / ticks
        );
    }

    /// Records the first mirror frame.
    pub(super) fn video(&mut self, timestamp: u64) {
        if self.video.is_some() {
            return;
        }
        let arrival = Self::now();
        self.video = Some((timestamp, arrival));
        log::info!("clock     video first frame: ts {timestamp}, arrived at {arrival} ns");
        self.video_previous = Some((timestamp, arrival));
        log::info!(
            "clock       candidates: /90000 = {:.6} s, /1000000 = {:.6} s, /1e9 = {:.6} s, \
             as q32.32 = {}",
            timestamp as f64 / 90_000.0,
            timestamp as f64 / 1_000_000.0,
            timestamp as f64 / 1e9,
            timestamp >> 32
        );
        self.report();
    }

    /// The candidate timebase that makes the two streams agree, with its residual.
    ///
    /// Returns `None` until both first frames have arrived. This is what a device run is
    /// asked for: the answer goes in the log, and a session that disagrees with every
    /// candidate has a timeline problem rather than a scheduling one.
    pub(super) fn agreement(&self) -> Option<(&'static str, f64)> {
        let ((audio, audio_arrival), (video, video_arrival)) = (self.audio?, self.video?);
        let observed = (video_arrival as i64 - audio_arrival as i64) as f64 / 1e9;
        let audio_seconds = audio as f64 / 44_100.0;
        let mut best: Option<(&'static str, f64)> = None;
        for (name, divisor) in [
            ("90000", 90_000.0),
            ("1e6", 1_000_000.0),
            ("1e9", 1e9),
            ("27e6", 27_000_000.0),
        ] {
            let residual = (audio_seconds - video as f64 / divisor) - observed;
            if best.is_none_or(|(_, lowest)| residual.abs() < lowest.abs()) {
                best = Some((name, residual));
            }
        }
        best.filter(|(_, residual)| residual.abs() < 0.05)
    }

    /// Says which candidate timebase makes the two streams agree, once both are known.
    pub(super) fn report(&self) {
        let (Some((audio, audio_arrival)), Some((video, video_arrival))) = (self.audio, self.video)
        else {
            return;
        };
        // The audio side is the example: samples over a known rate is a time.
        // The arrival difference is what a shared clock has to reproduce.
        let observed = (video_arrival as i64 - audio_arrival as i64) as f64 / 1e9;
        let audio_seconds = audio as f64 / 44_100.0;
        log::info!(
            "clock     the two first frames arrived {:.6} s apart, and their timestamps \
             differ by {:.6} s at the audio rate",
            observed,
            audio_seconds - video as f64 / 90_000.0
        );
        for (name, divisor) in [
            ("90000", 90_000.0),
            ("1e6", 1_000_000.0),
            ("1e9", 1e9),
            ("27e6", 27_000_000.0),
        ] {
            let video_seconds = video as f64 / divisor;
            let residual = (audio_seconds - video_seconds) - observed;
            log::info!(
                "clock       if the video clock is {name} Hz: residual {:+.6} s{}",
                residual,
                if residual.abs() < 0.05 {
                    "  <- agrees"
                } else {
                    ""
                }
            );
        }
        match self.agreement() {
            Some((name, residual)) => log::info!(
                "clock     the two streams share a clock: video counts {name} Hz \
                 (residual {:+.6} s)",
                residual
            ),
            None => log::info!(
                "clock     no candidate timebase makes the two agree: the streams do \
                 not share a timestamp domain"
            ),
        }
    }
}
/// A streaming report as a person can read it.
///
/// A report is a binary plist, so it is written out as XML; one that does not parse is
/// summarised as bytes, because a report a receiver cannot read is still evidence that the
/// client is sending something.
pub(super) fn describe_report(payload: &[u8]) -> String {
    const PREVIEW: usize = 2_048;
    let text = match crate::plist::Plist::parse(payload).and_then(|plist| plist.encode_xml()) {
        Ok(xml) => String::from_utf8_lossy(&xml).into_owned(),
        Err(_) => {
            let shown: Vec<String> = payload
                .iter()
                .take(32)
                .map(|byte| format!("{byte:02x}"))
                .collect();
            format!("{} bytes, not a plist: {}", payload.len(), shown.join(" "))
        }
    };
    if text.chars().count() > PREVIEW {
        text.chars().take(PREVIEW).collect()
    } else {
        text
    }
}

/// The gain a client's decibels mean under `curve`.
///
/// The two scales meet here: a client states decibels (with `-144` for mute) and a renderer
/// plays at a linear gain. Keeping it in one function is what lets the conversion be tested
/// without a sound card.
pub(super) fn client_gain(db: f32, curve: crate::VolumeCurve) -> f64 {
    let value = f64::from(db);
    // Decibels are `-30..0` and mute is `-144`, but a client that sends a **positive**
    // number is not speaking decibels: 0 is full scale, so above it can only be a slider
    // position, stated as a fraction (`0..1`) or a percentage (`0..100`). Treating those
    // as decibels clamped every one of them to full volume, which is a volume slider that
    // mutes at the bottom and does nothing anywhere else.
    let fraction = if value > 0.0 {
        if value <= 1.0 {
            value
        } else {
            (value / 100.0).clamp(0.0, 1.0)
        }
    } else {
        crate::airplay_db_to_fraction(value)
    };
    curve.gain(fraction)
}

/// The decibels a slider position means under `curve`.
pub(super) fn airplay_volume(fraction: f64, curve: crate::VolumeCurve) -> f64 {
    curve.db_for_fraction(fraction)
}

/// The longest a frame may be held back to keep a stream at its capture spacing.
///
/// A client sends a second of mirror frames in a few tens of milliseconds, so pacing them
/// exactly means the last frame of the burst waits most of a second before it is shown.
/// That is a latency the viewer sees, and it is the one this bounds: past the budget a
/// stream plays the frame it has and re-anchors, trading a few milliseconds of unevenness
/// for not falling behind.
///
/// Forty milliseconds is a little over one frame interval, and it is what a device session
/// asked for: with the budget at a hundred and twenty, the log showed the pacer holding
/// three frames at once - about a hundred milliseconds of it - while the queue in front of
/// the writer held another sixty-five. The pacer's share was the part this crate controls,
/// and cutting it costs only the ability to absorb a burst longer than a frame.
pub(super) const MAX_LEAD: std::time::Duration = std::time::Duration::from_millis(40);

/// Why a receiver could not start, or could not go on.
#[derive(Debug, Clone)]
pub struct Error {
    message: String,
}

impl Error {
    /// The message this error carries.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Self { message }
    }
}

impl From<&str> for Error {
    fn from(message: &str) -> Self {
        Self {
            message: message.to_owned(),
        }
    }
}
