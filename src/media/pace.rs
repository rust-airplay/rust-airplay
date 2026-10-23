//! When a frame of a session should play.
//!
//! The two streams a session carries do not share a timestamp domain, and a device session
//! settled that: a mirror frame's timestamp is NTP fixed point in the client's own epoch
//! (the high half read 8689, which is how long the device had been up), while an audio
//! frame's timestamp is an RTP counter that starts at a random value (2266925849, which is
//! fifty-one thousand seconds if it is read as samples) and advances 480 samples a frame.
//! Comparing the two is subtracting two arbitrary origins.
//!
//! What each stream does have is a rate. A mirror timestamp advances 2^32 per second, and
//! an audio timestamp advances at the sample rate. Given the moment the first frame
//! arrived, that rate says when every later frame is due, which is all a receiver needs to
//! play a stream at the speed it was captured.
//!
//! Anchoring each stream on its own first arrival is also what keeps them together. The
//! client captures audio and video at the same instants and sends them at the same time, so
//! their first frames arrive a network's width apart, and two anchors taken at arrival stay
//! that far apart for the rest of the session instead of drifting.

use std::time::Duration;

/// How fast a stream's timestamp counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ticks {
    /// NTP fixed point: 2^32 of them per second, the form a mirror frame carries.
    NtpFixed,
    /// Samples per second, the form an audio frame carries.
    Samples(u32),
}

impl Ticks {
    /// Ticks in one second.
    #[must_use]
    fn per_second(self) -> u64 {
        match self {
            // Fixed point overflows a 32-bit field by construction, so the count is 2^32.
            Self::NtpFixed => u64::from(u32::MAX) + 1,
            Self::Samples(rate) => u64::from(rate.max(1)),
        }
    }

    /// How long `ticks` of this stream last.
    #[must_use]
    fn duration(self, ticks: u64) -> Duration {
        // Nanoseconds, because a frame at thirty a second is thirty-three million of them
        // and dividing at millisecond resolution would round every frame interval.
        let nanos = (u128::from(ticks) * 1_000_000_000) / u128::from(self.per_second());
        Duration::from_nanos(nanos as u64)
    }
}

/// Turns a stream's timestamps into the instants its frames are due.
///
/// The first frame sets the anchor: whatever time this crate is told it arrived is when the
/// stream starts. Every later frame is due one of its own tick intervals after that.
#[derive(Debug, Clone)]
pub struct Pacer {
    ticks: Ticks,
    anchor: Option<(u64, u64)>,
}

impl Pacer {
    /// A pacer for a stream whose timestamps count at `ticks`.
    #[must_use]
    pub fn new(ticks: Ticks) -> Self {
        Self {
            ticks,
            anchor: None,
        }
    }

    /// Records a frame arriving at `arrival` (monotonic nanoseconds) and says when it is due.
    ///
    /// The first frame is due at its own arrival: there is nothing yet to say it is late,
    /// and a receiver that waited before playing its first frame would be adding a delay it
    /// has no way to justify.
    ///
    /// A frame whose timestamps go backwards is clamped to the anchor rather than scheduling
    /// it in the past, which a client that renumbers its stream would otherwise do.
    pub fn due(&mut self, timestamp: u64, arrival: u64) -> u64 {
        match self.anchor {
            None => {
                self.anchor = Some((timestamp, arrival));
                arrival
            }
            Some((first, at)) => {
                let elapsed = timestamp.wrapping_sub(first);
                // A timestamp that went backwards is a renumbered stream, not a frame from
                // the past: the anchor stands and this frame plays as soon as it can.
                let elapsed = if elapsed > u64::MAX / 2 { 0 } else { elapsed };
                at.saturating_add(self.ticks.duration(elapsed).as_nanos() as u64)
            }
        }
    }

    /// When a frame is due, with the wait it implies capped at `max_lead`.
    ///
    /// This is what keeps a measured latency from turning into an observed one. A client
    /// sends mirror frames in bursts - a second of capture can arrive in fifty
    /// milliseconds - and spreading a burst over its capture time means the last frame of
    /// it waits nearly a second before it is shown. Capping the wait makes the stream play
    /// a little fast at the end of a burst and a little slow at the start of the next one,
    /// which is a few milliseconds of unevenness rather than a second of lag.
    ///
    /// The anchor moves with the cap, so the following frames are spaced from the frame
    /// that was shown early rather than from the one that was not.
    pub fn due_limited(&mut self, timestamp: u64, arrival: u64, max_lead: Duration) -> u64 {
        let due = self.due(timestamp, arrival);
        if due.saturating_sub(arrival) > max_lead.as_nanos() as u64 {
            self.anchor = Some((timestamp, arrival));
            return arrival;
        }
        due
    }

    /// How long to wait before a frame that is due at `due` and has arrived at `now`.
    ///
    /// `None` when the frame is already due, which a caller treats as "write it now". A
    /// stream that has fallen behind does not have to catch up by playing early: it plays
    /// each frame as soon as it can, and the lag stays visible in whatever is counting
    /// dropped frames rather than being hidden by a burst.
    #[must_use]
    pub fn wait(due: u64, now: u64) -> Option<Duration> {
        (due > now).then(|| Duration::from_nanos(due - now))
    }
}

#[cfg(test)]
mod tests {
    use super::{Pacer, Ticks};
    use std::time::Duration;

    #[test]
    fn a_mirror_stream_plays_at_thirty_frames_a_second() {
        // The numbers a device produced: consecutive frames of a 1554x1080 mirror stream
        // differed by 143156808 ticks, and 2^32 of them is a second.
        let mut pacer = Pacer::new(Ticks::NtpFixed);
        let first = 37_322_249_211_398u64;
        assert_eq!(pacer.due(first, 1_000_000_000), 1_000_000_000);
        let second = first + 143_156_808;
        let due = pacer.due(second, 1_000_000_000);
        let interval = Duration::from_nanos(due - 1_000_000_000);
        assert!(
            interval.abs_diff(Duration::from_micros(33_333)) < Duration::from_micros(100),
            "one frame lasted {interval:?}"
        );
    }

    #[test]
    fn an_audio_stream_plays_at_its_sample_rate() {
        // An audio frame at 44.1 kHz carries 480 samples, which is 10.88 ms.
        let mut pacer = Pacer::new(Ticks::Samples(44_100));
        let first = 2_266_925_849u64;
        assert_eq!(pacer.due(first, 5_000_000_000), 5_000_000_000);
        let due = pacer.due(first + 480, 5_000_000_000);
        let interval = Duration::from_nanos(due - 5_000_000_000);
        assert!(
            interval.abs_diff(Duration::from_micros(10_884)) < Duration::from_micros(10),
            "one frame lasted {interval:?}"
        );
    }

    #[test]
    fn a_burst_of_frames_keeps_its_capture_spacing() {
        // A client sends mirror frames in bursts: the device's frames arrived thirty-three
        // milliseconds of capture apart but four milliseconds of arrival apart. Playing
        // them on arrival would run the stream eight times fast.
        let mut pacer = Pacer::new(Ticks::NtpFixed);
        let first = 1_000u64;
        pacer.due(first, 0);
        let mut last = 0;
        for index in 1..=3u64 {
            last = pacer.due(first + index * 143_156_808, 4_000_000);
        }
        let span = Duration::from_nanos(last);
        assert!(
            span.abs_diff(Duration::from_millis(100)) < Duration::from_millis(1),
            "three frames spanned {span:?}"
        );
    }

    #[test]
    fn a_timestamp_that_goes_backwards_does_not_schedule_the_past() {
        let mut pacer = Pacer::new(Ticks::Samples(44_100));
        pacer.due(10_000, 2_000_000_000);
        let due = pacer.due(5_000, 2_000_000_000);
        assert_eq!(
            due, 2_000_000_000,
            "a renumbered stream plays at the anchor"
        );
    }

    #[test]
    fn a_burst_does_not_buy_itself_a_second_of_latency() {
        // Thirty frame intervals is a second of capture. If the whole second arrives at
        // once, playing it at capture spacing would show the last frame a second late -
        // which is exactly the lag a device session showed. The cap makes the wait bounded
        // instead: the anchor moves and the burst plays out at once.
        let mut pacer = Pacer::new(Ticks::NtpFixed);
        let first = 1_000u64;
        let cap = Duration::from_millis(40);
        assert_eq!(pacer.due_limited(first, 0, cap), 0);
        let last = first + 29 * 143_156_808;
        let due = pacer.due_limited(last, 0, cap);
        assert_eq!(
            due, 0,
            "a frame a second in is shown now, not a second later"
        );

        // And the anchor moved with it: the next frame is spaced from the new anchor
        // rather than from the one the cap discarded.
        let next = last + 143_156_808;
        let due = pacer.due_limited(next, 0, cap);
        let interval = Duration::from_nanos(due);
        assert!(
            interval.abs_diff(Duration::from_micros(33_333)) < Duration::from_micros(100),
            "the following frame was spaced {interval:?}"
        );
    }

    #[test]
    fn a_frame_inside_the_cap_still_waits() {
        let mut pacer = Pacer::new(Ticks::NtpFixed);
        let first = 1_000u64;
        pacer.due_limited(first, 0, Duration::from_millis(40));
        // One frame in is thirty-three milliseconds, which is inside the cap.
        let due = pacer.due_limited(first + 143_156_808, 0, Duration::from_millis(40));
        let wait = Duration::from_nanos(due);
        assert!(
            wait.abs_diff(Duration::from_micros(33_333)) < Duration::from_micros(200),
            "a frame inside the cap waited {wait:?}"
        );
    }

    #[test]
    fn a_frame_that_is_already_due_is_not_waited_for() {
        assert!(Pacer::wait(1_000, 1_000).is_none());
        assert!(Pacer::wait(900, 1_000).is_none());
        assert_eq!(Pacer::wait(1_050, 1_000), Some(Duration::from_nanos(50)));
    }
}
