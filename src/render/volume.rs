// SPDX-License-Identifier: GPL-3.0-or-later
//! The AirPlay volume scale and the gain curve a backend applies.

/// The volume an AirPlay client means by the number it sends.
///
/// A client states volume in decibels over `-30` to `0`, and `-144` is its mute signal
/// A renderer wants a linear gain, so the two scales meet here:
/// the fraction is how far up the slider the client is, and the curve turns that into the
/// gain a sound card understands.
///
/// The direction matters: `-30` is silence and `0` is full, so an `-8` decibel value must land
/// high on the slider and a `-22` one low. The first version of this function computed the
/// two ends and the middle correctly and mirrored everything between them, which is a volume
/// that is quiet near the top and loud near the bottom.
///
/// # Examples
///
/// ```
/// use rust_airplay::airplay_db_to_fraction;
///
/// assert_eq!(airplay_db_to_fraction(0.0), 1.0, "0 dB is full volume");
/// assert_eq!(airplay_db_to_fraction(-30.0), 0.0, "-30 dB is silence");
/// assert_eq!(airplay_db_to_fraction(-144.0), 0.0, "-144 is the mute signal");
/// assert!((airplay_db_to_fraction(-15.0) - 0.5).abs() < 1e-9);
/// assert!(airplay_db_to_fraction(-8.0) > airplay_db_to_fraction(-22.0));
/// ```
#[must_use]
pub fn airplay_db_to_fraction(db: f64) -> f64 {
    const MUTE: f64 = -144.0;
    const LOW_DB: f64 = -30.0;
    const HIGH_DB: f64 = 0.0;
    if db == MUTE || db <= LOW_DB {
        return 0.0;
    }
    if db >= HIGH_DB {
        return 1.0;
    }
    ((db - LOW_DB) / (HIGH_DB - LOW_DB)).clamp(0.0, 1.0)
}

/// How a client's slider position becomes a gain.
///
/// This is the protocol's `-db` and `-taper` together. Flat rescaled the `-30..0` decibel range
/// onto `low_db..high_db`; tapered makes each halving of the remaining slider length a
/// halving of loudness (ten decibels), which is how several AirPlay senders behave
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VolumeCurve {
    /// Use the tapered profile rather than the flat one.
    pub taper: bool,
    /// Attenuation, in decibels, at the bottom of the slider.
    pub low_db: f64,
    /// Attenuation, in decibels, at the top of the slider.
    pub high_db: f64,
}

impl Default for VolumeCurve {
    fn default() -> Self {
        Self {
            taper: false,
            low_db: -30.0,
            high_db: 0.0,
        }
    }
}

impl VolumeCurve {
    /// The decibels this curve gives a slider position.
    #[must_use]
    pub fn db_for_fraction(self, fraction: f64) -> f64 {
        let fraction = fraction.clamp(0.0, 1.0);
        if fraction <= 0.0 {
            return self.low_db;
        }
        let flat = self.low_db + (self.high_db - self.low_db) * fraction;
        if self.taper {
            let tapered = self.high_db + 10.0 * fraction.log2();
            // The taper is never quieter than the flat mapping at the same position.
            tapered.max(flat)
        } else {
            flat
        }
    }

    /// The linear gain a renderer plays at for a slider position.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_airplay::VolumeCurve;
    ///
    /// let flat = VolumeCurve::default();
    /// assert!((flat.gain(1.0) - 1.0).abs() < 1e-12);
    /// assert_eq!(flat.gain(0.0), 0.0);
    ///
    /// // The tapered profile is louder than the flat one in the middle of the slider.
    /// let tapered = VolumeCurve {
    /// taper: true,
    /// ..VolumeCurve::default()
    /// };
    /// assert!(tapered.gain(0.5) > flat.gain(0.5));
    /// ```
    #[must_use]
    pub fn gain(self, fraction: f64) -> f64 {
        if fraction <= 0.0 {
            return 0.0;
        }
        // Decibels to a linear scale: `10 ** (0.05 * db)`.
        10f64.powf(0.05 * self.db_for_fraction(fraction))
    }
}

/// The volume a renderer plays at, from silence to full.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Volume(f64);

impl Volume {
    /// Full volume, which is what a session starts at: a client that says nothing
    /// about volume is not asking for silence.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_airplay::Volume;
    ///
    /// assert_eq!(Volume::new(0.5).fraction(), 0.5);
    /// assert_eq!(Volume::new(2.0), Volume::FULL, "a gain above unity is clamped");
    /// assert_eq!(Volume::new(-1.0).fraction(), 0.0);
    /// ```
    pub const FULL: Self = Self(1.0);

    /// The volume as a number from `0.0` to `1.0`, which is what a backend's own volume
    /// control takes.
    #[must_use]
    pub fn fraction(self) -> f64 {
        self.0
    }

    /// A volume, clamped to the range a client can ask for.
    ///
    /// AirPlay sends volume in decibels, where `0` is full scale and lower values are
    /// quieter; a value above full scale is not something to pass on to a device.
    #[must_use]
    pub fn new(level: f64) -> Self {
        if level.is_nan() {
            return Self::FULL;
        }
        Self(level.clamp(0.0, 1.0))
    }

    /// The level, from zero to one.
    pub fn level(self) -> f64 {
        self.0
    }
}

impl Default for Volume {
    fn default() -> Self {
        Self::FULL
    }
}
