// SPDX-License-Identifier: GPL-3.0-or-later
//! Multicast-DNS advertisement of the receiver.
//!
//! A receiver is reachable only if it announces itself: the protocol registers two
//! records, `_raop._tcp` for the audio protocol and `_airplay._tcp` for the
//! control protocol,
//! and a client discovers it by browsing those types. This module builds the
//! same records from a [`DeviceIdentity`] and registers them through `mdns-sd`.
//!
//! # Why the record contents are pinned to the protocol
//!
//! The text record is the advertisement's contract: `features` decides which
//! flows a client offers, `pk` is the key the client later authenticates the
//! receiver with, and `sf`/`pw` say whether a PIN or a password is expected.
//! A receiver that advertises one thing and answers another is undiscoverable in
//! practice, so the field list, the fixed values and the `pk` all mirror
//! and rather than being invented here.

use std::collections::HashMap;

use mdns_sd::{ServiceDaemon, ServiceInfo};

use crate::server::DeviceIdentity;

/// Service type of the audio protocol record.
const RAOP_SERVICE: &str = "_raop._tcp.local.";

/// Service type of the control protocol record.
const AIRPLAY_SERVICE: &str = "_airplay._tcp.local.";

/// Records take these values from.
const RAOP_TXTVERS: &str = "1";
const RAOP_CHANNELS: &str = "2";

const RAOP_ENCRYPTION: &str = "0,3,5";
const RAOP_RHD: &str = "5.6.0.0";
const RAOP_SAMPLE_RATE: &str = "44100";
const RAOP_SAMPLE_SIZE: &str = "16";
const RAOP_SV: &str = "false";
const RAOP_TP: &str = "UDP";
const RAOP_METADATA: &str = "0,1,2";
const RAOP_VN: &str = "65537";
const AIRPLAY_FLAGS: &str = "0x4";

/// `sf` of the audio record when no client has to authenticate.
const RAOP_SF_OPEN: &str = "0x4";
/// `sf` of the audio record when a digest password is required.
const RAOP_SF_PASSWORD: &str = "0x84";

/// What a client has to do before the receiver serves it.
///
/// It is one choice rather than two flags, because the records have exactly one
/// `pw`/`sf` pair: the protocol picks it with the same switch
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// Clients connect without authenticating.
    None,
    /// A digest password is requested when the client sets up a session.
    Password,
    /// The modern pairing flow asks the user for a PIN.
    Pin,
}

impl Protection {
    /// `pw` value of both records.
    ///
    /// A **password** and nothing else. A client reads these fields to decide whether it
    /// needs a credential, and AirPlay advertises `pw=false` on a receiver that asks clients
    /// to pair with a PIN, because pairing is a protocol step and a password is access
    /// control. Saying `true` here told clients that a receiver with no password had one.
    fn password_required(self) -> &'static str {
        match self {
            Self::None | Self::Pin => "false",
            Self::Password => "true",
        }
    }

    /// `sf` value of the audio record.
    ///
    /// Read back from a running receiver with `dns-sd`: `sf=0x4` on a receiver that does
    /// PIN pairing, and `0x84` only when a password is configured. The value this crate
    /// used to send for PIN pairing, `0x8c`, set both the "pin required" bit and the
    /// "password required" bit, which no receiver with a PIN alone advertises.
    fn status_flags(self) -> &'static str {
        match self {
            Self::None | Self::Pin => RAOP_SF_OPEN,
            Self::Password => RAOP_SF_PASSWORD,
        }
    }
}

/// The two records one receiver advertises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertisement {
    /// Instance name of the audio record: the hardware address, then the name
    pub raop_name: String,
    /// Instance name of the control record: the receiver's name.
    pub airplay_name: String,
    /// Port both records point at: the control service, which is where a client
    /// starts every session.
    pub port: u16,
    /// Text record of `_raop._tcp`.
    pub raop_txt: HashMap<String, String>,
    /// Text record of `_airplay._tcp`.
    pub airplay_txt: HashMap<String, String>,
}

impl Advertisement {
    /// Builds the records a receiver with `identity` advertises on `port`.
    ///
    /// `identity.public_key` is the `pk` field, so a caller that pairs clients has to build
    /// the identity from the same key it signs with (`docs/ARCHITECTURE.md`).
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_airplay::discovery::{Advertisement, Protection};
    /// use rust_airplay::server::DeviceIdentity;
    ///
    /// let identity = DeviceIdentity::default();
    /// let advertisement = Advertisement::new(&identity, 7000, Protection::None);
    /// let (airplay, raop) = advertisement.txt_records();
    /// assert!(!airplay.is_empty());
    /// assert!(!raop.is_empty());
    /// ```
    pub fn new(identity: &DeviceIdentity, port: u16, protection: Protection) -> Self {
        let features = features_string(identity.features);
        let public_key = hex(&identity.public_key);
        let mut raop_txt = HashMap::new();
        raop_txt.insert("txtvers".to_owned(), RAOP_TXTVERS.to_owned());
        raop_txt.insert("ch".to_owned(), RAOP_CHANNELS.to_owned());
        raop_txt.insert("cn".to_owned(), codecs_string());
        raop_txt.insert("da".to_owned(), "true".to_owned());
        raop_txt.insert("et".to_owned(), RAOP_ENCRYPTION.to_owned());
        raop_txt.insert("vv".to_owned(), identity.vv.to_string());
        raop_txt.insert("ft".to_owned(), features.clone());
        raop_txt.insert("am".to_owned(), identity.model.clone());
        raop_txt.insert("md".to_owned(), RAOP_METADATA.to_owned());
        raop_txt.insert("rhd".to_owned(), RAOP_RHD.to_owned());
        raop_txt.insert("pw".to_owned(), protection.password_required().to_owned());
        raop_txt.insert("sf".to_owned(), protection.status_flags().to_owned());
        raop_txt.insert("sr".to_owned(), RAOP_SAMPLE_RATE.to_owned());
        raop_txt.insert("ss".to_owned(), RAOP_SAMPLE_SIZE.to_owned());
        raop_txt.insert("sv".to_owned(), RAOP_SV.to_owned());
        raop_txt.insert("tp".to_owned(), RAOP_TP.to_owned());
        raop_txt.insert("vs".to_owned(), identity.source_version.clone());
        raop_txt.insert("vn".to_owned(), RAOP_VN.to_owned());
        raop_txt.insert("pk".to_owned(), public_key.clone());

        let mut airplay_txt = HashMap::new();
        airplay_txt.insert("deviceid".to_owned(), identity.device_id.clone());
        airplay_txt.insert("features".to_owned(), features);
        airplay_txt.insert("pw".to_owned(), protection.password_required().to_owned());
        airplay_txt.insert("flags".to_owned(), AIRPLAY_FLAGS.to_owned());
        airplay_txt.insert("model".to_owned(), identity.model.clone());
        airplay_txt.insert("pk".to_owned(), public_key);
        airplay_txt.insert("pi".to_owned(), identity.pi.clone());
        airplay_txt.insert("srcvers".to_owned(), identity.source_version.clone());
        airplay_txt.insert("vv".to_owned(), identity.vv.to_string());

        Self {
            raop_name: format!(
                "{}@{}",
                hardware_address(&identity.device_id),
                identity.name
            ),
            airplay_name: identity.name.clone(),
            port,
            raop_txt,
            airplay_txt,
        }
    }

    /// Encodes both records the way a client asks for them with `GET /info`: the
    /// control record first, then the audio one.
    ///
    /// A receiver that answers `/info` with the same bytes it advertises cannot
    /// tell a client two different things, which is why [`DeviceIdentity`]
    /// carries them ( answers the
    /// record a client names in its query).
    pub fn txt_records(&self) -> (Vec<u8>, Vec<u8>) {
        (encode_txt(&self.airplay_txt), encode_txt(&self.raop_txt))
    }
}

/// The `cn` record: the codings a client may choose from.
///
/// Built from [`AudioCodec::ALL`] rather than written out, so the advertisement cannot
/// drift from what this receiver decodes. The protocol lists `0,1,2,3` because it decodes all
/// four; this crate decodes two, and offering the other two would be a promise no part of
/// the receiver keeps.
fn codecs_string() -> String {
    crate::render::AudioCodec::ALL
        .iter()
        .map(|codec| codec.codec_number().to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Encodes properties in the text record wire format: a sequence of entries,
/// each a length byte followed by `key=value` (RFC 6763 section 6.4).
///
/// Entries are written in key order so the same advertisement always produces
/// the same bytes, and an entry that cannot fit into one length byte is left out
/// — the protocol's `TXTRecordSetValue` refuses those the same way
///, and every value this
/// module produces is far below the limit.
fn encode_txt(properties: &HashMap<String, String>) -> Vec<u8> {
    let mut entries: Vec<String> = properties
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    entries.sort();
    let mut encoded = Vec::new();
    for entry in entries {
        let bytes = entry.as_bytes();
        if bytes.len() + 1 > MAX_TXT_ENTRY {
            continue;
        }
        encoded.push(bytes.len() as u8);
        encoded.extend_from_slice(bytes);
    }
    encoded
}

/// Longest text record entry DNS-SD can carry: one length byte, so 255 bytes
/// including the byte itself.
const MAX_TXT_ENTRY: usize = 255;

/// The `0x%X,0x%X` pair both records carry
fn features_string(features: u64) -> String {
    let lower = features & 0xFFFF_FFFF;
    let upper = features >> 32;
    format!("0x{lower:X},0x{upper:X}")
}

/// Hardware address in the form the audio record's instance name uses:
/// upper-case hex without separators (`utils_hwaddr_raop`).
fn hardware_address(device_id: &str) -> String {
    device_id
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|digit| digit.to_ascii_uppercase())
        .collect()
}

/// Lower-case hexadecimal, the form `pk` is advertised in.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Why the receiver could not be advertised.
#[derive(Debug)]
pub enum DiscoveryError {
    /// The responder could not be started.
    Daemon(String),
    /// A record could not be built from its fields.
    Service(String),
    /// A record could not be registered.
    Register(String),
    /// A record could not be withdrawn.
    Unregister(String),
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Daemon(message) => write!(formatter, "the responder did not start: {message}"),
            Self::Service(message) => {
                write!(formatter, "the record is not advertisable: {message}")
            }
            Self::Register(message) => {
                write!(formatter, "the record was not registered: {message}")
            }
            Self::Unregister(message) => {
                write!(formatter, "the record was not withdrawn: {message}")
            }
        }
    }
}

impl std::error::Error for DiscoveryError {}

/// A receiver that is announced over multicast DNS.
///
/// Dropping the value withdraws both records, so a caller keeps it alive for as
/// long as the receiver runs.
pub struct Advertiser {
    daemon: ServiceDaemon,
    fullnames: Vec<String>,
}

impl Advertiser {
    /// Announces `advertisement` on every interface the responder finds.
    ///
    /// Dropping the returned value withdraws both records.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError`] when the responder cannot start or a record
    /// cannot be built or registered, for example when a field is not a valid
    /// DNS label.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rust_airplay::discovery::{Advertisement, Advertiser, Protection};
    /// use rust_airplay::server::DeviceIdentity;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let identity = DeviceIdentity::default();
    /// let advertisement = Advertisement::new(&identity, 7000, Protection::None);
    /// let advertiser = Advertiser::register(&advertisement)?;
    /// // The receiver runs here; dropping `advertiser` withdraws it.
    /// drop(advertiser);
    /// # Ok(())
    /// # }
    /// ```
    pub fn register(advertisement: &Advertisement) -> Result<Self, DiscoveryError> {
        let daemon =
            ServiceDaemon::new().map_err(|error| DiscoveryError::Daemon(error.to_string()))?;
        let host = format!(
            "{}.local.",
            hardware_address(&advertisement.raop_name).to_lowercase()
        );
        let mut fullnames = Vec::with_capacity(2);
        let records = [
            (
                RAOP_SERVICE,
                &advertisement.raop_name,
                &advertisement.raop_txt,
            ),
            (
                AIRPLAY_SERVICE,
                &advertisement.airplay_name,
                &advertisement.airplay_txt,
            ),
        ];
        for (service_type, name, properties) in records {
            let info = ServiceInfo::new(
                service_type,
                name,
                &host,
                // The responder fills in the addresses of every interface, which
                // is what a receiver on a machine with several adapters needs.
                "",
                advertisement.port,
                properties.clone(),
            )
            .map(|info| info.enable_addr_auto())
            .map_err(|error| DiscoveryError::Service(error.to_string()))?;
            let fullname = info.get_fullname().to_owned();
            daemon
                .register(info)
                .map_err(|error| DiscoveryError::Register(error.to_string()))?;
            fullnames.push(fullname);
        }
        Ok(Self { daemon, fullnames })
    }

    /// Full names of the registered records, for diagnostics.
    pub fn fullnames(&self) -> &[String] {
        &self.fullnames
    }

    /// Withdraws both records and stops the responder.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::Unregister`] when a withdrawal was refused; the
    /// responder is stopped either way, and dropping the value does the same
    /// without reporting.
    pub fn unregister(self) -> Result<(), DiscoveryError> {
        let mut failure = None;
        for fullname in &self.fullnames {
            if let Err(error) = self.daemon.unregister(fullname) {
                failure.get_or_insert_with(|| DiscoveryError::Unregister(error.to_string()));
            }
        }
        if let Err(error) = self.daemon.shutdown() {
            failure.get_or_insert_with(|| DiscoveryError::Unregister(error.to_string()));
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for Advertiser {
    /// Withdraws the records without reporting; [`Advertiser::unregister`] is the
    /// version that tells the caller whether that worked.
    fn drop(&mut self) {
        for fullname in &self.fullnames {
            let _ = self.daemon.unregister(fullname);
        }
        let _ = self.daemon.shutdown();
    }
}

#[cfg(test)]
mod tests {
    // SPDX-License-Identifier: GPL-3.0-or-later
    //! Tests for the advertisement and its text records.
    use super::*;

    fn identity() -> DeviceIdentity {
        DeviceIdentity {
            device_id: "aa:bb:cc:dd:ee:ff".to_owned(),
            name: "Receiver".to_owned(),
            public_key: vec![0xab; 32],
            ..DeviceIdentity::default()
        }
    }

    #[test]
    fn audio_record_matches_the_expected_fields() {
        let advertisement = Advertisement::new(&identity(), 7000, Protection::Pin);
        assert_eq!(advertisement.port, 7000);
        assert_eq!(advertisement.raop_name, "AABBCCDDEEFF@Receiver");
        let txt = &advertisement.raop_txt;
        // The expected values are what a current AirPlay receiver advertises, read back with
        // `dns-sd`, with one deliberate difference: `cn` lists the codings this receiver can
        // decode rather than the four the protocol lists, because offering a coding no renderer
        // here takes produces noise at the client with no way for it to notice.
        for (key, value) in [
            ("txtvers", "1"),
            ("ch", "2"),
            ("cn", "1,3"),
            ("da", "true"),
            ("et", "0,3,5"),
            ("vv", "2"),
            ("ft", "0x527FFEE6,0x0"),
            ("am", "AppleTV3,2"),
            ("md", "0,1,2"),
            ("rhd", "5.6.0.0"),
            ("pw", "false"),
            ("sf", "0x4"),
            ("sr", "44100"),
            ("ss", "16"),
            ("sv", "false"),
            ("tp", "UDP"),
            ("vs", "220.68"),
            ("vn", "65537"),
        ] {
            assert_eq!(txt.get(key).map(String::as_str), Some(value), "{key}");
        }
        assert_eq!(
            txt.get("pk").map(String::as_str),
            Some(&"ab".repeat(32)[..])
        );
        // The record carries nothing beyond the fields the protocol sets.
        assert_eq!(txt.len(), 19);
    }

    #[test]
    fn control_record_matches_the_expected_fields() {
        let advertisement = Advertisement::new(&identity(), 7000, Protection::Password);
        assert_eq!(advertisement.airplay_name, "Receiver");
        let txt = &advertisement.airplay_txt;
        for (key, value) in [
            ("deviceid", "aa:bb:cc:dd:ee:ff"),
            ("features", "0x527FFEE6,0x0"),
            ("pw", "true"),
            ("flags", "0x4"),
            ("model", "AppleTV3,2"),
            ("pi", crate::server::DEFAULT_PI),
            ("srcvers", "220.68"),
            ("vv", "2"),
        ] {
            assert_eq!(txt.get(key).map(String::as_str), Some(value), "{key}");
        }
        assert_eq!(
            txt.get("pk").map(String::as_str),
            Some(&"ab".repeat(32)[..])
        );
        assert_eq!(txt.len(), 9);
    }

    #[test]
    fn protection_selects_the_password_fields() {
        let open = Advertisement::new(&identity(), 7000, Protection::None);
        assert_eq!(open.raop_txt.get("pw").map(String::as_str), Some("false"));
        assert_eq!(open.raop_txt.get("sf").map(String::as_str), Some("0x4"));
        assert_eq!(
            open.airplay_txt.get("pw").map(String::as_str),
            Some("false")
        );

        let password = Advertisement::new(&identity(), 7000, Protection::Password);
        assert_eq!(
            password.raop_txt.get("sf").map(String::as_str),
            Some("0x84")
        );
        // A PIN is not a password. A receiver that asks a client to pair with a PIN advertises
        // `pw=false` and `sf=0x4` — that is what a current receiver does, read back from it with
        // `dns-sd`. Saying otherwise sends a client down its credential path before connecting.
        let pin = Advertisement::new(&identity(), 7000, Protection::Pin);
        assert_eq!(pin.raop_txt.get("sf").map(String::as_str), Some("0x4"));
        assert_eq!(pin.raop_txt.get("pw").map(String::as_str), Some("false"));
        assert_eq!(pin.airplay_txt.get("pw").map(String::as_str), Some("false"));
    }

    #[test]
    fn text_records_encode_every_field_for_info() {
        let advertisement = Advertisement::new(&identity(), 7000, Protection::Pin);
        let (airplay, raop) = advertisement.txt_records();

        // Decoding the wire format gives back exactly the maps, so `/info` and
        // the advertisement cannot disagree.
        assert_eq!(decode_txt(&airplay), advertisement.airplay_txt);
        assert_eq!(decode_txt(&raop), advertisement.raop_txt);
        // The encoding is stable and every entry fits one length byte.
        assert_eq!(advertisement.txt_records().0, airplay);
        assert_eq!(advertisement.txt_records().1, raop);
        assert!(airplay.len() <= advertisement.airplay_txt.len() * (MAX_TXT_ENTRY + 1));
    }

    /// An entry that cannot fit into a length byte is left out rather than
    /// truncated into something a client would misread.
    #[test]
    fn text_record_encoding_drops_what_cannot_fit() {
        let mut properties = HashMap::new();
        properties.insert("short".to_owned(), "value".to_owned());
        properties.insert("long".to_owned(), "x".repeat(300));
        let encoded = encode_txt(&properties);
        let mut expected = Vec::new();
        expected.push(11u8);
        expected.extend_from_slice(b"short=value");
        assert_eq!(encoded, expected);
    }

    /// Decodes the wire format, for the tests above and for anyone reading a
    /// record off the network.
    fn decode_txt(encoded: &[u8]) -> HashMap<String, String> {
        let mut properties = HashMap::new();
        let mut rest = encoded;
        while let Some((&length, tail)) = rest.split_first() {
            let length = usize::from(length);
            let (entry, tail) = tail.split_at_checked(length).expect("entry fits");
            let (key, value) = std::str::from_utf8(entry)
                .expect("utf-8")
                .split_once('=')
                .expect("key=value");
            properties.insert(key.to_owned(), value.to_owned());
            rest = tail;
        }
        properties
    }

    #[test]
    fn hardware_address_drops_the_separators() {
        assert_eq!(hardware_address("aa:bb:cc:dd:ee:ff"), "AABBCCDDEEFF");
        assert_eq!(hardware_address("AA-BB-CC-DD-EE-FF"), "AABBCCDDEEFF");
    }

    #[test]
    fn features_are_split_into_two_thirty_two_bit_halves() {
        assert_eq!(features_string(0x5A7F_FEE6), "0x5A7FFEE6,0x0");
        assert_eq!(features_string(0x1_0000_0001), "0x1,0x1");
    }

    /// Registers both records on the local network and withdraws them again.
    ///
    /// Ignored by default: it needs multicast DNS to work on the machine, and a
    /// system Bonjour service may already hold the port. Run it with
    /// `cargo test --lib -- --ignored advertises_and_withdraws`.
    #[test]
    #[ignore = "needs a working multicast DNS responder on the local network"]
    fn advertises_and_withdraws_both_records() {
        let advertisement = Advertisement::new(&identity(), 7000, Protection::Pin);
        let advertiser = Advertiser::register(&advertisement).expect("register");
        assert_eq!(advertiser.fullnames().len(), 2);
        advertiser.unregister().expect("unregister");
    }
}
