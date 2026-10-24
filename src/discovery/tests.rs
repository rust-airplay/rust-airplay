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
