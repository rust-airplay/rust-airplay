// SPDX-License-Identifier: GPL-3.0-or-later

// Tests report what they measured; the library itself never prints.
#![allow(clippy::print_stdout, clippy::print_stderr)]

//! Fixture-driven checks of the plist layer.
//!
//! The fixtures under `tests/fixtures/` are produced by CPython's `plistlib`
//! (see `tools/plist_fixtures.py`), not by the `plist` crate that the port
//! itself uses, so the decode direction is checked against an independent
//! implementation of the binary plist format. The key names and value types
//! mirror what upstream UxPlay reads and writes:
//!
//! - SETUP request and response: `upstream/UxPlay/lib/raop_handlers.h:600-1067`
//! - GET /info request and response: `upstream/UxPlay/lib/raop_handlers.h:37-206`
//!
//! The encode direction is cross-checked the other way round: this test dumps
//! what [`Plist::encode_binary`] and [`Plist::encode_xml`] produced into
//! `$CARGO_TARGET_TMPDIR`, and
//!
//! ```text
//! python tools/plist_fixtures.py --verify <target>/tmp/setup_response.rust.bplist
//! ```
//!
//! parses those files back with `plistlib`.

use std::path::PathBuf;

use plist::Dictionary;
use rust_airplay::plist::Plist;

const SETUP_REQUEST: &[u8] = include_bytes!("fixtures/setup_request.bplist");
const SETUP_RESPONSE: &[u8] = include_bytes!("fixtures/setup_response.bplist");
const INFO_REQUEST: &[u8] = include_bytes!("fixtures/info_request.bplist");
const INFO_RESPONSE: &[u8] = include_bytes!("fixtures/info_response.bplist");

/// The stream connection id in the fixture exceeds `i64::MAX`, which real
/// clients reach as well: it is used verbatim to derive the mirror AES key.
const STREAM_CONNECTION_ID: u64 = 12_345_678_901_234_567_890;

fn fixture(bytes: &[u8]) -> Plist {
    Plist::parse(bytes).expect("fixture is a valid property list")
}

fn stream(plist: &Plist, index: usize) -> Dictionary {
    plist.get_array("streams").expect("streams is an array")[index]
        .as_dictionary()
        .expect("stream entry is a dictionary")
        .clone()
}

#[test]
fn setup_request_matches_the_upstream_contract() {
    let plist = fixture(SETUP_REQUEST);

    assert_eq!(plist.get_string("deviceID").unwrap(), "AA:BB:CC:DD:EE:FF");
    assert_eq!(plist.get_string("model").unwrap(), "iPhone14,2");
    assert_eq!(plist.get_string("name").unwrap(), "Tester's iPhone");
    assert_eq!(
        plist.get_data("ekey").unwrap(),
        (0u8..16).collect::<Vec<u8>>()
    );
    assert_eq!(
        plist.get_data("eiv").unwrap(),
        (16u8..32).collect::<Vec<u8>>()
    );

    let streams = plist.get_array("streams").unwrap();
    assert_eq!(streams.len(), 2);

    let audio = stream(&plist, 0);
    assert_eq!(audio.get("type").unwrap().as_unsigned_integer(), Some(96));
    assert_eq!(
        audio.get("controlPort").unwrap().as_unsigned_integer(),
        Some(6100)
    );
    assert_eq!(audio.get("ct").unwrap().as_unsigned_integer(), Some(1));
    assert_eq!(audio.get("spf").unwrap().as_unsigned_integer(), Some(352));
    assert_eq!(
        audio.get("audioFormat").unwrap().as_unsigned_integer(),
        Some(0x40000)
    );
    assert_eq!(audio.get("isMedia").unwrap().as_boolean(), Some(false));
    assert_eq!(audio.get("usingScreen").unwrap().as_boolean(), Some(true));

    let mirror = stream(&plist, 1);
    assert_eq!(mirror.get("type").unwrap().as_unsigned_integer(), Some(110));
    assert_eq!(
        mirror
            .get("streamConnectionID")
            .unwrap()
            .as_unsigned_integer(),
        Some(STREAM_CONNECTION_ID)
    );
}

#[test]
fn setup_response_has_the_ports_the_receiver_advertises() {
    let plist = fixture(SETUP_RESPONSE);

    assert_eq!(plist.get_unsigned("timingPort").unwrap(), 7011);
    assert_eq!(plist.get_unsigned("eventPort").unwrap(), 0);

    let mirror = stream(&plist, 0);
    assert_eq!(
        mirror.get("dataPort").unwrap().as_unsigned_integer(),
        Some(7100)
    );
    assert_eq!(mirror.get("type").unwrap().as_unsigned_integer(), Some(110));
    assert!(mirror.get("controlPort").is_none());

    let audio = stream(&plist, 1);
    assert_eq!(
        audio.get("dataPort").unwrap().as_unsigned_integer(),
        Some(7101)
    );
    assert_eq!(
        audio.get("controlPort").unwrap().as_unsigned_integer(),
        Some(7102)
    );
    assert_eq!(audio.get("type").unwrap().as_unsigned_integer(), Some(96));
}

#[test]
fn info_request_qualifier_is_an_array_of_strings() {
    let plist = fixture(INFO_REQUEST);
    let qualifier = plist.get_array("qualifier").unwrap();
    assert_eq!(qualifier.len(), 1);
    assert_eq!(qualifier[0].as_string(), Some("txtAirPlay"));
}

#[test]
fn info_response_carries_the_dnssd_txt_values() {
    let plist = fixture(INFO_RESPONSE);

    assert_eq!(plist.get_string("deviceID").unwrap(), "AA:BB:CC:DD:EE:FF");
    assert_eq!(plist.get_string("macAddress").unwrap(), "AA:BB:CC:DD:EE:FF");
    assert_eq!(
        plist.get_data("pk").unwrap(),
        (0u8..32).collect::<Vec<u8>>()
    );
    assert_eq!(plist.get_unsigned("features").unwrap(), 0x5A7F_FFF7);
    assert_eq!(plist.get_string("name").unwrap(), "Rust AirPlay");
    assert_eq!(
        plist.get_string("pi").unwrap(),
        "b08f5a79-db29-4384-b456-a6f0e8e9d7db"
    );
    assert_eq!(plist.get_unsigned("vv").unwrap(), 2);
    assert_eq!(plist.get_unsigned("statusFlags").unwrap(), 68);
    assert_eq!(plist.get_unsigned("keepAliveLowPower").unwrap(), 1);
    assert_eq!(plist.get_string("sourceVersion").unwrap(), "220.68");
    assert!(plist.get_boolean("keepAliveSendStatsAsBody").unwrap());
    assert_eq!(plist.get_string("model").unwrap(), "AppleTV6,2");
    assert_eq!(plist.get("initialVolume").unwrap().as_real(), Some(0.0));

    let latencies = plist.get_array("audioLatencies").unwrap();
    assert_eq!(latencies.len(), 2);
    assert_eq!(
        latencies[0]
            .as_dictionary()
            .unwrap()
            .get("type")
            .unwrap()
            .as_unsigned_integer(),
        Some(100)
    );
    assert_eq!(
        latencies[1]
            .as_dictionary()
            .unwrap()
            .get("audioType")
            .unwrap()
            .as_string(),
        Some("default")
    );

    let formats = plist.get_array("audioFormats").unwrap();
    assert_eq!(
        formats[0]
            .as_dictionary()
            .unwrap()
            .get("audioOutputFormats")
            .unwrap()
            .as_unsigned_integer(),
        Some(0x3FF_FFFC)
    );
}

#[test]
fn every_fixture_survives_a_binary_and_xml_round_trip() {
    let dump = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(&dump).unwrap();

    let fixtures = [
        ("setup_request", SETUP_REQUEST),
        ("setup_response", SETUP_RESPONSE),
        ("info_request", INFO_REQUEST),
        ("info_response", INFO_RESPONSE),
    ];

    for (name, bytes) in fixtures {
        let original = fixture(bytes);

        let binary = original.encode_binary().unwrap();
        assert!(binary.starts_with(b"bplist00"), "{name} is a binary plist");
        assert_eq!(Plist::parse(&binary).unwrap(), original, "{name} binary");

        let xml = original.encode_xml().unwrap();
        assert!(xml.starts_with(b"<?xml"), "{name} is an XML plist");
        assert_eq!(Plist::parse(&xml).unwrap(), original, "{name} xml");

        std::fs::write(dump.join(format!("{name}.rust.bplist")), &binary).unwrap();
        std::fs::write(dump.join(format!("{name}.rust.xml")), &xml).unwrap();
    }

    println!(
        "re-encoded fixtures written to {} (cross-check with tools/plist_fixtures.py --verify)",
        dump.display()
    );
}

#[test]
fn a_repeated_key_keeps_the_value_written_last() {
    // The control plane reads keys by name and never counts entries, so the map
    // behavior of `Dictionary` is the contract handlers rely on.
    let mut dictionary = plist::Dictionary::new();
    dictionary.insert("stage".to_owned(), plist::Value::from(1_u64));
    dictionary.insert("stage".to_owned(), plist::Value::from(2_u64));
    let plist = Plist::from_value(plist::Value::Dictionary(dictionary));

    assert_eq!(plist.get_unsigned("stage"), Ok(2));
}
