// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded property-list access for AirPlay control payloads.
//!
//! # Duplicate keys
//!
//! A property list is a tree whose dictionaries map a string key to a value, so
//! a body that names the same key twice keeps one entry: the later value
//! replaces the earlier one. Both the reader this module wraps and the
//! [`Dictionary`] it re-exports behave that way, which is why a handler that
//! reads a key always sees the value a client wrote last. A reader that has to
//! reject such a body instead can count keys while walking the structure in
//! `check_structure`; today the control plane only reads a handful of
//! independent keys, so the map behavior is what the handlers are written
//! against and `plist_spec.rs` pins it.
//!
//! AirPlay speaks the binary and XML property-list formats: `SETUP` and `/pair-verify` bodies
//! are property lists, and responses are written as one. This module provides the two rules the
//! rest of the crate depends on:
//!
//! - the payload size is checked before the parser runs;
//! - typed access returns a typed error instead of panicking, so a malformed or truncated
//!   request body can never abort the process.
//!
//! Values are handed out as [`plist::Value`] on purpose: navigation of deeper
//! structures (for example `streams[]`) needs the full value API, and this crate
//! has no reason to hide it.

/// Property-list value the accessors of this module work with.
///
/// Re-exported so a caller that builds a response, such as the control service
/// handlers, needs only [`crate::plist`] rather than the backing implementation
/// crate.
pub use plist::Value;

/// Dictionary value of a property list, re-exported with [`Value`].
pub use plist::Dictionary;

/// Largest accepted plist payload. Matches the control-plane body bound in
mod check;
mod types;

pub use types::{
    MAX_PLIST_BYTES, MAX_PLIST_DEPTH, MAX_PLIST_OBJECTS, Plist, PlistError, dictionary,
};

#[cfg(test)]
use std::io::Cursor;

#[cfg(test)]
mod tests {
    // SPDX-License-Identifier: GPL-3.0-or-later
    //! Tests for bounded property-list parsing.
    use super::*;

    fn sample() -> plist::Value {
        dictionary([
            ("type", plist::Value::from("101")),
            ("timingPort", plist::Value::from(7011u64)),
            ("isRemoteControlOnly", plist::Value::from(false)),
            ("ekey", plist::Value::Data(vec![0xab; 16])),
            (
                "streams",
                plist::Value::Array(vec![dictionary([
                    ("type", plist::Value::from(110u64)),
                    ("audioFormat", plist::Value::from(0x40000u64)),
                ])]),
            ),
        ])
    }

    /// Builds a binary plist whose containers nest `depth` levels deep.
    ///
    /// Written out by hand because the encoder of the backing crate is
    /// recursive too, so it cannot produce the payload this bound exists for.
    fn nested_binary_plist(depth: usize) -> Vec<u8> {
        assert!(depth >= 1);
        let objects = depth;
        let offset_size = 2usize;
        let ref_size = if objects > 255 { 2usize } else { 1 };
        let mut bytes = b"bplist00".to_vec();
        let mut offsets = Vec::with_capacity(objects);
        for index in 0..objects {
            offsets.push(bytes.len());
            if index + 1 == objects {
                bytes.push(0xa0); // the innermost array is empty
            } else {
                bytes.push(0xa1); // an array holding the next level
                let reference = (index + 1).to_be_bytes();
                bytes.extend_from_slice(&reference[8 - ref_size..]);
            }
        }
        let table = bytes.len();
        for offset in &offsets {
            let encoded = offset.to_be_bytes();
            bytes.extend_from_slice(&encoded[8 - offset_size..]);
        }
        let mut trailer = [0u8; 32];
        trailer[6] = offset_size as u8;
        trailer[7] = ref_size as u8;
        trailer[8..16].copy_from_slice(&(objects as u64).to_be_bytes());
        trailer[16..24].copy_from_slice(&0u64.to_be_bytes());
        trailer[24..32].copy_from_slice(&(table as u64).to_be_bytes());
        bytes.extend_from_slice(&trailer);
        bytes
    }

    #[test]
    fn rejects_a_payload_that_nests_deeper_than_the_parser_can_descend() {
        // Without the bound in front of the parser this aborts the process with
        // a stack overflow rather than returning an error.
        for depth in [8, MAX_PLIST_DEPTH] {
            let bytes = nested_binary_plist(depth);
            assert!(
                bytes.len() < MAX_PLIST_BYTES,
                "the rejected payload has to fit the size bound"
            );
            assert!(Plist::parse(&bytes).is_ok(), "depth {depth} is accepted");
        }
        for depth in [MAX_PLIST_DEPTH + 1, 1_000, 5_000] {
            let bytes = nested_binary_plist(depth);
            let error = Plist::parse(&bytes).expect_err("deep nesting is refused");
            assert!(
                matches!(error, PlistError::Decode(_)),
                "depth {depth}: {error:?}"
            );
        }
    }

    #[test]
    #[ignore = "aborts the test process on purpose: it shows the stack overflow the bound prevents"]
    fn the_parser_behind_this_module_overflows_on_deep_nesting() {
        // Calls the backing parser directly, bypassing `check_structure`, so that
        // the reason for [`MAX_PLIST_DEPTH`] stays verifiable on demand:
        // `cargo test --lib -- --ignored the_parser_behind`.
        let bytes = nested_binary_plist(1_300);
        let _ = plist::Value::from_reader(Cursor::new(&bytes));
    }

    #[test]
    fn rejects_an_xml_payload_that_nests_too_deeply() {
        let deep = format!(
            "<?xml version=\"1.0\"?><plist version=\"1.0\">{}x{}</plist>",
            "<array>".repeat(MAX_PLIST_DEPTH + 1),
            "</array>".repeat(MAX_PLIST_DEPTH + 1)
        );
        assert!(matches!(
            Plist::parse(deep.as_bytes()),
            Err(PlistError::Decode(_))
        ));
        let shallow = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>a</key><string>b</string></dict></plist>";
        assert!(Plist::parse(shallow.as_bytes()).is_ok());
    }

    #[test]
    fn round_trips_binary_and_xml() {
        let plist = Plist::from_value(sample());
        let binary = plist.encode_binary().unwrap();
        assert!(binary.starts_with(b"bplist"));
        assert_eq!(Plist::parse(&binary).unwrap(), plist);

        let xml = plist.encode_xml().unwrap();
        assert!(xml.starts_with(b"<?xml"));
        assert_eq!(Plist::parse(&xml).unwrap(), plist);
    }

    #[test]
    fn reads_the_typed_values_requests_use() {
        let plist = Plist::from_value(sample());
        assert_eq!(plist.get_string("type").unwrap(), "101");
        assert_eq!(plist.get_unsigned("timingPort").unwrap(), 7011);
        assert!(!plist.get_boolean("isRemoteControlOnly").unwrap());
        assert_eq!(plist.get_data("ekey").unwrap(), &[0xab; 16]);
        let streams = plist.get_array("streams").unwrap();
        assert_eq!(streams.len(), 1);
        let stream = streams[0].as_dictionary().unwrap();
        assert_eq!(stream.get("type").unwrap().as_unsigned_integer(), Some(110));
        assert!(!plist.has_key("qualifier"));
        assert!(plist.get("qualifier").is_none());
    }

    #[test]
    fn reports_missing_keys_and_type_mismatches() {
        let plist = Plist::from_value(sample());
        assert_eq!(
            plist.get_string("qualifier"),
            Err(PlistError::MissingKey("qualifier"))
        );
        assert_eq!(
            plist.get_string("timingPort"),
            Err(PlistError::WrongType {
                key: "timingPort",
                expected: "string"
            })
        );
        assert_eq!(
            plist.get_array("type"),
            Err(PlistError::WrongType {
                key: "type",
                expected: "array"
            })
        );
        assert_eq!(
            plist.get_unsigned("ekey"),
            Err(PlistError::WrongType {
                key: "ekey",
                expected: "integer"
            })
        );
    }

    #[test]
    fn rejects_oversized_and_malformed_payloads() {
        let oversized = vec![0u8; MAX_PLIST_BYTES + 1];
        assert_eq!(
            Plist::parse(&oversized),
            Err(PlistError::TooLarge {
                declared: MAX_PLIST_BYTES + 1,
                maximum: MAX_PLIST_BYTES
            })
        );
        assert!(matches!(
            Plist::parse(b"not a plist at all"),
            Err(PlistError::Decode(_))
        ));
        assert!(matches!(
            Plist::parse(b"<?xml version=\"1.0\"?><plist><dict>"),
            Err(PlistError::Decode(_))
        ));
        // A truncated binary plist must fail rather than yield partial data.
        let binary = Plist::from_value(sample()).encode_binary().unwrap();
        assert!(matches!(
            Plist::parse(&binary[..binary.len() - 4]),
            Err(PlistError::Decode(_))
        ));
    }

    #[test]
    fn refuses_a_plist_format_it_cannot_bound() {
        assert!(matches!(
            Plist::parse(b"{ streams = (); }"),
            Err(PlistError::Decode(_))
        ));
    }

    #[test]
    fn root_must_be_a_dictionary_for_keyed_access() {
        let plist = Plist::parse(b"<?xml version=\"1.0\"?><plist version=\"1.0\"><array/></plist>")
            .unwrap();
        assert!(plist.root_dictionary().is_none());
        assert_eq!(
            plist.get_string("type"),
            Err(PlistError::MissingKey("type"))
        );
    }
}
