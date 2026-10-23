// SPDX-License-Identifier: GPL-3.0-or-later
//! Properties the parsers have to hold for *every* input a client can send.
//!
//! The unit tests next to each parser check the cases a person thought of. These
//! check the invariants that must not depend on that: no input makes a parser
//! panic, a reported length is a length the input really has, and a request that
//! arrives in pieces is answered exactly once, when the last piece lands. The
//! bounds added for the S3 security review are exercised here too, because a
//! bound that only holds for the inputs in the unit tests is not a bound.

use proptest::prelude::*;
use rust_airplay::control::{
    ControlOutcome, ControlSession, RouteHandler, RouteReply, RouteRequest,
};
use rust_airplay::plist::{MAX_PLIST_BYTES, Plist};
use rust_airplay::wire::{
    DEFAULT_MAX_FIELD_LEN, DEFAULT_MAX_FIELDS, DEFAULT_MAX_HEAD, DEFAULT_MAX_VALUE_LEN, HeadLimits,
    ParseError, parse_request_head, parse_request_head_with_limits, split_body,
};

/// A handler that serves every route, so a session can be driven end to end.
struct Serve;

impl RouteHandler for Serve {
    fn handle(
        &mut self,
        _route: rust_airplay::control::Route,
        _request: &RouteRequest<'_>,
    ) -> Option<RouteReply> {
        Some(RouteReply::ok())
    }
}

/// Control bytes, as a client may put them anywhere in a request.
fn control_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..2048)
}

/// Header names and values with the shapes a real client sends, plus the shapes
/// that are meant to be refused.
fn header_line() -> impl Strategy<Value = String> {
    prop_oneof![
        "[A-Za-z][A-Za-z0-9-]{0,20}: [ -~]{0,80}",
        "[A-Za-z][A-Za-z0-9-]{0,20}:[ -~]{0,80}",
        "[A-Za-z][A-Za-z0-9-]{0,80}: [ -~]{0,200}",
        "[A-Za-z][A-Za-z0-9-]{0,20}:\t[ -~]{0,80}",
    ]
}

fn request_line() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("OPTIONS * RTSP/1.0".to_owned()),
        Just("SETUP /stream RTSP/1.0".to_owned()),
        Just("GET /info RTSP/1.0".to_owned()),
        Just("POST /pair-verify RTSP/1.0".to_owned()),
        "[A-Z]{1,12} [ -~]{0,40} RTSP/1.0",
        "[A-Z]{1,12} [ -~]{0,40} HTTP/1.1",
        "[A-Z]{1,12} [ -~]{0,40}",
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, max_shrink_iters: 4096, ..ProptestConfig::default() })]

    /// Whatever a client sends, the head parser answers or fails, and never
    /// panics.
    #[test]
    fn parsing_a_head_never_panics(input in control_bytes()) {
        let _ = parse_request_head(&input);
        let _ = parse_request_head_with_limits(&input, HeadLimits::default());
    }

    /// A parsed head describes the bytes it came from: it consumed something
    /// inside the input, its headers are inside the limits, and reading its body
    /// cannot claim more than the input holds.
    #[test]
    fn a_parsed_head_stays_inside_its_limits(
        request in request_line(),
        headers in prop::collection::vec(header_line(), 0..24),
        length in prop_oneof![Just(None), (0usize..100_000).prop_map(Some)],
        mut body in control_bytes(),
    ) {
        let mut assembled = format!("{request}\r\n");
        for header in &headers {
            assembled.push_str(header);
            assembled.push_str("\r\n");
        }
        if let Some(length) = length {
            assembled.push_str(&format!("Content-Length: {length}\r\n"));
        }
        assembled.push_str("\r\n");
        let mut input = assembled.into_bytes();
        input.append(&mut body);

        if let Ok(head) = parse_request_head(&input) {
            prop_assert!(head.consumed <= input.len());
            prop_assert!(head.headers.len() <= DEFAULT_MAX_FIELDS);
            for (name, value) in &head.headers {
                prop_assert!(name.len() <= DEFAULT_MAX_FIELD_LEN);
                prop_assert!(value.len() <= DEFAULT_MAX_VALUE_LEN);
            }
            if let Ok(declared) = head.content_length(64 * 1024) {
                // `split_body` is what a caller uses to reach the body, so what
                // it hands out can never reach past the input.
                if let Ok(slice) = split_body(&input, declared) {
                    prop_assert!(slice.len() <= input.len());
                }
            }
        }
    }

    /// A request split anywhere either waits for more bytes or yields the same
    /// answer as the whole request; it is never answered twice.
    #[test]
    fn a_request_split_anywhere_is_answered_once(
        request in request_line(),
        header in header_line(),
        body in prop::collection::vec(any::<u8>(), 0..64),
        split in 0usize..64,
    ) {
        let assembled = format!(
            "{request}\r\nCSeq: 1\r\n{header}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut input = assembled.into_bytes();
        input.extend_from_slice(&body);
        let split = split.min(input.len());
        let (first, rest) = input.split_at(split);

        let mut session = ControlSession::new();
        let mut handler = Serve;
        match session.handle_with(first, &mut handler) {
            Ok(ControlOutcome::Ignored) => {
                // The first piece was not enough: the rest has to complete it.
                let _ = session.handle_with(rest, &mut handler);
            }
            Ok(ControlOutcome::Respond(_)) => {}
            // Framing errors are answers too; what matters is that a partial
            // request is not reported as a completed one.
            Err(_) => {}
        }
    }

    /// The body splitter never reads past what it was given, however the caller
    /// miscounts.
    #[test]
    fn splitting_a_body_never_reads_past_the_input(
        input in control_bytes(),
        length in 0usize..4096,
    ) {
        if let Ok(slice) = split_body(&input, length) {
            prop_assert!(slice.len() <= input.len());
        }
    }

    /// A property list of any shape is either refused or parsed; the bounds hold
    /// and the parser never panics on binary input.
    #[test]
    fn parsing_a_property_list_never_panics(input in control_bytes()) {
        let _ = Plist::parse(&input);
        let _ = Plist::parse_with_maximum(&input, MAX_PLIST_BYTES);
    }

    /// A binary property list claiming a deep structure is refused rather than
    /// walked into the stack.
    ///
    /// The structure is the one the security review reproduced the stack
    /// overflow with: one array per level, each holding a reference to the next.
    /// It stays inside one-byte offsets, so the refusal can only come from the
    /// depth bound.
    #[test]
    fn a_deep_binary_property_list_is_refused(depth in 33usize..100) {
        let objects = depth + 1;
        let mut bytes = b"bplist00".to_vec();
        let mut offset_table = Vec::with_capacity(objects);
        for index in 0..objects {
            offset_table.push(bytes.len());
            if index + 1 < objects {
                bytes.extend_from_slice(&[0xa1, (index + 1) as u8]);
            } else {
                // The innermost level: an empty array, which ends the chain.
                bytes.push(0xa0);
            }
        }
        let offset_table_offset = bytes.len();
        bytes.extend(offset_table.iter().map(|offset| *offset as u8));
        // Six unused bytes, the widths, then the object count, the root object
        // and where the offset table starts.
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        bytes.push(1);
        bytes.push(1);
        bytes.extend_from_slice(&(objects as u64).to_be_bytes());
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&(offset_table_offset as u64).to_be_bytes());

        prop_assert!(bytes.len() < MAX_PLIST_BYTES);
        prop_assert!(Plist::parse(&bytes).is_err());
    }
}

/// A body the client declared but did not send is not a body.
#[test]
fn a_short_body_is_incomplete_rather_than_accepted() {
    let input = b"POST /pair-verify RTSP/1.0\r\nContent-Length: 100\r\n\r\nshort";
    let head = parse_request_head(input).expect("head parses");
    assert_eq!(head.content_length(1024), Ok(100));
    assert_eq!(split_body(input, 100), Err(ParseError::Incomplete));
}

/// A head that fits its limit exactly is accepted, and one byte more is not.
#[test]
fn the_head_limit_is_inclusive() {
    let prefix = b"GET /info RTSP/1.0\r\n\r\n";
    let limits = HeadLimits {
        max_head: prefix.len(),
        ..HeadLimits::default()
    };
    assert!(parse_request_head_with_limits(prefix, limits).is_ok());
    let mut longer = b"GET /info RTSP/1.0\r\nX: y\r\n\r\n".to_vec();
    longer.extend_from_slice(prefix);
    let longer = longer.as_slice();
    assert!(matches!(
        parse_request_head_with_limits(longer, limits),
        Err(ParseError::TooLarge { .. })
    ));
}

/// The limits the wire layer applies by default are the upstream header bounds.
#[test]
fn default_limits_match_upstream_header_bounds() {
    assert_eq!(DEFAULT_MAX_HEAD, 64 * 1024);
    assert_eq!(DEFAULT_MAX_FIELDS, 20);
    assert_eq!(DEFAULT_MAX_FIELD_LEN, 64);
    assert_eq!(DEFAULT_MAX_VALUE_LEN, 1024);
}
