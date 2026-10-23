// SPDX-License-Identifier: GPL-3.0-or-later
//! Tests for the route handlers.
use super::*;
use crate::wire::{MessageHead, parse_request_head};

/// Parses `method target` plus `extra` headers and `body` the way the control
/// layer does, and returns the head with the body slice the handler sees.
fn parse(method_target: &str, extra: &str, body: &[u8]) -> (MessageHead, Vec<u8>) {
    let mut bytes = format!(
        "{method_target} RTSP/1.0\r\n{extra}Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    let head = parse_request_head(&bytes).unwrap();
    let remaining = bytes[head.consumed..].to_vec();
    (head, remaining)
}

fn info_reply(handlers: &RouteHandlers, head: &MessageHead, body: &[u8]) -> RouteReply {
    handlers.info(&RouteRequest {
        head,
        body,
        peer: None,
    })
}

#[test]
fn info_answers_the_full_device_record() {
    let identity = DeviceIdentity::new("aa:bb:cc:dd:ee:ff", "Test Receiver", vec![7; 32]);
    let handlers = RouteHandlers::new(identity);
    let (head, body) = parse("GET /info", "CSeq: 1\r\n", &[]);
    let reply = info_reply(&handlers, &head, &body);

    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.header("Content-Type"),
        Some("application/x-apple-binary-plist")
    );
    let parsed = Plist::parse(&reply.body).unwrap();
    assert_eq!(parsed.get_string("deviceID").unwrap(), "aa:bb:cc:dd:ee:ff");
    assert_eq!(
        parsed.get_string("macAddress").unwrap(),
        "aa:bb:cc:dd:ee:ff"
    );
    assert_eq!(parsed.get_data("pk").unwrap(), vec![7; 32]);
    assert_eq!(parsed.get_unsigned("features").unwrap(), DEFAULT_FEATURES);
    assert_eq!(parsed.get_unsigned("statusFlags").unwrap(), STATUS_FLAGS);
    assert_eq!(parsed.get_unsigned("keepAliveLowPower").unwrap(), 1);
    assert!(parsed.get_boolean("keepAliveSendStatsAsBody").unwrap());
    assert_eq!(parsed.get_string("sourceVersion").unwrap(), "220.68");
    assert_eq!(parsed.get_array("audioLatencies").unwrap().len(), 2);
    assert_eq!(parsed.get_array("audioFormats").unwrap().len(), 2);
    assert_eq!(parsed.get_array("displays").unwrap().len(), 1);
}

#[test]
fn the_offered_display_comes_from_the_identity() {
    // Upstream's `-s wxh@r`, `-fps` and `-o`: a client reads these from `displays` and
    // sends a mirror stream that matches, so a receiver that offers a smaller picture has
    // to say so here rather than drop frames afterwards.
    let mut identity = DeviceIdentity::new("aa:bb:cc:dd:ee:ff", "Test", Vec::new());
    identity.width = 1280;
    identity.height = 720;
    identity.refresh_rate = 30.0;
    identity.max_fps = 24;
    identity.overscanned = true;
    let handlers = RouteHandlers::new(identity);
    let (head, body) = parse(
        "GET /info",
        "CSeq: 1
",
        &[],
    );
    let reply = info_reply(&handlers, &head, &body);

    let parsed = Plist::parse(&reply.body).unwrap();
    let display = parsed
        .get_dictionary("displays")
        .or_else(|_| {
            parsed
                .get_array("displays")
                .map(|array| array[0].as_dictionary().unwrap())
        })
        .unwrap();
    assert_eq!(
        display.get("width").unwrap().as_unsigned_integer(),
        Some(1280)
    );
    assert_eq!(
        display.get("height").unwrap().as_unsigned_integer(),
        Some(720)
    );
    assert_eq!(
        display.get("widthPixels").unwrap().as_unsigned_integer(),
        Some(1280)
    );
    assert_eq!(
        display.get("heightPixels").unwrap().as_unsigned_integer(),
        Some(720)
    );
    assert_eq!(
        display.get("maxFPS").unwrap().as_unsigned_integer(),
        Some(24)
    );
    assert_eq!(display.get("overscanned").unwrap().as_boolean(), Some(true));
    // The refresh rate is sent as the interval, which is what upstream does.
    let interval = display.get("refreshRate").unwrap().as_real();
    assert!(
        interval.is_some_and(|value| (value - 1.0 / 30.0).abs() < 1e-9),
        "interval {interval:?}"
    );
}

#[test]
fn the_default_display_is_upstreams() {
    let display = super::Display::default();
    assert_eq!(display.width, DEFAULT_WIDTH);
    assert_eq!(display.height, DEFAULT_HEIGHT);
    assert_eq!(display.refresh_rate, DEFAULT_REFRESH_RATE);
    assert_eq!(display.max_fps, DEFAULT_MAX_FPS);
    assert!(!display.overscanned);
}

#[test]
fn the_advertised_features_are_the_identitys() {
    // Bit 42 is what allows HEVC video, and it is the bit upstream's `-h265` sets. A
    // caller that turns it on has to see it in every place a client reads features.
    let mut identity = DeviceIdentity::new("aa:bb:cc:dd:ee:ff", "Test", Vec::new());
    identity.features |= 1 << 42;
    let handlers = RouteHandlers::new(identity.clone());
    let (head, body) = parse(
        "GET /info",
        "CSeq: 1
",
        &[],
    );
    let reply = info_reply(&handlers, &head, &body);
    let parsed = Plist::parse(&reply.body).unwrap();
    assert_eq!(
        parsed.get_unsigned("features").unwrap(),
        DEFAULT_FEATURES | (1 << 42)
    );
    assert_eq!(identity.features, DEFAULT_FEATURES | (1 << 42));
}

#[test]
fn a_blocked_client_is_never_admitted() {
    let policy = super::ClientPolicy {
        restrict: true,
        allow: vec!["aa:bb:cc:dd:ee:ff".to_owned()],
        block: vec!["aa:bb:cc:dd:ee:ff".to_owned()],
    };
    let client = super::ClientRequest {
        device_id: "aa:bb:cc:dd:ee:ff".to_owned(),
        model: "iPad".to_owned(),
        name: "Test".to_owned(),
    };
    assert!(
        !policy.admits(&client),
        "a block wins over an allow: the narrower permission is the safer reading"
    );
}

#[test]
fn a_restrict_policy_admits_only_what_it_lists() {
    let policy = super::ClientPolicy {
        restrict: true,
        allow: vec!["aa:bb:cc:dd:ee:ff".to_owned()],
        block: Vec::new(),
    };
    let admitted = super::ClientRequest {
        device_id: "aa:bb:cc:dd:ee:ff".to_owned(),
        model: String::new(),
        name: String::new(),
    };
    let refused = super::ClientRequest {
        device_id: "11:22:33:44:55:66".to_owned(),
        ..admitted.clone()
    };
    assert!(policy.admits(&admitted));
    assert!(!policy.admits(&refused));
    // Without restrict, a policy with no block list admits everything.
    let open = super::ClientPolicy::default();
    assert!(open.admits(&refused));
}

#[test]
fn a_refused_client_gets_403_before_any_key_is_derived() {
    // Upstream drops the connection when its callback refuses; a client deserves an answer
    // that says so. The body here is a mirror-only SETUP, which needs no keys, so the
    // refusal is the only thing that can decide the reply.
    let mut handlers = RouteHandlers::new(DeviceIdentity::default());
    handlers.set_client_policy(super::ClientPolicy {
        restrict: true,
        allow: Vec::new(),
        block: vec!["aa:bb:cc:dd:ee:ff".to_owned()],
    });
    let mut request_body = plist::Dictionary::new();
    request_body.insert(
        "deviceID".to_owned(),
        plist::Value::from("aa:bb:cc:dd:ee:ff"),
    );
    request_body.insert("model".to_owned(), plist::Value::from("iPad"));
    request_body.insert("name".to_owned(), plist::Value::from("Test"));
    let encoded = Plist::from_value(plist::Value::Dictionary(request_body))
        .encode_binary()
        .unwrap();
    let (head, body) = parse(
        "SETUP /stream",
        "CSeq: 1
Content-Type: application/x-apple-binary-plist
",
        &encoded,
    );
    let reply = handlers.setup(&RouteRequest {
        head: &head,
        body: &body,
        peer: None,
    });
    assert_eq!(reply.status, 403);
}

#[test]
fn info_answers_only_the_requested_txt_record() {
    let mut identity = DeviceIdentity::new("aa:bb:cc:dd:ee:ff", "Test", Vec::new());
    identity.txt_airplay = Some(b"txt".to_vec());
    let handlers = RouteHandlers::new(identity);

    let mut request_value = plist::Dictionary::new();
    request_value.insert(
        "qualifier".to_owned(),
        plist::Value::Array(vec!["txtAirPlay".into()]),
    );
    let body = Plist::from_value(plist::Value::Dictionary(request_value))
        .encode_binary()
        .unwrap();
    let (head, body) = parse(
        "GET /info",
        "CSeq: 1\r\nContent-Type: application/x-apple-binary-plist\r\n",
        &body,
    );
    let reply = info_reply(&handlers, &head, &body);

    let parsed = Plist::parse(&reply.body).unwrap();
    assert_eq!(parsed.get_data("txtAirPlay").unwrap(), b"txt");
    assert!(!parsed.has_key("deviceID"));
}

#[test]
fn bluetooth_le_info_omits_the_session_values() {
    let handlers = RouteHandlers::new(DeviceIdentity::default());
    let (head, body) = parse("GET /info?txtAirPlay", "", &[]);
    let reply = info_reply(&handlers, &head, &body);

    let parsed = Plist::parse(&reply.body).unwrap();
    assert!(parsed.has_key("txtAirPlay"));
    assert!(parsed.has_key("model"));
    assert!(!parsed.has_key("initialVolume"));
    assert!(!parsed.has_key("displays"));
}

#[test]
fn fairplay_setup_rejects_unknown_versions_and_lengths() {
    let mut handlers = RouteHandlers::new(DeviceIdentity::default());

    let (head, body) = parse("POST /fp-setup", "CSeq: 1\r\n", &[0; SETUP_REQUEST_LEN]);
    let rejected = handlers.fairplay_setup(&RouteRequest {
        head: &head,
        body: &body,
        peer: None,
    });
    // Version byte 4 is 0, which is not the FairPlay version upstream accepts.
    assert_eq!(rejected.status, 501);

    let (head, body) = parse("POST /fp-setup", "CSeq: 1\r\n", &[0; 5]);
    let ignored = handlers.fairplay_setup(&RouteRequest {
        head: &head,
        body: &body,
        peer: None,
    });
    assert_eq!(ignored.status, 200);
    assert!(ignored.body.is_empty());
}

#[test]
fn reads_the_mirror_identifier_a_device_actually_sent() {
    // A real session sent this, and refusing it cost the whole video stream:
    // `streamConnectionID` as a *signed* 64-bit number, negative because its high bit
    // is set. Upstream prints it with `%llu` (`raop_handlers.h:963`), so those same
    // bits are the identifier, and the keys are derived from their decimal form.
    let mut stream = plist::Dictionary::new();
    stream.insert("type".to_owned(), 110u64.into());
    stream.insert(
        "streamConnectionID".to_owned(),
        plist::Value::from(-4_578_581_632_668_906_207i64),
    );
    assert_eq!(
        super::stream_connection_id(&stream),
        Some(0xc075_9c43_71a4_4d21),
        "the bits are the identifier, not the signed value"
    );
    // The decimal form is what the key derivation hashes, so the round trip matters:
    // a port that hashed `-4578...` would derive a stream the client cannot read.
    assert_eq!(
        super::stream_connection_id(&stream).unwrap().to_string(),
        "13868162441040645409"
    );
}

#[test]
fn reads_a_positive_or_fractional_identifier_the_way_a_client_wrote_it() {
    let identifier = |value: plist::Value| {
        let mut stream = plist::Dictionary::new();
        stream.insert("streamConnectionID".to_owned(), value);
        super::stream_connection_id(&stream)
    };
    // The shape most sessions send.
    assert_eq!(
        identifier(plist::Value::from(10_139_102_790_113_880_880_u64)),
        Some(10_139_102_790_113_880_880_u64)
    );
    // A real that is whole is a way of writing the same number.
    assert_eq!(identifier(plist::Value::from(4096.0f64)), Some(4096));
    // One that is not whole would derive a stream nobody can read, so it is refused
    // rather than rounded.
    assert_eq!(identifier(plist::Value::from(4096.5f64)), None);
    assert_eq!(identifier(plist::Value::from(f64::NAN)), None);
    // An entry with no identifier at all is `None`, which is what a client that has
    // not named its stream sends.
    let mut bare = plist::Dictionary::new();
    bare.insert("type".to_owned(), 110u64.into());
    assert_eq!(super::stream_connection_id(&bare), None);
}
