// SPDX-License-Identifier: GPL-3.0-or-later
//! Tests for the control plane.
use super::*;

fn request(method: &str, target: &str, cseq: Option<u32>, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut head = format!("{method} {target} RTSP/1.0\r\n");
    if let Some(cseq) = cseq {
        head.push_str(&format!("CSeq: {cseq}\r\n"));
    }
    head.push_str(extra);
    head.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

#[track_caller]
fn respond(session: &mut ControlSession, input: &[u8]) -> ControlResponse {
    match session.handle(input).unwrap() {
        ControlOutcome::Respond(response) => response,
        ControlOutcome::Ignored => panic!("expected a response, got Ignored"),
    }
}

/// Handler that serves `SETUP`, the one route the control layer delegates.
struct SetupHandler;

impl RouteHandler for SetupHandler {
    fn handle(&mut self, route: Route, _request: &RouteRequest<'_>) -> Option<RouteReply> {
        matches!(route, Route::Setup).then(RouteReply::ok)
    }
}

#[track_caller]
fn setup_with_handler(session: &mut ControlSession, input: &[u8]) -> ControlResponse {
    match session.handle_with(input, &mut SetupHandler).unwrap() {
        ControlOutcome::Respond(response) => response,
        ControlOutcome::Ignored => panic!("expected a response, got Ignored"),
    }
}

#[track_caller]
fn assert_header(response: &ControlResponse, name: &str, value: &str) {
    assert_eq!(
        response.header(name),
        Some(value),
        "header {name} in {:?}",
        response.headers
    );
}

#[test]
fn lifecycle_is_observable_and_never_rejects_a_route() {
    let mut session = ControlSession::new();
    let options = respond(&mut session, &request("OPTIONS", "*", Some(1), "", &[]));
    assert_eq!(session.state(), ControlState::New);
    assert_header(&options, "Public", PUBLIC_METHODS);
    assert_header(&options, "Server", SERVER_HEADER_VALUE);
    assert_header(&options, "Audio-Jack-Status", AUDIO_JACK_STATUS);

    // SETUP works on a fresh connection: no ANNOUNCE is required, because
    // the protocol has no ANNOUNCE route at all. The control layer hands this
    // route to a handler, so the session below needs one that serves it.
    let setup = setup_with_handler(
        &mut session,
        &request("SETUP", "/stream", Some(2), "", b"plist"),
    );
    assert_eq!(setup.status, 200);
    assert_eq!(session.state(), ControlState::Setup);

    // OPTIONS stays valid in every state.
    respond(&mut session, &request("OPTIONS", "*", Some(3), "", &[]));
    assert_eq!(session.state(), ControlState::Setup);

    let record = respond(
        &mut session,
        &request("RECORD", "/stream", Some(4), "", &[]),
    );
    assert_eq!(session.state(), ControlState::Recording);
    assert_header(&record, "Audio-Latency", "11025");
    assert_header(&record, "Audio-Jack-Status", AUDIO_JACK_STATUS_RECORD);

    // FLUSH and a repeated SETUP keep the recording state.
    respond(&mut session, &request("FLUSH", "/stream", Some(5), "", &[]));
    assert_eq!(session.state(), ControlState::Recording);
    setup_with_handler(
        &mut session,
        &request("SETUP", "/stream", Some(6), "", b"plist"),
    );
    assert_eq!(session.state(), ControlState::Recording);

    let teardown = respond(
        &mut session,
        &request("TEARDOWN", "/stream", Some(7), "", &[]),
    );
    assert_header(&teardown, "Connection", "close");
    assert_eq!(session.state(), ControlState::Closed);
}

#[test]
fn announce_is_an_extension_that_only_marks_the_state() {
    let mut session = ControlSession::new();
    respond(
        &mut session,
        &request("ANNOUNCE", "/stream", Some(1), "", b"v=0\r\n"),
    );
    assert_eq!(session.state(), ControlState::Announced);
}

#[test]
fn ignores_unusable_and_missing_cseq() {
    let mut session = ControlSession::new();
    // raop.c:247-250: a CSeq that is not a non-negative integer is dropped.
    assert_eq!(
        session
            .handle(b"OPTIONS * RTSP/1.0\r\nCSeq: x\r\n\r\n")
            .unwrap(),
        ControlOutcome::Ignored
    );
    assert_eq!(
        session
            .handle(b"OPTIONS * RTSP/1.0\r\nCSeq: -1\r\n\r\n")
            .unwrap(),
        ControlOutcome::Ignored
    );
    // raop.c:263-266: no CSeq, HLS support off, not a BLE beacon response.
    assert_eq!(
        session.handle(b"OPTIONS * RTSP/1.0\r\n\r\n").unwrap(),
        ControlOutcome::Ignored
    );
    assert_eq!(session.state(), ControlState::New);
}

#[test]
fn ble_beacon_responses_and_hls_requests_take_their_own_paths() {
    let mut session = ControlSession::new();
    // raop.c:257-260: a BLE beacon response has no CSeq but is not dropped.
    let ble = respond(
        &mut session,
        b"GET /info?txtAirPlay RTSP/1.0\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(ble.status, 501);
    assert_header(&ble, "Server", SERVER_HEADER_VALUE);
    assert_eq!(ble.header("CSeq"), None);
    assert_eq!(ble.header("Audio-Jack-Status"), None);

    // raop.c:270 plus raop.c:263-266: without HLS support the same shape of
    // request with a Host header is dropped...
    let mut plain_session = ControlSession::new();
    assert_eq!(
        plain_session
            .handle(b"GET /hls/x.m3u8 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .unwrap(),
        ControlOutcome::Ignored
    );
    // ...and with it enabled the HLS route answers 501 with no Server or
    // CSeq header (raop.c:476-477, raop.c:488).
    session.set_hls_support(true);
    let hls = respond(
        &mut session,
        b"GET /hls/x.m3u8 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    assert_eq!(hls.status, 501);
    assert_eq!(hls.header("Server"), None);
    assert_eq!(hls.header("CSeq"), None);
}

#[test]
fn binds_the_connection_to_one_apple_session_id() {
    let mut session = ControlSession::new();
    let first = respond(
        &mut session,
        &request("OPTIONS", "*", Some(1), "X-Apple-Session-ID: abc\r\n", &[]),
    );
    assert_eq!(session.session_id(), Some("abc"));
    assert_eq!(
        first.header("Session"),
        None,
        "the protocol never sends a Session header"
    );
    respond(
        &mut session,
        &request("OPTIONS", "*", Some(2), "X-Apple-Session-ID: abc\r\n", &[]),
    );
    assert_eq!(
        session.handle(&request(
            "OPTIONS",
            "*",
            Some(3),
            "X-Apple-Session-ID: other\r\n",
            &[]
        )),
        Err(ControlError::SessionMismatch)
    );
    assert_eq!(session.session_id(), Some("abc"));
}

#[test]
fn echoes_the_request_protocol_and_frames_the_body() {
    let mut session = ControlSession::new();
    let response = respond(&mut session, &request("OPTIONS", "*", Some(7), "", &[]));
    let bytes = response.to_bytes();
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.starts_with("RTSP/1.0 200 OK\r\n"));
    // http_response.c:151-168: no body and no Content-Type means no
    // Content-Length at all.
    assert!(!text.contains("Content-Length"), "{text}");
    assert!(text.ends_with("\r\n\r\n"));

    let http = respond(
        &mut session,
        b"OPTIONS * HTTP/1.1\r\nCSeq: 8\r\nContent-Length: 0\r\n\r\n",
    );
    assert!(http.to_bytes().starts_with(b"HTTP/1.1 200 OK\r\n"));

    let mut with_type = ControlResponse::new("RTSP/1.0", 200, "OK");
    with_type
        .headers
        .push(("Content-Type".to_owned(), "text/parameters".to_owned()));
    assert_eq!(
        String::from_utf8(with_type.to_bytes()).unwrap(),
        "RTSP/1.0 200 OK\r\nContent-Type: text/parameters\r\nContent-Length: 0\r\n\r\n"
    );

    let mut with_body = ControlResponse::new("RTSP/1.0", 200, "OK");
    with_body.body = b"hi".to_vec();
    assert_eq!(
        String::from_utf8(with_body.to_bytes()).unwrap(),
        "RTSP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    );
}

#[test]
fn answers_501_for_delegated_routes_and_unknown_methods() {
    let mut session = ControlSession::new();
    for (method, target, version) in [
        ("POST", "/feedback", "RTSP/1.0"),
        ("GET", "/info", "RTSP/1.0"),
        ("PAUSE", "/stream", "RTSP/1.0"),
    ] {
        let input = format!("{method} {target} {version}\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n");
        let response = respond(&mut session, input.as_bytes());
        assert_eq!(response.status, 501, "{method} {target}");
        assert_eq!(response.reason, "Not Implemented");
        assert_header(&response, "Server", SERVER_HEADER_VALUE);
        assert_header(&response, "CSeq", "1");
    }
    // A route that no handler serves must not advance the session either.
    assert_eq!(session.state(), ControlState::New);
}

#[test]
fn answers_the_default_for_unmatched_targets() {
    let mut session = ControlSession::new();
    let response = respond(&mut session, &request("POST", "/unknown", Some(1), "", &[]));
    assert_eq!(response.status, 200);
    assert_eq!(response.reason, "OK");
    assert!(response.body.is_empty());
    assert_header(&response, "Server", SERVER_HEADER_VALUE);
}

#[test]
fn maps_errors_to_status_codes() {
    let parse = ControlError::Parse(ParseError::Invalid("header"));
    assert_eq!(parse.status(), (400, "Bad Request"));
    let head = ControlError::HeadTooLarge {
        declared: 70 * 1024,
        maximum: MAX_CONTROL_BODY,
    };
    assert_eq!(head.status(), (431, "Request Header Fields Too Large"));
    let body = ControlError::BodyTooLarge {
        declared: MAX_CONTROL_BODY + 1,
        maximum: MAX_CONTROL_BODY,
    };
    assert_eq!(body.status(), (400, "Bad Request"));
    assert_eq!(ControlError::SessionMismatch.status(), (400, "Bad Request"));
    // raop.c:236-238 returns before any header is added.
    assert_eq!(
        head.to_response("RTSP/1.0").to_bytes(),
        b"RTSP/1.0 431 Request Header Fields Too Large\r\n\r\n"
    );
}

#[test]
fn rejects_oversized_and_incomplete_requests() {
    let mut session = ControlSession::new();
    let oversized_header = format!(
        "SETUP /stream RTSP/1.0\r\nX: {}\r\n\r\n",
        "a".repeat(70 * 1024)
    );
    assert!(matches!(
        session.handle(oversized_header.as_bytes()),
        Err(ControlError::HeadTooLarge { .. })
    ));

    let oversized_body = format!(
        "SETUP /stream RTSP/1.0\r\nCSeq: 1\r\nContent-Length: {}\r\n\r\n",
        MAX_CONTROL_BODY + 1
    );
    assert!(matches!(
        session.handle(oversized_body.as_bytes()),
        Err(ControlError::BodyTooLarge { .. })
    ));

    // A declared body that never arrived is a parse failure, not a request
    // to act on.
    let truncated = b"SETUP /stream RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 4\r\n\r\nda";
    assert!(matches!(
        session.handle(truncated),
        Err(ControlError::Parse(ParseError::Incomplete))
    ));

    let malformed = b"GET / FTP/1.0\r\n\r\n";
    assert!(matches!(
        session.handle(malformed),
        Err(ControlError::Parse(ParseError::Invalid("start line")))
    ));
}

#[test]
fn audio_latency_follows_the_formula() {
    assert_eq!(audio_latency_samples(DEFAULT_AUDIO_DELAY_MICROS), 11_025);
    assert_eq!(audio_latency_samples(0), 0);
    assert_eq!(audio_latency_samples(MAX_AUDIO_DELAY_MICROS), 441_000);
    // The narrowest possible input still fits: even a saturated delay times
    // the sample rate stays below `u32::MAX`.
    assert_eq!(audio_latency_samples(u32::MAX), 189_408_057);
}

#[test]
fn record_reports_the_configured_audio_delay() {
    let mut session = ControlSession::new();
    session.set_audio_delay_micros(500_000);
    respond(
        &mut session,
        &request("SETUP", "/stream", Some(1), "", b"plist"),
    );
    let record = respond(
        &mut session,
        &request("RECORD", "/stream", Some(2), "", &[]),
    );
    assert_header(&record, "Audio-Latency", "22050");
}
