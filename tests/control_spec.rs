// SPDX-License-Identifier: GPL-3.0-or-later
//! The control-plane specification.
//!
//! The tables below pin the observable control-plane contract: route selection and the HLS and
//! BLE-beacon rules; requests that get no response; the `Public` header; response headers
//! (`Audio-Latency`, the analog jack status, `Connection: close`); framing and protocol echo;
//! session binding; and the status codes (`200`, `400`, `404`, `431`, `501`).

use rust_airplay::control::{
    AUDIO_JACK_STATUS, AUDIO_JACK_STATUS_RECORD, ControlError, ControlOutcome, ControlResponse,
    ControlSession, ControlState, DEFAULT_AUDIO_DELAY_MICROS, Dispatch, PUBLIC_METHODS,
    RequestFacts, Route, SERVER_HEADER_VALUE, audio_latency_samples, dispatch,
};
use rust_airplay::wire::{DEFAULT_MAX_HEAD, ParseError, parse_request_head};

fn facts<'a>(method: &'a str, target: &'a str, version: &'a str) -> RequestFacts<'a> {
    RequestFacts {
        method,
        target,
        version,
        has_cseq: true,
        has_host: false,
        has_session_id: false,
    }
}

fn request(method: &str, target: &str, version: &str, cseq: u32, extra: &str) -> Vec<u8> {
    format!("{method} {target} {version}\r\nCSeq: {cseq}\r\n{extra}Content-Length: 0\r\n\r\n")
        .into_bytes()
}

fn with_body(method: &str, target: &str, version: &str, cseq: u32, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "{method} {target} {version}\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
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

#[track_caller]
fn assert_header(response: &ControlResponse, name: &str, value: &str) {
    assert!(
        response
            .headers
            .iter()
            .any(|(header, found)| header == name && found == value),
        "missing header {name}: {value} in {:?}",
        response.headers
    );
}

#[test]
fn route_table_matches() {
    use Dispatch::{Delegated, Local, Unhandled, UnknownRtspMethod};
    let cases: &[(&str, &str, &str, Dispatch)] = &[
        // RTSP/1.0 `POST` handlers.
        ("POST", "/feedback", "RTSP/1.0", Delegated(Route::Feedback)),
        (
            "POST",
            "/pair-pin-start",
            "RTSP/1.0",
            Delegated(Route::PairPinStart),
        ),
        (
            "POST",
            "/pair-setup-pin",
            "RTSP/1.0",
            Delegated(Route::PairSetupPin),
        ),
        (
            "POST",
            "/pair-setup",
            "RTSP/1.0",
            Delegated(Route::PairSetup),
        ),
        (
            "POST",
            "/pair-verify",
            "RTSP/1.0",
            Delegated(Route::PairVerify),
        ),
        (
            "POST",
            "/fp-setup",
            "RTSP/1.0",
            Delegated(Route::FairPlaySetup),
        ),
        (
            "POST",
            "/audioMode",
            "RTSP/1.0",
            Delegated(Route::AudioMode),
        ),
        // RTSP/1.0 `GET`: the protocol matches the URL with `strstr`.
        ("GET", "/info", "RTSP/1.0", Delegated(Route::Info)),
        ("GET", "/info?x=1", "RTSP/1.0", Delegated(Route::Info)),
        ("GET", "/other", "RTSP/1.0", Unhandled),
        // RTSP/1.0 method-only handlers. SETUP carries the
        // session's key material, so the control layer hands it to a handler.
        ("OPTIONS", "*", "RTSP/1.0", Local(Route::Options)),
        (
            "SETUP",
            "rtsp://host/stream",
            "RTSP/1.0",
            Delegated(Route::Setup),
        ),
        (
            "GET_PARAMETER",
            "/stream",
            "RTSP/1.0",
            Delegated(Route::GetParameter),
        ),
        (
            "SET_PARAMETER",
            "/stream",
            "RTSP/1.0",
            Delegated(Route::SetParameter),
        ),
        ("RECORD", "/stream", "RTSP/1.0", Local(Route::Record)),
        ("FLUSH", "/stream", "RTSP/1.0", Local(Route::Flush)),
        ("TEARDOWN", "/stream", "RTSP/1.0", Local(Route::Teardown)),
        // Documented extension: the protocol has no ANNOUNCE route at all.
        ("ANNOUNCE", "/stream", "RTSP/1.0", Local(Route::Announce)),
        // Unknown RTSP method: raop.c:442-444 answers 501.
        ("PAUSE", "/stream", "RTSP/1.0", UnknownRtspMethod),
        // HTTP/1.1 POST handlers.
        ("POST", "/reverse", "HTTP/1.1", Delegated(Route::Reverse)),
        ("POST", "/play", "HTTP/1.1", Delegated(Route::Play)),
        (
            "POST",
            "/getProperty?key=x",
            "HTTP/1.1",
            Delegated(Route::GetProperty),
        ),
        (
            "POST",
            "/scrub?position=1",
            "HTTP/1.1",
            Delegated(Route::Scrub),
        ),
        ("POST", "/rate?value=1", "HTTP/1.1", Delegated(Route::Rate)),
        ("POST", "/stop", "HTTP/1.1", Delegated(Route::Stop)),
        ("POST", "/action", "HTTP/1.1", Delegated(Route::Action)),
        (
            "POST",
            "/fp-setup2",
            "HTTP/1.1",
            Delegated(Route::FairPlaySetup2),
        ),
        // HTTP/1.1 GET and PUT handlers.
        (
            "GET",
            "/server-info",
            "HTTP/1.1",
            Delegated(Route::ServerInfo),
        ),
        (
            "GET",
            "/playback-info",
            "HTTP/1.1",
            Delegated(Route::PlaybackInfo),
        ),
        (
            "PUT",
            "/setProperty?x=1",
            "HTTP/1.1",
            Delegated(Route::SetProperty),
        ),
        // No handler selected: the protocol keeps its default 200.
        ("POST", "/unknown", "HTTP/1.1", Unhandled),
        ("PATCH", "/reverse", "HTTP/1.1", Unhandled),
        // The HTTP/1.1 table has no `/info` route.
        ("GET", "/info", "HTTP/1.1", Unhandled),
        // The protocol compares the protocol string exactly (raop.c:406, 445).
        ("POST", "/feedback", "RTSP/2.0", Unhandled),
    ];
    for (method, target, version, expected) in cases {
        assert_eq!(
            dispatch(&facts(method, target, version)),
            *expected,
            "{method} {target} {version}"
        );
    }
}

#[test]
fn hls_rule_precedes_both_protocol_tables() {
    let hls = RequestFacts {
        method: "GET",
        target: "/hls/playlist.m3u8",
        version: "HTTP/1.1",
        has_cseq: false,
        has_host: true,
        has_session_id: false,
    };
    assert_eq!(dispatch(&hls), Dispatch::Delegated(Route::Hls));

    // CSeq or an Apple session id keeps the request on the normal tables.
    let with_cseq = RequestFacts {
        has_cseq: true,
        ..hls
    };
    assert_eq!(dispatch(&with_cseq), Dispatch::Unhandled);
    let with_session = RequestFacts {
        has_session_id: true,
        ..hls
    };
    assert_eq!(dispatch(&with_session), Dispatch::Unhandled);
}

#[test]
fn request_facts_come_from_the_parsed_head() {
    let head = parse_request_head(
        b"GET /info RTSP/1.0\r\nCSeq: 1\r\nX-Apple-Session-ID: abc\r\nContent-Length: 0\r\n\r\n",
    )
    .unwrap();
    let facts = RequestFacts::from_head(&head);
    assert!(facts.has_cseq && facts.has_session_id);
    assert!(!facts.has_host);
    assert!(!facts.is_hls_request());
    assert!(!facts.is_ble_beacon_response());
    assert_eq!(dispatch(&facts), Dispatch::Delegated(Route::Info));

    let hls = parse_request_head(b"GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
    let facts = RequestFacts::from_head(&hls);
    assert!(facts.is_hls_request());
    assert_eq!(dispatch(&facts), Dispatch::Delegated(Route::Hls));

    // raop.c:257-260: only a CSeq-less RTSP/1.0 request that mentions
    // txtAirPlay/txtRAOP is a BLE beacon response.
    let ble = parse_request_head(b"GET /info?txtAirPlay HTTP/1.0\r\n\r\n").unwrap();
    assert!(!RequestFacts::from_head(&ble).is_ble_beacon_response());
    let ble = parse_request_head(b"GET /info?txtRAOP RTSP/1.0\r\n\r\n").unwrap();
    assert!(RequestFacts::from_head(&ble).is_ble_beacon_response());
}

#[test]
fn announce_is_an_unadvertised_extension() {
    assert!(!PUBLIC_METHODS.contains("ANNOUNCE"));
    assert_eq!(
        dispatch(&facts("ANNOUNCE", "/stream", "RTSP/1.0")),
        Dispatch::Local(Route::Announce)
    );
}

#[test]
fn options_response_pins_public_headers() {
    let mut session = ControlSession::new();
    let response = respond(&mut session, &request("OPTIONS", "*", "RTSP/1.0", 7, ""));
    assert_eq!(response.status, 200);
    assert_header(&response, "CSeq", "7");
    assert_header(&response, "Server", SERVER_HEADER_VALUE);
    assert_header(&response, "Audio-Jack-Status", AUDIO_JACK_STATUS);
    assert_header(&response, "Public", PUBLIC_METHODS);
    assert_eq!(response.protocol, "RTSP/1.0");
    // the protocol never sends or reads a `Session` header.
    assert_eq!(response.header("Session"), None);
}

#[test]
fn record_response_uses_the_analog_jack_status_and_reports_latency() {
    let mut session = ControlSession::new();
    // No ANNOUNCE: the protocol has no route for it, so SETUP may follow on a fresh
    // connection. This session has no handler, and the server tests cover the
    // route itself.
    respond(
        &mut session,
        &with_body("SETUP", "/stream", "RTSP/1.0", 2, b"tp"),
    );
    let response = respond(
        &mut session,
        &request("RECORD", "/stream", "RTSP/1.0", 3, ""),
    );
    assert_eq!(response.status, 200);
    assert_header(&response, "Audio-Jack-Status", AUDIO_JACK_STATUS_RECORD);
    assert_eq!(
        audio_latency_samples(DEFAULT_AUDIO_DELAY_MICROS).to_string(),
        "11025"
    );
    assert_header(&response, "Audio-Latency", "11025");
    assert!(
        !response
            .headers
            .iter()
            .any(|(_, value)| value == AUDIO_JACK_STATUS)
    );
    assert_eq!(session.state(), ControlState::New);
}
#[test]
fn options_and_setup_are_never_rejected_by_state() {
    let mut session = ControlSession::new();
    // SETUP first, then OPTIONS, then a second SETUP: the protocol's routing layer
    // has no state gate.
    for (method, target, cseq) in [
        ("SETUP", "/stream", 1),
        ("OPTIONS", "*", 2),
        ("SETUP", "/stream", 3),
        ("FLUSH", "/stream", 4),
        ("OPTIONS", "*", 5),
    ] {
        let response = respond(&mut session, &request(method, target, "RTSP/1.0", cseq, ""));
        // SETUP and FLUSH are served by handlers, and this session has none, so their
        // answers are `501` rather than rejections by state; the server tests cover the
        // routes themselves. OPTIONS needs no handler and is always served.
        let expected = if method == "SETUP" || method == "FLUSH" {
            501
        } else {
            200
        };
        assert_eq!(response.status, expected, "{method} #{cseq}");
    }
    assert_eq!(session.state(), ControlState::New);
}

#[test]
fn requests_without_a_usable_cseq_get_no_response() {
    // raop.c:263-266: no CSeq, HLS support off, not a BLE beacon response.
    let mut session = ControlSession::new();
    assert_eq!(
        session
            .handle(b"OPTIONS * RTSP/1.0\r\nContent-Length: 0\r\n\r\n")
            .unwrap(),
        ControlOutcome::Ignored
    );
    // raop.c:247-250: a CSeq that is not a non-negative integer is dropped too.
    assert_eq!(
        session
            .handle(b"OPTIONS * RTSP/1.0\r\nCSeq: nope\r\nContent-Length: 0\r\n\r\n")
            .unwrap(),
        ControlOutcome::Ignored
    );
    assert_eq!(session.state(), ControlState::New);

    // raop.c:257-260: a BLE beacon response is answered even without HLS.
    let response = respond(
        &mut session,
        b"GET /info?txtAirPlay RTSP/1.0\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(response.status, 501);
    assert_eq!(response.header("CSeq"), None);
    assert_eq!(response.header("Audio-Jack-Status"), None);
}

#[test]
fn hls_requests_are_dropped_unless_hls_support_is_enabled() {
    let mut session = ControlSession::new();
    let hls = b"GET /hls/playlist.m3u8 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    assert_eq!(session.handle(hls).unwrap(), ControlOutcome::Ignored);

    session.set_hls_support(true);
    let response = respond(&mut session, hls);
    assert_eq!(response.status, 501);
    // raop.c:488: an HLS response carries neither `Server` nor `CSeq`.
    assert_eq!(response.header("Server"), None);
    assert_eq!(response.header("CSeq"), None);
}

#[test]
fn the_connection_binds_the_first_apple_session_id_it_sees() {
    let mut session = ControlSession::new();
    assert_eq!(session.session_id(), None);
    respond(
        &mut session,
        &request(
            "SETUP",
            "/stream",
            "RTSP/1.0",
            1,
            "X-Apple-Session-ID: 5A1B\r\n",
        ),
    );
    assert_eq!(session.session_id(), Some("5A1B"));
    // The same id on a later request is fine.
    respond(
        &mut session,
        &request(
            "RECORD",
            "/stream",
            "RTSP/1.0",
            2,
            "X-Apple-Session-ID: 5A1B\r\n",
        ),
    );
    // raop.c:400-402 asserts equality; the port answers 400 instead of aborting.
    let error = session
        .handle(&request(
            "FLUSH",
            "/stream",
            "RTSP/1.0",
            3,
            "X-Apple-Session-ID: other\r\n",
        ))
        .unwrap_err();
    assert_eq!(error, ControlError::SessionMismatch);
    assert_eq!(error.status(), (400, "Bad Request"));
    assert_eq!(
        error.to_response("RTSP/1.0").to_bytes(),
        b"RTSP/1.0 400 Bad Request\r\n\r\n".to_vec()
    );
    assert_eq!(session.session_id(), Some("5A1B"));
}

#[test]
fn status_line_echoes_the_request_protocol() {
    let mut session = ControlSession::new();
    let http = respond(&mut session, &request("POST", "/stop", "HTTP/1.1", 1, ""));
    assert_eq!(http.protocol, "HTTP/1.1");
    let bytes = http.to_bytes();
    assert!(bytes.starts_with(b"HTTP/1.1 501 Not Implemented\r\n"));
}

#[test]
fn unported_and_unknown_routes_answer_501() {
    let mut session = ControlSession::new();
    for (method, target) in [
        ("POST", "/feedback"),
        ("GET", "/info"),
        ("PAUSE", "/stream"),
    ] {
        let response = respond(&mut session, &request(method, target, "RTSP/1.0", 1, ""));
        assert_eq!(response.status, 501, "{method} {target}");
        assert_eq!(response.reason, "Not Implemented");
        assert_header(&response, "Server", SERVER_HEADER_VALUE);
    }
    // A route that is not implemented must not advance the session either.
    assert_eq!(session.state(), ControlState::New);
}

#[test]
fn teardown_closes_the_connection() {
    let mut session = ControlSession::new();
    respond(
        &mut session,
        &request("SETUP", "/stream", "RTSP/1.0", 1, ""),
    );
    let response = respond(
        &mut session,
        &request("TEARDOWN", "/stream", "RTSP/1.0", 2, ""),
    );
    assert_eq!(response.status, 200);
    assert_header(&response, "Connection", "close");
    assert_eq!(session.state(), ControlState::Closed);
}

#[test]
fn only_bodies_and_content_type_get_a_content_length() {
    // http_response.c:131-170.
    let mut session = ControlSession::new();
    let bare = respond(&mut session, &request("OPTIONS", "*", "RTSP/1.0", 1, ""));
    let text = String::from_utf8(bare.to_bytes()).unwrap();
    assert!(!text.contains("Content-Length"), "{text}");
    assert!(text.ends_with("\r\n\r\n"), "{text}");

    let mut typed = ControlResponse::new("RTSP/1.0", 200, "OK");
    typed
        .headers
        .push(("Content-Type".to_owned(), "text/parameters".to_owned()));
    assert_eq!(
        String::from_utf8(typed.to_bytes()).unwrap(),
        "RTSP/1.0 200 OK\r\nContent-Type: text/parameters\r\nContent-Length: 0\r\n\r\n"
    );

    let mut bodied = ControlResponse::new("RTSP/1.0", 200, "OK");
    bodied.body = b"volume: 0.000000\r\n".to_vec();
    assert_eq!(
        String::from_utf8(bodied.to_bytes()).unwrap(),
        "RTSP/1.0 200 OK\r\nContent-Length: 18\r\n\r\nvolume: 0.000000\r\n"
    );
}

#[test]
fn rejections_use_bare_status_codes() {
    let mut session = ControlSession::new();
    let oversized_header = format!(
        "SETUP /stream RTSP/1.0\r\nCSeq: 1\r\nX: {}\r\n\r\n",
        "a".repeat(DEFAULT_MAX_HEAD)
    );
    let error = session.handle(oversized_header.as_bytes()).unwrap_err();
    assert_eq!(error.status(), (431, "Request Header Fields Too Large"));
    // raop.c:236-238 returns before `Server`, `CSeq` or `Audio-Jack-Status`.
    assert_eq!(
        error.to_response("RTSP/1.0").to_bytes(),
        b"RTSP/1.0 431 Request Header Fields Too Large\r\n\r\n".to_vec()
    );

    let malformed = session.handle(b"SETUP /stream\r\n\r\n").unwrap_err();
    assert!(matches!(malformed, ControlError::Parse(_)));
    assert_eq!(malformed.status(), (400, "Bad Request"));

    let truncated = session
        .handle(b"SETUP /stream RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 9\r\n\r\nshort")
        .unwrap_err();
    assert_eq!(truncated, ControlError::Parse(ParseError::Incomplete));
}
