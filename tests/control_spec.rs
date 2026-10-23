// SPDX-License-Identifier: GPL-3.0-or-later
//! Upstream control-plane specification.
//!
//! These tables pin the observable control-plane contract to
//! `upstream/UxPlay@517cbb1240d9b9f69330c55b957cdd52b4175b2a`:
//!
//! - route selection: `upstream/UxPlay/lib/raop.c:406-478`, plus the HLS rule at
//!   `upstream/UxPlay/lib/raop.c:270` and the BLE beacon rule at
//!   `upstream/UxPlay/lib/raop.c:257-260`;
//! - requests that get no response at all: `upstream/UxPlay/lib/raop.c:247-250`
//!   (unusable `CSeq`) and `upstream/UxPlay/lib/raop.c:263-266` (no `CSeq`);
//! - `Public` header: `upstream/UxPlay/lib/raop_handlers.h:596`;
//! - response headers: `upstream/UxPlay/lib/raop.c:338-340`,
//!   `upstream/UxPlay/lib/raop.c:488-492`,
//!   `upstream/UxPlay/lib/raop_handlers.h:1225-1226` (`Audio-Latency` and the
//!   analog jack status), `upstream/UxPlay/lib/raop_handlers.h:1284`
//!   (`Connection: close`);
//! - response framing and protocol echo: `upstream/UxPlay/lib/http_response.c:71-91`
//!   and `:131-170`;
//! - session binding: `upstream/UxPlay/lib/raop.c:268-270` and `:400-402`;
//! - status codes: `upstream/UxPlay/lib/raop.c:335` (default `200`),
//!   `upstream/UxPlay/lib/raop.c:237` (`431`), `upstream/UxPlay/lib/raop.c:442-444`
//!   and `upstream/UxPlay/lib/raop_handlers.h:558` (`501`),
//!   `upstream/UxPlay/lib/http_handlers.h:657` and `:891` (`400`),
//!   `upstream/UxPlay/lib/http_handlers.h:910`, `:926` and `:974` (`404`).
//!
//! The port deliberately differs from upstream where upstream has no handler:
//! the ported routes' plist and media work (W5), the `400` status for a request
//! whose head it cannot parse, and the `501` for a route upstream serves but the
//! port has not ported. Those differences are asserted below rather than being
//! described as gaps.

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
fn route_table_matches_upstream() {
    use Dispatch::{NotImplemented, Ported, Unhandled, UnknownRtspMethod};
    let cases: &[(&str, &str, &str, Dispatch)] = &[
        // RTSP/1.0 `POST` handlers (raop.c:407-422).
        (
            "POST",
            "/feedback",
            "RTSP/1.0",
            NotImplemented(Route::Feedback),
        ),
        (
            "POST",
            "/pair-pin-start",
            "RTSP/1.0",
            NotImplemented(Route::PairPinStart),
        ),
        (
            "POST",
            "/pair-setup-pin",
            "RTSP/1.0",
            NotImplemented(Route::PairSetupPin),
        ),
        (
            "POST",
            "/pair-setup",
            "RTSP/1.0",
            NotImplemented(Route::PairSetup),
        ),
        (
            "POST",
            "/pair-verify",
            "RTSP/1.0",
            NotImplemented(Route::PairVerify),
        ),
        (
            "POST",
            "/fp-setup",
            "RTSP/1.0",
            NotImplemented(Route::FairPlaySetup),
        ),
        (
            "POST",
            "/audioMode",
            "RTSP/1.0",
            NotImplemented(Route::AudioMode),
        ),
        // RTSP/1.0 `GET`: upstream matches the URL with `strstr` (raop.c:424).
        ("GET", "/info", "RTSP/1.0", NotImplemented(Route::Info)),
        ("GET", "/info?x=1", "RTSP/1.0", NotImplemented(Route::Info)),
        ("GET", "/other", "RTSP/1.0", Unhandled),
        // RTSP/1.0 method-only handlers (raop.c:427-441). SETUP carries the
        // session's key material, so the control layer hands it to a handler.
        ("OPTIONS", "*", "RTSP/1.0", Ported(Route::Options)),
        (
            "SETUP",
            "rtsp://host/stream",
            "RTSP/1.0",
            NotImplemented(Route::Setup),
        ),
        (
            "GET_PARAMETER",
            "/stream",
            "RTSP/1.0",
            NotImplemented(Route::GetParameter),
        ),
        (
            "SET_PARAMETER",
            "/stream",
            "RTSP/1.0",
            NotImplemented(Route::SetParameter),
        ),
        ("RECORD", "/stream", "RTSP/1.0", Ported(Route::Record)),
        ("FLUSH", "/stream", "RTSP/1.0", Ported(Route::Flush)),
        ("TEARDOWN", "/stream", "RTSP/1.0", Ported(Route::Teardown)),
        // Documented extension: upstream has no ANNOUNCE route at all.
        ("ANNOUNCE", "/stream", "RTSP/1.0", Ported(Route::Announce)),
        // Unknown RTSP method: raop.c:442-444 answers 501.
        ("PAUSE", "/stream", "RTSP/1.0", UnknownRtspMethod),
        // HTTP/1.1 POST handlers (raop.c:446-463).
        (
            "POST",
            "/reverse",
            "HTTP/1.1",
            NotImplemented(Route::Reverse),
        ),
        ("POST", "/play", "HTTP/1.1", NotImplemented(Route::Play)),
        (
            "POST",
            "/getProperty?key=x",
            "HTTP/1.1",
            NotImplemented(Route::GetProperty),
        ),
        (
            "POST",
            "/scrub?position=1",
            "HTTP/1.1",
            NotImplemented(Route::Scrub),
        ),
        (
            "POST",
            "/rate?value=1",
            "HTTP/1.1",
            NotImplemented(Route::Rate),
        ),
        ("POST", "/stop", "HTTP/1.1", NotImplemented(Route::Stop)),
        ("POST", "/action", "HTTP/1.1", NotImplemented(Route::Action)),
        (
            "POST",
            "/fp-setup2",
            "HTTP/1.1",
            NotImplemented(Route::FairPlaySetup2),
        ),
        // HTTP/1.1 GET and PUT handlers (raop.c:464-475).
        (
            "GET",
            "/server-info",
            "HTTP/1.1",
            NotImplemented(Route::ServerInfo),
        ),
        (
            "GET",
            "/playback-info",
            "HTTP/1.1",
            NotImplemented(Route::PlaybackInfo),
        ),
        (
            "PUT",
            "/setProperty?x=1",
            "HTTP/1.1",
            NotImplemented(Route::SetProperty),
        ),
        // No handler selected: upstream keeps its default 200 (raop.c:334-335).
        ("POST", "/unknown", "HTTP/1.1", Unhandled),
        ("PATCH", "/reverse", "HTTP/1.1", Unhandled),
        // The HTTP/1.1 table has no `/info` route.
        ("GET", "/info", "HTTP/1.1", Unhandled),
        // Upstream compares the protocol string exactly (raop.c:406, 445).
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
    assert_eq!(dispatch(&hls), Dispatch::NotImplemented(Route::Hls));

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
    assert_eq!(dispatch(&facts), Dispatch::NotImplemented(Route::Info));

    let hls = parse_request_head(b"GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
    let facts = RequestFacts::from_head(&hls);
    assert!(facts.is_hls_request());
    assert_eq!(dispatch(&facts), Dispatch::NotImplemented(Route::Hls));

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
        Dispatch::Ported(Route::Announce)
    );
}

#[test]
fn options_response_pins_public_and_upstream_headers() {
    let mut session = ControlSession::new();
    let response = respond(&mut session, &request("OPTIONS", "*", "RTSP/1.0", 7, ""));
    assert_eq!(response.status, 200);
    assert_header(&response, "CSeq", "7");
    assert_header(&response, "Server", SERVER_HEADER_VALUE);
    assert_header(&response, "Audio-Jack-Status", AUDIO_JACK_STATUS);
    assert_header(&response, "Public", PUBLIC_METHODS);
    assert_eq!(response.protocol, "RTSP/1.0");
    // upstream never sends or reads a `Session` header.
    assert_eq!(response.header("Session"), None);
}

#[test]
fn record_response_uses_the_analog_jack_status_and_reports_latency() {
    let mut session = ControlSession::new();
    // No ANNOUNCE: upstream has no route for it, so SETUP may follow on a fresh
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
    // SETUP first, then OPTIONS, then a second SETUP: upstream's routing layer
    // has no state gate (raop.c:406-478).
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
fn rejections_use_bare_upstream_status_codes() {
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
