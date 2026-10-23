// SPDX-License-Identifier: GPL-3.0-or-later
//! RTSP/HTTP control-plane routing and per-connection session state.
//!
//! [`dispatch`] mirrors the method and URL table of
//! `upstream/UxPlay/lib/raop.c:406-478`. [`ControlSession`] adds the
//! per-connection state that upstream keeps in `raop_conn_t`, and
//! [`ControlResponse`] ports the response framing of
//! `upstream/UxPlay/lib/http_response.c:71-170`. Socket I/O, service discovery
//! and the media sessions a `SETUP` request describes stay outside this module.
//!
//! # Documented differences from upstream
//!
//! * A request this module cannot parse is rejected with a status upstream also
//!   uses: `400 Bad Request` for a malformed start line, malformed headers, an
//!   unusable `Content-Length` or a body past [`MAX_CONTROL_BODY`], and
//!   `431 Request Header Fields Too Large` for a head past
//!   [`crate::wire::DEFAULT_MAX_HEAD`] (`upstream/UxPlay/lib/raop.c:232-238`).
//!   Upstream's httpd drops a request whose head it cannot parse; the port
//!   answers instead of failing silently.
//! * Every rejection is a bare status line. Upstream's `431` path returns
//!   before it adds anything (`raop.c:236-238`), and the port extends that to
//!   all rejections so an unusable request never influences a response header.
//! * Routes upstream serves but this crate has not ported answer `501 Not
//!   Implemented` (see [`Route::is_ported`]).
//! * `ANNOUNCE` is an extension: upstream has no such route, and the port keeps
//!   it out of [`PUBLIC_METHODS`] so it is never advertised.
//! * [`ControlState`] is this crate's summary of the RTSP lifecycle. Upstream
//!   tracks a connection type plus `raop_rtp`/`raop_rtp_mirror` handles instead,
//!   so this state is informational and never rejects a request.
//! * `SETUP`, `RECORD`, `FLUSH` and `TEARDOWN` are answered with the
//!   control-plane envelope only: the plist streams, keys and RTP ports they
//!   describe, and the `Authorization`/digest handling of a real `SETUP`
//!   (`upstream/UxPlay/lib/raop_handlers.h:624-1067`), land with the network
//!   service work (`docs/ARCHITECTURE.md`, W5).

use std::fmt;

use std::net::SocketAddr;

use crate::wire::{
    DEFAULT_MAX_HEAD, MessageHead, ParseError, parse_request_head_with_maximum, split_body,
};

/// Largest request body the control plane accepts.
///
/// Bodies this large are rejected before they are buffered; upstream does not
/// bound them at all, so the bound is a documented port limit.
pub const MAX_CONTROL_BODY: usize = 64 * 1024;

/// Value of the `Server` header.
///
/// Upstream sends `"AirTunes/" GLOBAL_VERSION` (`upstream/UxPlay/lib/raop.c:489`)
/// and `upstream/UxPlay/lib/global.h:22` defines `GLOBAL_VERSION` as `220.68`,
/// so the port keeps that wire identity instead of inventing a version string.
pub const SERVER_HEADER_VALUE: &str = "AirTunes/220.68";

/// `Audio-Jack-Status` used by every RTSP response that carries a `CSeq`,
/// except `RECORD` (`upstream/UxPlay/lib/raop.c:338-340`).
pub const AUDIO_JACK_STATUS: &str = "connected; type=digital";

/// `Audio-Jack-Status` sent by the `RECORD` handler
/// (`upstream/UxPlay/lib/raop_handlers.h:1226`).
pub const AUDIO_JACK_STATUS_RECORD: &str = "connected; type=analog";

/// `Public` header value for `OPTIONS`
/// (`upstream/UxPlay/lib/raop_handlers.h:596`).
pub const PUBLIC_METHODS: &str =
    "SETUP, RECORD, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER";

/// Sample rate of every audio format upstream supports
/// (`upstream/UxPlay/lib/raop_handlers.h:27`).
pub const AUDIO_SAMPLE_RATE: u32 = 44_100;

/// Audio delay upstream starts with, in microseconds
/// (`upstream/UxPlay/lib/raop.c:639`).
pub const DEFAULT_AUDIO_DELAY_MICROS: u32 = 250_000;

/// Largest audio delay upstream accepts, in microseconds
/// (`upstream/UxPlay/lib/raop.c:759-761`).
pub const MAX_AUDIO_DELAY_MICROS: u32 = 10 * 1_000_000;

/// Converts an audio delay into the sample count of the `Audio-Latency` header.
///
/// This is `audio_delay_micros * AUDIO_SAMPLE_RATE / 1_000_000` exactly as
/// `upstream/UxPlay/lib/raop_handlers.h:1222` computes it. The multiplication
/// runs in 64 bits and the conversion falls back to `u32::MAX`, so no input can
/// wrap or panic.
pub fn audio_latency_samples(audio_delay_micros: u32) -> u32 {
    let samples = u64::from(audio_delay_micros) * u64::from(AUDIO_SAMPLE_RATE) / 1_000_000;
    u32::try_from(samples).unwrap_or(u32::MAX)
}

/// One entry of the upstream control-plane route table.
///
/// Names follow the upstream handler that serves the route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// `POST /feedback`
    Feedback,
    /// `POST /pair-pin-start`
    PairPinStart,
    /// `POST /pair-setup-pin`
    PairSetupPin,
    /// `POST /pair-setup`
    PairSetup,
    /// `POST /pair-verify`
    PairVerify,
    /// `POST /fp-setup`
    FairPlaySetup,
    /// `POST /audioMode`
    AudioMode,
    /// `GET` whose URL contains `/info` (upstream matches with `strstr`)
    Info,
    /// `OPTIONS`, any target
    Options,
    /// `SETUP`, any target
    Setup,
    /// `GET_PARAMETER`, any target
    GetParameter,
    /// `SET_PARAMETER`, any target
    SetParameter,
    /// `RECORD`, any target
    Record,
    /// `FLUSH`, any target
    Flush,
    /// `TEARDOWN`, any target
    Teardown,
    /// `POST /reverse`
    Reverse,
    /// `POST /play`
    Play,
    /// `POST /getProperty?...`
    GetProperty,
    /// `POST /scrub?...`
    Scrub,
    /// `POST /rate?...`
    Rate,
    /// `POST /stop`
    Stop,
    /// `POST /action`
    Action,
    /// `POST /fp-setup2`
    FairPlaySetup2,
    /// `GET /server-info`
    ServerInfo,
    /// `GET /playback-info`
    PlaybackInfo,
    /// `PUT /setProperty?...`
    SetProperty,
    /// HLS request: a `Host` header without `CSeq` and without
    /// `X-Apple-Session-ID` (`upstream/UxPlay/lib/raop.c:270`).
    Hls,
    /// `ANNOUNCE`, which upstream does not dispatch at all.
    ///
    /// This crate keeps it as a documented extension so a session can be
    /// announced before `SETUP`; it is deliberately absent from
    /// [`PUBLIC_METHODS`] because upstream never advertises it.
    Announce,
}

impl Route {
    /// Whether this crate implements the route's control-plane behavior.
    ///
    /// An unported route answers `501 Not Implemented` rather than the upstream
    /// handler's `200 OK`, so an unimplemented handler can never be mistaken for
    /// success. `RECORD`, `FLUSH` and `TEARDOWN` are ported as the RTSP envelope
    /// only; their media handling lands with S4. `SETUP` is served by a
    /// [`RouteHandler`] because it carries the session's key material and stream
    /// requests, and a control layer without one answers `501` for it.
    pub fn is_ported(self) -> bool {
        matches!(
            self,
            Self::Options | Self::Record | Self::Flush | Self::Teardown | Self::Announce
        )
    }
}

/// Request facts the upstream dispatcher keys on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestFacts<'a> {
    /// Request method as sent.
    pub method: &'a str,
    /// Request target as sent.
    pub target: &'a str,
    /// Protocol as sent, for example `RTSP/1.0`.
    pub version: &'a str,
    /// Whether a `CSeq` header is present.
    pub has_cseq: bool,
    /// Whether a `Host` header is present.
    pub has_host: bool,
    /// Whether an `X-Apple-Session-ID` header is present.
    pub has_session_id: bool,
}

impl<'a> RequestFacts<'a> {
    /// Derives the routing facts from one parsed request head.
    pub fn from_head(head: &'a MessageHead) -> Self {
        Self {
            method: &head.method,
            target: &head.target,
            version: &head.version,
            has_cseq: head.header("cseq").is_some(),
            has_host: head.header("host").is_some(),
            has_session_id: head.header("x-apple-session-id").is_some(),
        }
    }

    /// Whether this is a response to a Bluetooth LE beacon advertisement.
    ///
    /// `upstream/UxPlay/lib/raop.c:257`: an `RTSP/1.0` request without `CSeq`
    /// that mentions `txtAirPlay` or `txtRAOP` is such a response, and upstream
    /// does not ignore it even when HLS support is off.
    pub fn is_ble_beacon_response(self) -> bool {
        self.version == "RTSP/1.0"
            && !self.has_cseq
            && (self.target.contains("txtAirPlay") || self.target.contains("txtRAOP"))
    }

    /// Whether this is an HLS request (`upstream/UxPlay/lib/raop.c:270`).
    pub fn is_hls_request(self) -> bool {
        self.has_host && !self.has_cseq && !self.has_session_id
    }
}

/// Result of one upstream route lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatch {
    /// Upstream serves the route and this crate implements it.
    Ported(Route),
    /// Upstream serves the route but this crate has not ported it, so the
    /// response is `501 Not Implemented`.
    NotImplemented(Route),
    /// Upstream selected no handler and answers its default `200 OK` with no body.
    Unhandled,
    /// Upstream answers `501 Not Implemented` for an unknown RTSP method
    /// (`upstream/UxPlay/lib/raop.c:442-444`).
    UnknownRtspMethod,
}

/// Looks up one request in the upstream route table.
///
/// Upstream compares the protocol string exactly, so `RTSP/2.0` or any other
/// version selects no handler. The HLS rule precedes both protocol tables
/// (`upstream/UxPlay/lib/raop.c:406`, `:445-478`).
pub fn dispatch(facts: &RequestFacts<'_>) -> Dispatch {
    if facts.is_hls_request() {
        return classify(Route::Hls);
    }
    match facts.version {
        "RTSP/1.0" => dispatch_rtsp(facts),
        "HTTP/1.1" => dispatch_http(facts),
        _ => Dispatch::Unhandled,
    }
}

fn classify(route: Route) -> Dispatch {
    if route.is_ported() {
        Dispatch::Ported(route)
    } else {
        Dispatch::NotImplemented(route)
    }
}

fn classify_rtsp_post(target: &str) -> Dispatch {
    let route = match target {
        "/feedback" => Route::Feedback,
        "/pair-pin-start" => Route::PairPinStart,
        "/pair-setup-pin" => Route::PairSetupPin,
        "/pair-setup" => Route::PairSetup,
        "/pair-verify" => Route::PairVerify,
        "/fp-setup" => Route::FairPlaySetup,
        "/audioMode" => Route::AudioMode,
        _ => return Dispatch::Unhandled,
    };
    classify(route)
}

fn dispatch_rtsp(facts: &RequestFacts<'_>) -> Dispatch {
    match facts.method {
        "POST" => classify_rtsp_post(facts.target),
        "GET" => {
            if facts.target.contains("/info") {
                classify(Route::Info)
            } else {
                Dispatch::Unhandled
            }
        }
        "OPTIONS" => classify(Route::Options),
        "SETUP" => classify(Route::Setup),
        "GET_PARAMETER" => classify(Route::GetParameter),
        "SET_PARAMETER" => classify(Route::SetParameter),
        "RECORD" => classify(Route::Record),
        "FLUSH" => classify(Route::Flush),
        "TEARDOWN" => classify(Route::Teardown),
        "ANNOUNCE" => classify(Route::Announce),
        _ => Dispatch::UnknownRtspMethod,
    }
}

fn dispatch_http(facts: &RequestFacts<'_>) -> Dispatch {
    let route = match facts.method {
        "POST" => {
            let target = facts.target;
            if target == "/reverse" {
                Route::Reverse
            } else if target == "/play" {
                Route::Play
            } else if target.starts_with("/getProperty?") {
                Route::GetProperty
            } else if target.starts_with("/scrub?") {
                Route::Scrub
            } else if target.starts_with("/rate?") {
                Route::Rate
            } else if target == "/stop" {
                Route::Stop
            } else if target == "/action" {
                Route::Action
            } else if target == "/fp-setup2" {
                Route::FairPlaySetup2
            } else {
                return Dispatch::Unhandled;
            }
        }
        "GET" => match facts.target {
            "/server-info" => Route::ServerInfo,
            "/playback-info" => Route::PlaybackInfo,
            _ => return Dispatch::Unhandled,
        },
        "PUT" if facts.target.starts_with("/setProperty?") => Route::SetProperty,
        // Upstream has no 501 branch for HTTP/1.1: an unknown method leaves the
        // default 200 response untouched (`upstream/UxPlay/lib/raop.c:445-475`).
        _ => return Dispatch::Unhandled,
    };
    classify(route)
}

/// Lifecycle state this crate observes for one connection.
///
/// The transitions are informational: upstream's routing layer is stateless, so
/// no request is ever rejected because of this state
/// (`upstream/UxPlay/lib/raop.c:406-478`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ControlState {
    /// Nothing has been announced or set up yet.
    #[default]
    New,
    /// `ANNOUNCE` was seen. Upstream has no such route; the port keeps the
    /// announcement as an extension.
    Announced,
    /// `SETUP` was seen.
    Setup,
    /// `RECORD` was seen after `SETUP`.
    Recording,
    /// `TEARDOWN` was seen; upstream also closes the connection
    /// (`upstream/UxPlay/lib/raop_handlers.h:1284`).
    Closed,
}

/// One response to write back on the connection.
///
/// The layout follows `upstream/UxPlay/lib/http_response.c:71-170`: the status
/// line echoes the request protocol, headers keep insertion order, and
/// `Content-Length` is appended last and only when there is a body or a
/// `Content-Type` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlResponse {
    /// Protocol echoed in the status line, for example `RTSP/1.0`.
    ///
    /// `upstream/UxPlay/lib/raop.c:335` initializes the response with the
    /// request's protocol, so an HTTP/1.1 peer is answered with `HTTP/1.1`.
    pub protocol: String,
    /// Numeric status code.
    pub status: u16,
    /// Reason phrase sent after the status code.
    pub reason: &'static str,
    /// Header fields in the order they must be written.
    pub headers: Vec<(String, String)>,
    /// Response body, empty for a header-only response.
    pub body: Vec<u8>,
    /// Whether the connection is closed once this response is written.
    ///
    /// Upstream asks its connection to disconnect through
    /// `http_response_set_disconnect` (`upstream/UxPlay/lib/http_response.c:172-186`),
    /// which `RAOP` uses for `TEARDOWN` and for a failed `/pair-verify`
    /// signature. It is not visible on the wire by itself.
    pub close_after_reply: bool,
}

impl ControlResponse {
    /// Builds an empty response whose status line echoes `protocol`.
    pub fn new(protocol: &str, status: u16, reason: &'static str) -> Self {
        Self {
            protocol: protocol.to_owned(),
            status,
            reason,
            headers: Vec::new(),
            body: Vec::new(),
            close_after_reply: false,
        }
    }

    /// First value of `name`, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Serializes the response exactly as `http_response_finish` does.
    ///
    /// `upstream/UxPlay/lib/http_response.c:131-170` appends `Content-Length`
    /// and the body when there is a body, appends `Content-Length: 0` when there
    /// is no body but a `Content-Type` header was set, and otherwise terminates
    /// the head with an empty line and no `Content-Length` at all.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(128 + self.body.len());
        output.extend_from_slice(self.protocol.as_bytes());
        output.extend_from_slice(b" ");
        output.extend_from_slice(self.status.to_string().as_bytes());
        output.extend_from_slice(b" ");
        output.extend_from_slice(self.reason.as_bytes());
        output.extend_from_slice(b"\r\n");
        for (name, value) in &self.headers {
            output.extend_from_slice(name.as_bytes());
            output.extend_from_slice(b": ");
            output.extend_from_slice(value.as_bytes());
            output.extend_from_slice(b"\r\n");
        }
        if self.body.is_empty() {
            if self.header("content-type").is_some() {
                output.extend_from_slice(b"Content-Length: 0\r\n");
            }
            output.extend_from_slice(b"\r\n");
        } else {
            output.extend_from_slice(b"Content-Length: ");
            output.extend_from_slice(self.body.len().to_string().as_bytes());
            output.extend_from_slice(b"\r\n\r\n");
            output.extend_from_slice(&self.body);
        }
        output
    }
}

/// One routed request as a [`RouteHandler`] sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteRequest<'a> {
    /// Parsed request head, including its headers and target.
    pub head: &'a MessageHead,
    /// Complete request body, empty when the request declared no body.
    pub body: &'a [u8],
    /// The peer this request arrived from, when the transport knows it.
    ///
    /// A `SETUP` needs it: the clock exchange is the receiver's to start, and it
    /// goes to the address the request came from (`raop_ntp.c:617-618`). A request
    /// built without a transport — a unit test, a replay — has none.
    pub peer: Option<SocketAddr>,
}

/// Reply a [`RouteHandler`] produces for a route it serves.
///
/// The control plane wraps it into a [`ControlResponse`]: it echoes the request
/// protocol and prepends `Audio-Jack-Status` the way
/// `upstream/UxPlay/lib/raop.c:338-340` does, appends `Server` and `CSeq`
/// afterwards (`raop.c:488-492`), and leaves the status code, reason phrase,
/// body and handler headers to the handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteReply {
    /// Numeric status code.
    pub status: u16,
    /// Reason phrase sent after the status code.
    pub reason: &'static str,
    /// Headers this handler contributes, in the order they must be written.
    pub headers: Vec<(String, String)>,
    /// Response body, empty for a header-only response.
    pub body: Vec<u8>,
    /// Whether the connection is closed once this reply is written.
    pub close_after_reply: bool,
}

impl RouteReply {
    /// `200 OK` with no headers and no body, upstream's default response
    /// (`upstream/UxPlay/lib/raop.c:334-335`).
    pub fn ok() -> Self {
        Self::new(200, "OK")
    }

    /// `501 Not Implemented`.
    ///
    /// Upstream answers this for an unknown RTSP method
    /// (`upstream/UxPlay/lib/raop.c:442-444`) and for an unsupported FairPlay
    /// setup challenge (`raop_handlers.h:558`). This crate also uses it for every
    /// route upstream serves that it has not implemented yet, so an unimplemented
    /// handler can never be mistaken for the upstream `200 OK`.
    pub fn not_implemented() -> Self {
        Self::new(501, "Not Implemented")
    }

    /// Reply with the given status code and reason phrase.
    pub fn new(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            headers: Vec::new(),
            body: Vec::new(),
            close_after_reply: false,
        }
    }

    /// Adds one header.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Value of the first `name` header, ignoring case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Sets the response body.
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Closes the connection once this reply is written.
    pub fn closing(mut self) -> Self {
        self.close_after_reply = true;
        self
    }
}

/// Serves the routes that upstream implements but this control layer does not.
///
/// The trait exists so that the routing table, the request preconditions
/// (unusable `CSeq`, HLS and Bluetooth LE handling) and the response header
/// order live in exactly one place: [`ControlSession::handle_with`], a direct
/// port of `upstream/UxPlay/lib/raop.c:232-494`. A handler therefore contributes
/// only the status, reason, body and the headers its upstream handler adds.
///
/// One handler instance serves one connection, so it may hold per-connection
/// protocol state such as a FairPlay or pairing session.
pub trait RouteHandler {
    /// Handles `route`, or returns `None` when this handler does not serve it.
    ///
    /// `None` makes the control plane answer `501 Not Implemented`.
    fn handle(&mut self, route: Route, request: &RouteRequest<'_>) -> Option<RouteReply>;

    /// Is told about every request this connection answered.
    ///
    /// Upstream logs the same facts (`upstream/UxPlay/lib/raop.c:347-360` logs
    /// the method and URL of each request). A trace carries only what a client
    /// sends in the clear — method, target, `CSeq`, `User-Agent`,
    /// `Content-Type`, body length and the answer's status — and never a body,
    /// a key or a signature, so a receiver can be debugged against a real client
    /// without printing secrets.
    fn trace(&mut self, _trace: &RequestTrace<'_>) {}

    /// A clock the transport can watch to tell whether the client is still there.
    ///
    /// `GET`-style sessions are kept alive by `POST /feedback`, and a client that stops
    /// sending it has gone away even though its socket has not. A handler that supports a
    /// timeout returns the millisecond clock it updates on each feedback request; `None`
    /// means this connection cannot be timed out from its feedback.
    fn feedback_clock(&self) -> Option<std::sync::Arc<std::sync::atomic::AtomicU64>> {
        None
    }
}

/// One request and the answer it got, for diagnostics.
///
/// The fields are the ones a person needs to follow a session: what was asked,
/// how big it was, and what came back. Nothing here is secret by construction,
/// which is the point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestTrace<'a> {
    /// Method of the request, as sent.
    pub method: &'a str,
    /// Target of the request, as sent.
    pub target: &'a str,
    /// `CSeq` of the request, when the client sent one.
    pub cseq: Option<u32>,
    /// `User-Agent` header, when the client sent one.
    pub user_agent: Option<&'a str>,
    /// `Content-Type` header, when the client sent one.
    pub content_type: Option<&'a str>,
    /// `Active-Remote` token, when the client sent one.
    ///
    /// Upstream records it on the connection and hands it to its caller
    /// (`upstream/UxPlay/lib/raop.c:342-351`). It names the remote-control
    /// client a request came from, and it authorizes nothing: the header is
    /// written by whoever connects.
    pub active_remote: Option<&'a str>,
    /// `DACP-ID` header, when the client sent one.
    ///
    /// The same header pair identifies the remote-control connection a client
    /// wants to use; see [`RequestTrace::active_remote`].
    pub dacp_id: Option<&'a str>,
    /// Length of the body the request carried.
    pub body_len: usize,
    /// Status the connection answered with.
    pub status: u16,
}

/// A [`RouteHandler`] that implements no route.
///
/// Every route upstream serves but the port has not implemented answers
/// `501 Not Implemented`; this is what [`ControlSession::handle`] uses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoHandler;

impl RouteHandler for NoHandler {
    fn handle(&mut self, _route: Route, _request: &RouteRequest<'_>) -> Option<RouteReply> {
        None
    }
}

/// A request the control plane cannot act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlError {
    /// The request head could not be parsed. Answered with `400 Bad Request`.
    Parse(ParseError),
    /// The head block exceeded [`DEFAULT_MAX_HEAD`]. Answered with
    /// `431 Request Header Fields Too Large`, the code upstream uses for
    /// overlong request headers (`upstream/UxPlay/lib/raop.c:232-238`).
    HeadTooLarge {
        /// Size of the head that was rejected.
        declared: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// The declared body exceeded [`MAX_CONTROL_BODY`]. Answered with
    /// `400 Bad Request`; upstream bounds no body, so this is a port limit.
    BodyTooLarge {
        /// Declared body size.
        declared: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// The request carried an `X-Apple-Session-ID` that differs from the one
    /// this connection already used, so it belongs to another session.
    ///
    /// `upstream/UxPlay/lib/raop.c:400-402` asserts the same equality; the port
    /// answers `400 Bad Request` instead of aborting.
    SessionMismatch,
}

impl ControlError {
    /// Status code and reason phrase upstream associates with this failure.
    pub fn status(&self) -> (u16, &'static str) {
        match self {
            Self::HeadTooLarge { .. } => (431, "Request Header Fields Too Large"),
            Self::Parse(_) | Self::BodyTooLarge { .. } | Self::SessionMismatch => {
                (400, "Bad Request")
            }
        }
    }

    /// Builds the bare rejection response for this failure.
    ///
    /// The response carries no headers: upstream's `431` path returns before any
    /// header is added (`upstream/UxPlay/lib/raop.c:236-238`), and the port
    /// never echoes fields of a request it rejected. `protocol` is the protocol
    /// to put in the status line; a caller that could not parse the head at all
    /// passes the protocol it expects.
    pub fn to_response(&self, protocol: &str) -> ControlResponse {
        let (status, reason) = self.status();
        ControlResponse::new(protocol, status, reason)
    }
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => error.fmt(f),
            Self::HeadTooLarge { declared, maximum } => {
                write!(
                    f,
                    "request head of {declared} bytes exceeds maximum {maximum}"
                )
            }
            Self::BodyTooLarge { declared, maximum } => {
                write!(
                    f,
                    "request body of {declared} bytes exceeds maximum {maximum}"
                )
            }
            Self::SessionMismatch => {
                f.write_str("X-Apple-Session-ID does not match the connection session")
            }
        }
    }
}

impl std::error::Error for ControlError {}

impl From<ParseError> for ControlError {
    fn from(error: ParseError) -> Self {
        Self::Parse(error)
    }
}

/// What a caller must do with one handled request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlOutcome {
    /// Write this response back on the connection.
    Respond(ControlResponse),
    /// Write nothing and keep the connection open.
    ///
    /// Upstream drops the request in two cases: an unusable `CSeq` value
    /// (`upstream/UxPlay/lib/raop.c:247-250`) and a request without `CSeq` while
    /// HLS support is off and the request is not a BLE beacon response
    /// (`upstream/UxPlay/lib/raop.c:263-266`). Its httpd then sends no response
    /// at all (`upstream/UxPlay@3dbf7cee:lib/httpd.c:588-625`).
    Ignored,
}

/// Per-connection control-plane state.
#[derive(Debug)]
pub struct ControlSession {
    state: ControlState,
    session_id: Option<String>,
    hls_support: bool,
    audio_delay_micros: u32,
    /// The peer the connection this session serves belongs to, when it has one.
    peer: Option<SocketAddr>,
}

impl Default for ControlSession {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlSession {
    /// Creates a session with upstream's defaults: HLS support off and a
    /// [`DEFAULT_AUDIO_DELAY_MICROS`] audio delay.
    pub fn new() -> Self {
        Self {
            state: ControlState::New,
            session_id: None,
            hls_support: false,
            audio_delay_micros: DEFAULT_AUDIO_DELAY_MICROS,
            peer: None,
        }
    }

    /// Current lifecycle state.
    pub fn state(&self) -> ControlState {
        self.state
    }

    /// `X-Apple-Session-ID` this connection is bound to, once one was seen.
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Enables HLS request handling, mirroring upstream's `-hls` option.
    ///
    /// The port implements no HLS handler, so enabling this only turns the
    /// silent drop of a CSeq-less request with a `Host` header into an explicit
    /// `501 Not Implemented` for [`Route::Hls`].
    pub fn set_hls_support(&mut self, enabled: bool) {
        self.hls_support = enabled;
    }

    /// Tells the session which peer it is serving.
    ///
    /// A `SETUP` needs it to know where to send the clock exchange, which the
    /// receiver starts (`raop_ntp.c:617-618`). A session with no peer serves
    /// requests whose routes do not need one.
    pub fn set_peer(&mut self, peer: SocketAddr) {
        self.peer = Some(peer);
    }

    /// Sets the audio delay reported by `RECORD` in `Audio-Latency`.
    ///
    /// The accepted range is `0..=`[`MAX_AUDIO_DELAY_MICROS`]
    /// (`upstream/UxPlay/lib/raop.c:759-761`); validating configuration input is
    /// the configuration layer's job, and this stores the value as given.
    pub fn set_audio_delay_micros(&mut self, micros: u32) {
        self.audio_delay_micros = micros;
    }

    /// Handles one complete request and decides what to write back.
    ///
    /// The steps follow `upstream/UxPlay/lib/raop.c:232-494`:
    ///
    /// 1. bound and parse the head, then bound the declared body and require it
    ///    to be present;
    /// 2. read `CSeq`, dropping the request when it is unusable
    ///    (`raop.c:247-250`);
    /// 3. drop a request without `CSeq` unless HLS support is on or the request
    ///    is a BLE beacon response (`raop.c:263-266`);
    /// 4. bind the connection to the first `X-Apple-Session-ID` it sees and
    ///    reject a later different one (`raop.c:400-402`);
    /// 5. route by method and URL, then add the headers upstream adds:
    ///    `Audio-Jack-Status`, the handler's headers, `Server` and `CSeq`.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] when the request cannot be acted on; the caller
    /// answers with [`ControlError::to_response`], whose status code comes from
    /// [`ControlError::status`].
    ///
    /// This is [`ControlSession::handle_with`] with a [`NoHandler`], so every
    /// route upstream serves that the port has not implemented answers
    /// `501 Not Implemented`.
    pub fn handle(&mut self, input: &[u8]) -> Result<ControlOutcome, ControlError> {
        self.handle_with(input, &mut NoHandler)
    }

    /// Handles one complete request, letting `handler` serve the routes this
    /// layer does not implement itself.
    ///
    /// The network service passes its per-connection [`RouteHandler`] here.
    ///
    /// # Errors
    ///
    /// Same as [`ControlSession::handle`].
    pub fn handle_with(
        &mut self,
        input: &[u8],
        handler: &mut dyn RouteHandler,
    ) -> Result<ControlOutcome, ControlError> {
        let head = parse_request_head_with_maximum(input, DEFAULT_MAX_HEAD).map_err(head_error)?;
        let length = head.content_length(MAX_CONTROL_BODY).map_err(body_error)?;
        // The body must be complete before the request is routed, and a route
        // handler describing a media session receives it.
        let body = split_body(&input[head.consumed..], length)?;
        let facts = RequestFacts::from_head(&head);

        let cseq = match head.header("cseq") {
            None => None,
            Some(value) => match value.trim().parse::<u32>() {
                // Upstream drops a request whose CSeq is not a non-negative
                // integer instead of answering it (`raop.c:241-250`).
                Err(_) => return Ok(ControlOutcome::Ignored),
                Ok(cseq) => Some(cseq),
            },
        };

        if cseq.is_none() && !facts.is_ble_beacon_response() && !self.hls_support {
            return Ok(ControlOutcome::Ignored);
        }

        if let Some(id) = head.header("x-apple-session-id") {
            match self.session_id.as_deref() {
                None => {}
                Some(known) if known == id => {}
                Some(_) => return Err(ControlError::SessionMismatch),
            }
            if self.session_id.is_none() {
                self.session_id = Some(id.to_owned());
            }
        }

        let reply = match dispatch(&facts) {
            Dispatch::Ported(route) => {
                self.observe(route);
                ported_reply(route, self.audio_delay_micros)
            }
            // Upstream serves the route; a handler that has not implemented it
            // answers 501 rather than pretending to succeed. A handler that does
            // serve it also gives the route its lifecycle meaning, which is why
            // the state is observed here and not for a 501.
            Dispatch::NotImplemented(route) => {
                match handler.handle(
                    route,
                    &RouteRequest {
                        head: &head,
                        body,
                        peer: self.peer,
                    },
                ) {
                    Some(reply) => {
                        self.observe(route);
                        reply
                    }
                    None => RouteReply::not_implemented(),
                }
            }
            Dispatch::UnknownRtspMethod => RouteReply::not_implemented(),
            Dispatch::Unhandled => RouteReply::ok(),
        };

        // The trace happens once the answer is known, so it reports what the
        // client actually got rather than what was intended.
        handler.trace(&RequestTrace {
            method: &head.method,
            target: &head.target,
            cseq,
            user_agent: head.header("user-agent"),
            content_type: head.header("content-type"),
            active_remote: head.header("active-remote"),
            dacp_id: head.header("dacp-id"),
            body_len: body.len(),
            status: reply.status,
        });

        let mut response = ControlResponse::new(&head.version, reply.status, reply.reason);
        // `raop.c:338-340`: added before the handler runs, for every RTSP
        // request that carries a CSeq except RECORD.
        if cseq.is_some() && head.method != "RECORD" {
            response
                .headers
                .push(("Audio-Jack-Status".to_owned(), AUDIO_JACK_STATUS.to_owned()));
        }
        response.headers.extend(reply.headers);
        // `raop.c:488-492`: `Server` and `CSeq` come last, and an HLS request
        // gets neither.
        if !facts.is_hls_request() {
            response
                .headers
                .push(("Server".to_owned(), SERVER_HEADER_VALUE.to_owned()));
            if let Some(cseq) = cseq {
                response.headers.push(("CSeq".to_owned(), cseq.to_string()));
            }
        }
        response.body = reply.body;
        response.close_after_reply = reply.close_after_reply;
        Ok(ControlOutcome::Respond(response))
    }

    /// Records what a ported route means for the observed lifecycle state.
    ///
    /// The mapping is monotone and permissive, because upstream answers all of
    /// these routes with `200 OK` regardless of what came before
    /// (`upstream/UxPlay/lib/raop.c:406-478`, `raop_handlers.h:1215-1250`):
    /// `OPTIONS` never changes the state, a second `SETUP` does not rewind a
    /// recording session, and `FLUSH` outside a recording session is a no-op
    /// upstream only logs a warning about.
    fn observe(&mut self, route: Route) {
        self.state = match route {
            Route::Announce if self.state == ControlState::New => ControlState::Announced,
            Route::Setup if matches!(self.state, ControlState::New | ControlState::Announced) => {
                ControlState::Setup
            }
            Route::Record
                if matches!(self.state, ControlState::Setup | ControlState::Recording) =>
            {
                ControlState::Recording
            }
            Route::Teardown => ControlState::Closed,
            _ => self.state,
        };
    }
}

/// Reply for a route this control layer implements itself.
///
/// `OPTIONS` and `RECORD` contribute the headers their upstream handlers add
/// (`upstream/UxPlay/lib/raop_handlers.h:596`, `:1225-1226`), and `TEARDOWN`
/// asks the peer to close the connection (`raop_handlers.h:1284`).
fn ported_reply(route: Route, audio_delay_micros: u32) -> RouteReply {
    match route {
        Route::Options => RouteReply::ok().with_header("Public", PUBLIC_METHODS),
        Route::Record => {
            let latency = audio_latency_samples(audio_delay_micros).to_string();
            RouteReply::ok()
                .with_header("Audio-Latency", &latency)
                .with_header("Audio-Jack-Status", AUDIO_JACK_STATUS_RECORD)
        }
        Route::Teardown => RouteReply::ok()
            .with_header("Connection", "close")
            .closing(),
        // A route this crate does not serve says so. Answering `200 OK` while doing
        // nothing is a promise to the client that the receiver is not keeping, and a
        // client that waits for a recording or a stream to start has no way to tell the
        // difference between "not yet" and "never".
        _ => RouteReply::not_implemented(),
    }
}

/// Length in bytes of the first request in `input`, or `None` while that
/// request is still incomplete.
///
/// A network service uses this to frame a byte stream: the length covers the
/// request head plus the body its `Content-Length` declares and stops before
/// the next request, so a caller can pass exactly one request to
/// [`ControlSession::handle_with`] and keep the remaining bytes buffered.
///
/// An incomplete request is not an error, so [`ParseError::Incomplete`] is
/// reported as `Ok(None)` here.
///
/// # Errors
///
/// Returns the failures [`ControlSession::handle_with`] reports: a malformed
/// head or body length (`400`), a head past [`crate::wire::DEFAULT_MAX_HEAD`]
/// (`431`) or a body past [`MAX_CONTROL_BODY`] (`400`).
pub fn request_length(input: &[u8]) -> Result<Option<usize>, ControlError> {
    let head = match parse_request_head_with_maximum(input, DEFAULT_MAX_HEAD) {
        Ok(head) => head,
        Err(ParseError::Incomplete) => return Ok(None),
        Err(error) => return Err(head_error(error)),
    };
    let length = head.content_length(MAX_CONTROL_BODY).map_err(body_error)?;
    match split_body(&input[head.consumed..], length) {
        Ok(_) => Ok(Some(head.consumed + length)),
        Err(ParseError::Incomplete) => Ok(None),
        Err(error) => Err(ControlError::Parse(error)),
    }
}

fn head_error(error: ParseError) -> ControlError {
    match error {
        ParseError::TooLarge { declared, maximum } => {
            ControlError::HeadTooLarge { declared, maximum }
        }
        other => ControlError::Parse(other),
    }
}

fn body_error(error: ParseError) -> ControlError {
    match error {
        ParseError::TooLarge { declared, maximum } => {
            ControlError::BodyTooLarge { declared, maximum }
        }
        other => ControlError::Parse(other),
    }
}

#[cfg(test)]
mod tests;
