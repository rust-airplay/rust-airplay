// SPDX-License-Identifier: GPL-3.0-or-later
//! Turning a request line into a route.

use crate::wire::MessageHead;

use super::route::Route;

/// Request facts the protocol dispatcher keys on.
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
    /// an `RTSP/1.0` request without `CSeq`
    /// that mentions `txtAirPlay` or `txtRAOP` is such a response, and the protocol
    /// does not ignore it even when HLS support is off.
    pub fn is_ble_beacon_response(self) -> bool {
        self.version == "RTSP/1.0"
            && !self.has_cseq
            && (self.target.contains("txtAirPlay") || self.target.contains("txtRAOP"))
    }

    /// Whether this is an HLS request.
    pub fn is_hls_request(self) -> bool {
        self.has_host && !self.has_cseq && !self.has_session_id
    }
}

/// Result of one route lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatch {
    /// This layer answers the route itself.
    Local(Route),
    /// The route is offered to the connection's [`RouteHandler`](super::types::RouteHandler); a connection without one
    /// answers `501 Not Implemented`.
    Delegated(Route),
    /// No route matched. The request is answered `200 OK` with no body.
    Unhandled,
    /// The method is not one the RTSP table knows. The request is answered `501 Not
    /// Implemented`.
    UnknownRtspMethod,
}

/// Looks up one request in the route table.
///
/// The protocol string is compared exactly, so `RTSP/2.0` selects no route. The HLS rule is
/// checked before the RTSP and HTTP tables, because an HLS request is recognised by its headers
/// rather than by a method.
///
/// # Examples
///
/// ```
/// use rust_airplay::control::{Dispatch, RequestFacts, Route, dispatch};
/// use rust_airplay::wire::parse_request_head;
///
/// let head = parse_request_head(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
///     .expect("request");
/// let facts = RequestFacts::from_head(&head);
/// assert_eq!(dispatch(&facts), Dispatch::Local(Route::Options));
/// ```
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
    if route.is_local() {
        Dispatch::Local(route)
    } else {
        Dispatch::Delegated(route)
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
        // The protocol has no 501 branch for HTTP/1.1: an unknown method leaves the
        // default 200 response untouched.
        _ => return Dispatch::Unhandled,
    };
    classify(route)
}
