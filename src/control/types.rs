// SPDX-License-Identifier: GPL-3.0-or-later
//! The values a request and a reply carry, and the handler trait.

use std::fmt;
use std::net::SocketAddr;

use crate::wire::{MessageHead, ParseError};

use super::route::Route;

/// Lifecycle state this crate observes for one connection.
///
/// The transitions are informational: the protocol's routing layer is stateless, so
/// no request is ever rejected because of this state
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ControlState {
    /// Nothing has been announced or set up yet.
    #[default]
    New,
    /// `ANNOUNCE` was seen. The protocol has no such route; the port keeps the
    /// announcement as an extension.
    Announced,
    /// `SETUP` was seen.
    Setup,
    /// `RECORD` was seen after `SETUP`.
    Recording,
    /// `TEARDOWN` was seen; the protocol also closes the connection
    Closed,
}

/// One response to write back on the connection.
///
/// The layout follows: the status
/// line echoes the request protocol, headers keep insertion order, and
/// `Content-Length` is appended last and only when there is a body or a
/// `Content-Type` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlResponse {
    /// Protocol echoed in the status line, for example `RTSP/1.0`.
    ///
    /// initializes the response with the
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
    /// The protocol asks its connection to disconnect through
    /// `http_response_set_disconnect`,
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
    /// appends `Content-Length`
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
    /// goes to the address the request came from. A request
    /// built without a transport — a unit test, a replay — has none.
    pub peer: Option<SocketAddr>,
}

/// Reply a [`RouteHandler`] produces for a route it serves.
///
/// The control plane wraps it into a [`ControlResponse`]: it echoes the request
/// protocol and prepends `Audio-Jack-Status` the way
/// does, appends `Server` and `CSeq`
/// afterwards, and leaves the status code, reason phrase,
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
    /// `200 OK` with no headers and no body, the protocol's default response
    pub fn ok() -> Self {
        Self::new(200, "OK")
    }

    /// A `501 Not Implemented` reply.
    ///
    /// It answers an unknown RTSP method, an unsupported FairPlay setup challenge, and a route
    /// no handler served, so a client never mistakes work that was not done for success.
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

/// Serves the routes that the protocol implements but this control layer does not.
///
/// The trait exists so that the routing table, the request preconditions
/// (unusable `CSeq`, HLS and Bluetooth LE handling) and the response header
/// order live in exactly one place: [`ControlSession::handle_with`](super::ControlSession::handle_with), a direct
/// port of. A handler therefore contributes
/// only the status, reason, body and the headers its the protocol handler adds.
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
    /// The protocol logs the same facts ( logs
    /// the method and URL of each request). A trace carries only what a client
    /// sends in the clear — method, target, `CSeq`, `User-Agent`,
    /// `Content-Type`, body length and the answer's status — and never a body,
    /// a key or a signature, so a receiver can be debugged against a real client
    /// without printing secrets.
    fn trace(&mut self, _trace: &RequestTrace<'_>) {}

    /// Is told when the client tears the session down.
    ///
    /// `TEARDOWN` is answered by this control layer rather than a [`RouteHandler`], so a
    /// handler that owns session state needs this hook to release it.
    fn teardown(&mut self) {}

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
    /// The protocol records it on the connection and hands it to its caller
    /// It names the remote-control
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

/// A [`RouteHandler`] that serves no route.
///
/// Every delegated route is answered `501 Not Implemented`; this is what
/// [`ControlSession::handle`](super::ControlSession::handle) uses.
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
    /// The head block exceeded [`DEFAULT_MAX_HEAD`](crate::wire::DEFAULT_MAX_HEAD). Answered with
    /// `431 Request Header Fields Too Large`, the code the protocol uses for
    /// overlong request headers.
    HeadTooLarge {
        /// Size of the head that was rejected.
        declared: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// The declared body exceeded [`MAX_CONTROL_BODY`](super::MAX_CONTROL_BODY). Answered with
    /// `400 Bad Request`; the protocol bounds no body, so this is a port limit.
    BodyTooLarge {
        /// Declared body size.
        declared: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// The request carried an `X-Apple-Session-ID` that differs from the one
    /// this connection already used, so it belongs to another session.
    ///
    /// asserts the same equality; the port
    /// answers `400 Bad Request` instead of aborting.
    SessionMismatch,
}

impl ControlError {
    /// Status code and reason phrase the protocol associates with this failure.
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
    /// The response carries no headers: the protocol's `431` path returns before any
    /// header is added, and the port
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
    /// The protocol drops the request in two cases: an unusable `CSeq` value
    /// and a request without `CSeq` while
    /// HLS support is off and the request is not a BLE beacon response
    /// Its httpd then sends no response
    /// at all.
    Ignored,
}
