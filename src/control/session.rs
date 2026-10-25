// SPDX-License-Identifier: GPL-3.0-or-later
//! One connection's RTSP session state and the framing of its replies.

use std::net::SocketAddr;

use crate::wire::{DEFAULT_MAX_HEAD, ParseError, parse_request_head_with_maximum, split_body};

use super::*;

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
    /// Creates a session with the protocol's defaults: HLS support off and a
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

    /// Enables HLS request handling, mirroring the protocol's `-hls` option.
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
    /// receiver starts. A session with no peer serves
    /// requests whose routes do not need one.
    pub fn set_peer(&mut self, peer: SocketAddr) {
        self.peer = Some(peer);
    }

    /// Sets the audio delay reported by `RECORD` in `Audio-Latency`.
    ///
    /// The accepted range is `0..=MAX_AUDIO_DELAY_MICROS`; validating configuration input is
    /// the configuration layer's job, and this stores the value as given.
    pub fn set_audio_delay_micros(&mut self, micros: u32) {
        self.audio_delay_micros = micros;
    }

    /// Handles one complete request and decides what to write back.
    ///
    /// The steps are: bound and parse the head, then bound the declared body and require it to
    /// be present; read `CSeq` and drop the request when it is unusable; drop a request without
    /// `CSeq` unless HLS support is on or it is a BLE beacon response; bind the connection to
    /// the first `X-Apple-Session-ID` it sees and reject a later different one; route by method
    /// and URL; and add the headers the protocol adds - `Audio-Jack-Status`, the handler's
    /// headers, `Server` and `CSeq`.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] when the request cannot be acted on; the caller
    /// answers with [`ControlError::to_response`], whose status code comes from
    /// [`ControlError::status`].
    ///
    /// This is [`ControlSession::handle_with`] with a [`NoHandler`], so a delegated route is
    /// answered `501 Not Implemented`.
    pub fn handle(&mut self, input: &[u8]) -> Result<ControlOutcome, ControlError> {
        self.handle_with(input, &mut NoHandler)
    }

    /// Handles one complete request, letting `handler` serve the routes this layer delegates.
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
                // The protocol drops a request whose CSeq is not a non-negative
                // integer instead of answering it.
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
            Dispatch::Local(route) => {
                if route == Route::Teardown {
                    handler.teardown();
                }
                self.observe(route);
                ported_reply(route, self.audio_delay_micros)
            }
            // The route is delegated; a handler that does not serve it answers 501 rather than
            // pretending to succeed. A handler that does serve it also gives the route its
            // lifecycle meaning, which is why the state is observed here and not for a 501.
            Dispatch::Delegated(route) => {
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
    /// The mapping is monotone and permissive, because the protocol answers all of
    /// these routes with `200 OK` regardless of what came before
    ///
    /// `OPTIONS` never changes the state, a second `SETUP` does not rewind a
    /// recording session, and `FLUSH` outside a recording session is a no-op
    /// the protocol only logs a warning about.
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
/// `OPTIONS` and `RECORD` contribute the headers their the protocol handlers add
///, and `TEARDOWN`
/// asks the peer to close the connection.
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
