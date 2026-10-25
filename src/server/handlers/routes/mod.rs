// SPDX-License-Identifier: GPL-3.0-or-later
//! The route handlers themselves, over the values in `types`.

use std::sync::Arc;

use crate::control::{RequestTrace, Route, RouteHandler, RouteReply, RouteRequest};
use crate::fairplay::FairPlaySession;
use crate::server::pairing::{PairingSession, PairingState};

use self::helpers::now_millis;
use super::types::*;

mod helpers;
mod info;
mod pairing;
mod parameters;
mod setup;

#[cfg(test)]
pub(crate) use helpers::stream_connection_id;

/// The handlers one control connection uses.
///
/// The protocol keeps the same state in `raop_conn_t`, so one instance serves one
/// connection: the FairPlay session established by `POST /fp-setup` and the
/// pairing exchange belong to the client that opened it. The receiver-wide half
/// of pairing lives in [`PairingState`], which a caller shares between
/// connections.
pub struct RouteHandlers {
    identity: DeviceIdentity,
    fairplay: FairPlaySession,
    feedback: Option<Box<dyn FnMut() + Send>>,
    /// What a FLUSH does, if the caller wants to do anything.
    flush: Option<Box<dyn FnMut(u16) + Send>>,
    pairing: Option<PairingSession>,
    setup_ports: SetupPorts,
    /// The peer of the connection whose `SETUP` is being served, which is where
    /// the clock exchange has to go.
    peer: Option<std::net::SocketAddr>,
    setup: Option<Box<dyn FnMut(SetupRequest) + Send>>,
    /// Which clients may start a session.
    client_policy: ClientPolicy,
    /// When the last `POST /feedback` arrived, in milliseconds since the Unix epoch.
    ///
    /// A client that keeps a session alive by asking for feedback is a client that is
    /// still there; the transport watches this clock to decide when a silent one has gone.
    feedback_clock: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// What to do with artwork a client sends.
    artwork: Option<ArtworkHandler>,
    /// What to do with the metadata listing a client sends.
    metadata: Option<MetadataHandler>,
    /// What to do with the remote-control identifiers a request carries.
    remote_control: Option<RemoteControlHandler>,
    /// The identifiers the last request carried, so a callback fires when they change
    /// rather than on every request.
    last_remote: Option<(String, String)>,
    /// The volume the client last asked for.
    ///
    /// The protocol keeps the same value on its audio renderer and answers `GET_PARAMETER`
    /// with it; a client that reads back what it set is a
    /// client that can show the right slider. Shared between connections because a
    /// session's volume does not belong to one socket.
    client_volume: std::sync::Arc<std::sync::Mutex<f64>>,
    parameter: Option<Box<dyn FnMut(SetParameter) + Send>>,
    trace: Option<TraceCallback>,
    /// Whether `SETUP` reports its body to the callback.
    ///
    /// Off by default: the body carries the media key, and a receiver that reports it
    /// without being asked hands session material to whatever logs the callback's value.
    debug_body: bool,
    /// What a `TEARDOWN` releases, when the caller owns session state.
    teardown: Option<Box<dyn FnMut() + Send>>,
    authenticated: bool,
    digest_nonce: Option<[u8; 16]>,
}

impl RouteHandlers {
    /// Creates handlers that advertise `identity` and serve the routes that need
    /// no receiver-wide state.
    ///
    /// The pairing routes answer `501 Not Implemented` until a caller adds
    /// [`PairingState`] with [`RouteHandlers::with_pairing`].
    pub fn new(identity: DeviceIdentity) -> Self {
        let identity_volume = identity.initial_volume;
        Self {
            identity,
            fairplay: FairPlaySession::new(),
            feedback: None,
            flush: None,
            pairing: None,
            setup_ports: SetupPorts::default(),
            peer: None,
            setup: None,
            client_policy: ClientPolicy::default(),
            feedback_clock: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(now_millis())),
            client_volume: std::sync::Arc::new(std::sync::Mutex::new(identity_volume)),
            artwork: None,
            metadata: None,
            remote_control: None,
            last_remote: None,
            parameter: None,
            trace: None,
            debug_body: false,
            teardown: None,
            authenticated: false,
            digest_nonce: None,
        }
    }

    /// Creates handlers that advertise `identity` and pair clients with `state`.
    ///
    /// The public key of `state` is what `/info`, `/pair-setup` and the reply of
    /// `/pair-setup-pin` answer with; it replaces
    /// [`DeviceIdentity::public_key`] so that a client can never cache one
    /// identity and be authenticated with another
    pub fn with_pairing(identity: DeviceIdentity, state: Arc<PairingState>) -> Self {
        let mut identity = identity;
        identity.public_key = state.identity_public().to_vec();
        Self {
            pairing: Some(PairingSession::new(state)),
            ..Self::new(identity)
        }
    }

    /// Sets the ports a `SETUP` response may advertise.
    pub fn set_setup_ports(&mut self, ports: SetupPorts) {
        self.setup_ports = ports;
    }

    /// Sets the callback that is told about every request this connection served.
    ///
    /// A trace carries the method, target, `CSeq`, `User-Agent`, `Content-Type`,
    /// body length and answer status of a request, and never a body, key or
    /// signature, so a receiver can be followed against a real client without
    /// printing secrets.
    pub fn set_trace_callback(&mut self, callback: impl FnMut(&RequestTrace<'_>) + Send + 'static) {
        self.trace = Some(Box::new(callback));
    }

    /// Shares the client-visible volume with the other connections of a receiver.
    ///
    /// `GET_PARAMETER` and `/info` answer with this value, so a client that sets the
    /// volume on one connection and reads it on another sees one session, not two.
    pub fn set_client_volume(&mut self, volume: std::sync::Arc<std::sync::Mutex<f64>>) {
        self.client_volume = volume;
    }

    /// Sets whether a `SETUP` reports its body alongside the values it established.
    ///
    /// Off by default. A body carries the media key and the client's session material, so
    /// a receiver turns this on for a diagnostic run and off for a real one.
    pub fn set_debug_body(&mut self, enabled: bool) {
        self.debug_body = enabled;
    }

    /// Sets the callback that runs when a client tears the session down.
    ///
    /// `TEARDOWN` ends the media session, so a receiver that keeps a key, a clock
    /// target or a flush handle releases them here instead of leaving them for the
    /// next session to overwrite.
    pub fn set_teardown_callback(&mut self, callback: impl FnMut() + Send + 'static) {
        self.teardown = Some(Box::new(callback));
    }

    /// Sets the callback that receives what a `SET_PARAMETER` request asked for.
    ///
    /// The protocol applies the same values to its media session
    pub fn set_parameter_callback(&mut self, callback: impl FnMut(SetParameter) + Send + 'static) {
        self.parameter = Some(Box::new(callback));
    }

    /// Sets the callback that receives what a `SETUP` request established.
    ///
    /// The protocol passes the same values straight into its media sessions
    ///; a receiver
    /// without those sessions uses the callback to keep the key for whatever
    /// plays the stream.
    pub fn set_setup_callback(&mut self, callback: impl FnMut(SetupRequest) + Send + 'static) {
        self.setup = Some(Box::new(callback));
    }

    /// The identity these handlers advertise.
    pub fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    /// Sets what to do with artwork a client sends.
    ///
    /// A client sends its cover art as `SET_PARAMETER` with `Content-Type: image/jpeg` or
    /// `image/png`; the protocol hands the bytes to its renderer
    /// and this crate hands them to the caller, which is the only place a file can exist.
    pub fn set_artwork_callback(&mut self, callback: impl FnMut(&str, &[u8]) + Send + 'static) {
        self.artwork = Some(Box::new(callback));
    }

    /// Sets what to do with the metadata listing a client sends.
    ///
    /// The bytes are a DMAP listing; `media::dmap` is how this crate reads it, and the protocol
    /// writes the text to its `-md` file.
    pub fn set_metadata_callback(&mut self, callback: impl FnMut(&[u8]) + Send + 'static) {
        self.metadata = Some(Box::new(callback));
    }

    /// Sets what to do with the remote-control identifiers a request carries.
    ///
    /// `DACP-ID` and `Active-Remote` name the client a remote control belongs to; the protocol
    /// exports them for `-dacp`. They authorize nothing: the headers are
    /// whatever the client wrote.
    pub fn set_remote_control_callback(
        &mut self,
        callback: impl FnMut(&str, &str) + Send + 'static,
    ) {
        self.remote_control = Some(Box::new(callback));
    }

    /// Sets which clients may start a session.
    ///
    /// The protocol consults its `report_client_request` callback in the middle of `SETUP`
    /// and drops the connection when it refuses; this answers
    /// `403 Forbidden` instead, because a client that could not be admitted should be told
    /// that rather than left with a closed socket.
    pub fn set_client_policy(&mut self, policy: ClientPolicy) {
        self.client_policy = policy;
    }

    /// Sets the callback reported for `POST /feedback`.
    ///
    /// The protocol's handler only calls `conn_feedback`
    ///, which is how a receiver notices
    /// that a client is still there; the response is the default `200 OK`.
    pub fn set_feedback_callback(&mut self, callback: impl FnMut() + Send + 'static) {
        self.feedback = Some(Box::new(callback));
    }

    /// Answers `FLUSH`, naming the sequence the client wants to resume at.
    ///
    /// The protocol reads `RTP-Info` for `seq=` and hands that number to its audio thread
    /// A request without
    /// it still flushes: what is buffered is stale either way, and the next packet that
    /// arrives re-establishes the sequence.
    fn flush(&mut self, request: &RouteRequest<'_>) -> RouteReply {
        let next = request
            .head
            .header("rtp-info")
            .and_then(|value| {
                value
                    .split(';')
                    .find_map(|part| part.trim().strip_prefix("seq="))
            })
            .and_then(|seq| seq.trim().parse::<u16>().ok())
            .unwrap_or_default();
        if let Some(callback) = self.flush.as_mut() {
            callback(next);
        }
        RouteReply::ok()
    }

    /// Sets what a `FLUSH` does.
    ///
    /// The request names the sequence number the client considers playable next. A
    /// receiver that ignores it plays back whatever it buffered before the pause.
    pub fn set_flush_callback(&mut self, callback: impl FnMut(u16) + Send + 'static) {
        self.flush = Some(Box::new(callback));
    }
}

impl RouteHandlers {
    /// Reports the remote-control identifiers of a request, once per distinct pair.
    fn report_remote_control(&mut self, request: &RouteRequest<'_>) {
        let dacp = request.head.header("dacp-id");
        let active = request.head.header("active-remote");
        let (Some(dacp), Some(active)) = (dacp, active) else {
            return;
        };
        let pair = (dacp.to_owned(), active.to_owned());
        if self.last_remote.as_ref() == Some(&pair) {
            return;
        }
        self.last_remote = Some(pair.clone());
        if let Some(callback) = self.remote_control.as_mut() {
            callback(&pair.0, &pair.1);
        }
    }
}

impl RouteHandler for RouteHandlers {
    fn feedback_clock(&self) -> Option<std::sync::Arc<std::sync::atomic::AtomicU64>> {
        Some(std::sync::Arc::clone(&self.feedback_clock))
    }

    fn handle(&mut self, route: Route, request: &RouteRequest<'_>) -> Option<RouteReply> {
        self.report_remote_control(request);
        // A configured password protects the routes that change the session and the
        // media, not just `SETUP`: a client that could set the volume, send artwork or
        // flush a stream without authenticating would make the password advisory.
        if matches!(
            route,
            Route::SetParameter | Route::GetParameter | Route::Flush
        ) {
            if let Some(challenge) = self.digest_challenge(request) {
                return Some(challenge);
            }
        }
        match route {
            Route::Feedback => Some(self.feedback_reply()),
            Route::Info => Some(self.info(request)),
            Route::FairPlaySetup => Some(self.fairplay_setup(request)),
            Route::PairPinStart => Some(self.pairing_reply(|session| session.pin_start())),
            Route::PairSetupPin => Some(self.pair_setup_pin(request)),
            Route::PairSetup => {
                let body = request.body;
                Some(self.pairing_reply(|session| session.setup(body)))
            }
            Route::PairVerify => {
                let body = request.body;
                Some(self.pairing_reply(|session| session.verify(body)))
            }
            Route::Setup => Some(self.setup(request)),
            Route::SetParameter => Some(self.set_parameter(request)),
            Route::GetParameter => Some(self.get_parameter(request)),
            Route::Flush => Some(self.flush(request)),
            _ => None,
        }
    }

    fn trace(&mut self, trace: &RequestTrace<'_>) {
        self.report_trace(trace);
    }

    fn teardown(&mut self) {
        if let Some(callback) = self.teardown.as_mut() {
            callback();
        }
    }
}
