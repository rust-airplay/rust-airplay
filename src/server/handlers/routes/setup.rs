// SPDX-License-Identifier: GPL-3.0-or-later
//! `SETUP`: stream registration, the audio key and the digest challenge.

use crate::control::{RouteReply, RouteRequest};
use std::sync::Arc;

use crate::crypto::sha512_concat;
use crate::pairing::parse_digest_authorization;
use crate::plist::{self, Plist};
use crate::server::pairing::SessionAuth;

use super::super::types::*;
use super::RouteHandlers;
use super::helpers::{MAX_SETUP_STREAMS, binary_plist, describe_plist, hex, stream_connection_id};

impl RouteHandlers {
    /// Port of `raop_handler_setup`
    ///
    /// This step covers what an AirPlay 1 client sends: the encrypted audio key
    /// with its IV, and the streams it wants. Later steps add the digest
    /// password branch (`:650-748`) and the media and timing sessions the
    /// handler starts (`:910-929`); a receiver without them answers the ports it
    /// actually has.
    pub(crate) fn setup(&mut self, request: &RouteRequest<'_>) -> RouteReply {
        // The clock exchange goes to the address a client's control connection came
        // from, so the request has to say which that was
        //.
        self.peer = request.peer;
        // The password gate comes first, before any of the body is looked at:
        // the protocol parses the property list before it challenges
        //, and a receiver should not spend work on a
        // request that has not authenticated yet.
        if let Some(challenge) = self.digest_challenge(request) {
            return challenge;
        }
        // The protocol reads the body with `plist_from_bin` and carries on with an
        // empty request when that fails (`:601-644`); a malformed body is
        // refused here instead, because the alternative is a `200 OK` that
        // describes a session nobody can use.
        if !request.body.starts_with(b"bplist00") {
            return RouteReply::new(400, "Bad Request");
        }
        let Ok(body) = Plist::parse(request.body) else {
            return RouteReply::new(400, "Bad Request");
        };

        // Who is asking decides whether there is a session at all. The protocol consults its
        // callback at the same point, after the password gate and before it derives keys
        //.
        let client = ClientRequest {
            device_id: body.get_string("deviceID").unwrap_or_default().to_owned(),
            model: body.get_string("model").unwrap_or_default().to_owned(),
            name: body.get_string("name").unwrap_or_default().to_owned(),
        };
        if !self.client_policy.admits(&client) {
            log::info!(
                "media     refused {} ({}, model {})",
                client.name,
                client.device_id,
                client.model
            );
            return RouteReply::new(403, "Forbidden");
        }

        //: both keys are read as fixed-size buffers
        // there, without looking at the length the client sent.
        let audio_iv = match body.get_data("eiv").ok() {
            Some(iv) => match <[u8; 16]>::try_from(iv) {
                Ok(iv) => Some(iv),
                Err(_) => return RouteReply::new(400, "Bad Request"),
            },
            None => None,
        };
        let encrypted = body.get_data("ekey").ok();
        let mut client_identity = None;
        let (audio_key, audio_iv) = match (encrypted, audio_iv) {
            // A mirror-only setup carries neither,.
            (None, None) => (None, None),
            (Some(encrypted), Some(iv)) => {
                if encrypted.len() != 72 {
                    return RouteReply::new(400, "Bad Request");
                }
                let mut key = match self.fairplay.decrypt(encrypted) {
                    Ok(key) => key,
                    // The protocol logs the failure and keeps going with whatever the
                    // buffer held (`:807-813`).
                    Err(_) => return RouteReply::new(400, "Bad Request"),
                };
                if let Some(session) = self.pairing.as_mut() {
                    if let Some(keys) = session.take_session_keys() {
                        //: the key is hashed with the
                        // shared secret of a pairing session, which this crate
                        // only produces for a connection that verified the
                        // client (`pairing.c:108-119` is what it narrows).
                        let digest = sha512_concat(&[&key, &keys.ecdh_secret]);
                        key.copy_from_slice(&digest[..16]);
                        client_identity = keys.client_identity;
                    }
                }
                (Some(key), Some(iv))
            }
            // Half a key pair is a request that cannot be answered.
            _ => return RouteReply::new(400, "Bad Request"),
        };

        //: the port the client listens on for the clock
        // exchange, which the receiver has to send its requests to. The receiver
        // starts that exchange, so a session that never learns this crate never
        // ticks.
        // What the request actually carried, for a device session that has to be
        // read afterwards. A `SETUP` is where clients differ most.
        let keys: Vec<String> = body
            .root_dictionary()
            .map(|dictionary| dictionary.keys().cloned().collect())
            .unwrap_or_default();

        let client_timing_port = body
            .get("timingPort")
            .and_then(plist::Value::as_unsigned_integer)
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0);

        //: every requested stream is answered with
        // the port the receiver listens on, in request order.
        let mut streams = Vec::new();
        if let Ok(requested) = body.get_array("streams") {
            if requested.len() > MAX_SETUP_STREAMS {
                return RouteReply::new(400, "Bad Request");
            }
            for stream in requested {
                let Some(stream) = stream.as_dictionary() else {
                    return RouteReply::new(400, "Bad Request");
                };
                let Some(kind) = stream
                    .get("type")
                    .and_then(plist::Value::as_unsigned_integer)
                    .and_then(|kind| u16::try_from(kind).ok())
                else {
                    return RouteReply::new(400, "Bad Request");
                };
                let connection_id = stream_connection_id(stream);
                // What the entry actually carried, for a device that names its mirror
                // stream in one session and not in the next: the difference is either in
                // the request or in this reader, and only the keys can say which.
                if connection_id.is_none() {
                    let keys: Vec<&str> = stream.keys().map(String::as_str).collect();
                    log::debug!("set     stream type {kind} carried [{}]", keys.join(", "));
                }
                // The protocol's `switch` has no default arm: an unknown type is
                // simply not answered (`:954-1050`).
                if !matches!(kind, 96 | 110) {
                    continue;
                }
                // The coding a client is sending, which is what decides the decoder: `ct`
                // is 2 for ALAC and 8 for AAC-ELD, and `spf` is the
                // samples a frame carries. Read here rather than assumed downstream,
                // because a receiver that guesses is wrong for every client that uses the
                // other coding and cannot tell that it is.
                let compression_type = stream
                    .get("ct")
                    .and_then(plist::Value::as_unsigned_integer)
                    .and_then(|value| u16::try_from(value).ok());
                let samples_per_frame = stream
                    .get("spf")
                    .and_then(plist::Value::as_unsigned_integer)
                    .and_then(|value| u16::try_from(value).ok());
                let control_port = stream
                    .get("controlPort")
                    .and_then(plist::Value::as_unsigned_integer)
                    .and_then(|value| u16::try_from(value).ok())
                    .filter(|port| *port != 0);
                streams.push(SetupStream {
                    kind,
                    stream_connection_id: connection_id,
                    compression_type,
                    samples_per_frame,
                    control_port,
                });
            }
        }

        let mut dictionary = plist::Dictionary::new();
        if let Some(port) = self.setup_ports.timing_port {
            dictionary.insert("timingPort".to_owned(), u64::from(port).into());
        }
        // The protocol answers `eventPort` unconditionally, with `0` when there is no
        // event channel. A response that omitted the
        // key is a different shape from the one a client was written against.
        dictionary.insert(
            "eventPort".to_owned(),
            u64::from(self.setup_ports.event_port_or_zero()).into(),
        );
        if !streams.is_empty() {
            let answer = streams
                .iter()
                .map(|stream| {
                    let mut entry = plist::Dictionary::new();
                    let port = match stream.kind {
                        110 => self.setup_ports.mirror_data_port,
                        _ => self.setup_ports.data_port,
                    };
                    if let Some(port) = port {
                        entry.insert("dataPort".to_owned(), u64::from(port).into());
                    }
                    if stream.kind == 96 {
                        if let Some(port) = self.setup_ports.control_port {
                            entry.insert("controlPort".to_owned(), u64::from(port).into());
                        }
                    }
                    entry.insert("type".to_owned(), u64::from(stream.kind).into());
                    plist::Value::Dictionary(entry)
                })
                .collect();
            dictionary.insert("streams".to_owned(), plist::Value::Array(answer));
        }
        let authentication = self
            .pairing
            .as_ref()
            .map(|session| session.authentication())
            .unwrap_or(SessionAuth::None);
        self.report_setup(SetupRequest {
            audio_key,
            audio_iv,
            streams,
            client_timing_port,
            client_address: self.peer,
            debug_body: self.debug_body.then(|| describe_plist(&body)),
            keys,
            client_identity,
            authentication,
        });
        binary_plist(plist::Value::Dictionary(dictionary))
    }

    /// RFC 2617 password gate of `SETUP`, or `None` when the request may pass.
    ///
    /// The protocol keeps the same three facts on its receiver: whether the
    /// connection authenticated, the challenge it handed out, and how many
    /// attempts failed.
    /// The port keeps the nonce and the flag per connection and the failure count
    /// on the shared receiver state, so guessing across connections costs
    /// attempts. The nonce is one the port drew from its own random source
    /// instead of the protocol's construction, which hashes a heap address.
    pub(super) fn digest_challenge(&mut self, request: &RouteRequest<'_>) -> Option<RouteReply> {
        let state = Arc::clone(self.pairing.as_ref()?.shared());
        if !state.has_password() || self.authenticated {
            return None;
        }
        let method = request.head.method.as_str();
        if let Some(header) = request.head.header("authorization") {
            if let Some(parsed) = parse_digest_authorization(header) {
                let nonce_matches = self
                    .digest_nonce
                    .is_some_and(|nonce| hex(&nonce) == parsed.nonce);
                // The challenge is single use, whether or not it matched.
                self.digest_nonce = None;
                if nonce_matches && state.verify_password_digest(method, &parsed).is_ok() {
                    self.authenticated = true;
                    return None;
                }
            }
        }
        let mut nonce = [0u8; 16];
        if state.fill_random(&mut nonce).is_err() {
            // Without randomness there is no challenge worth sending.
            return Some(RouteReply::new(401, "Unauthorized"));
        }
        self.digest_nonce = Some(nonce);
        Some(RouteReply::new(401, "Unauthorized").with_header(
            "WWW-Authenticate",
            &format!("Digest realm=\"raop\", nonce=\"{}\"", hex(&nonce)),
        ))
    }

    /// Reports an accepted `SETUP` to the callback of this connection.
    fn report_setup(&mut self, request: SetupRequest) {
        if let Some(callback) = self.setup.as_mut() {
            callback(request);
        }
    }
}
