// SPDX-License-Identifier: GPL-3.0-or-later
//! `/pair-pin-start`, `/pair-setup` and `/pair-verify` handling.

use crate::control::{RouteReply, RouteRequest};
use crate::server::pairing::{PairingError, PairingReply, PairingSession};

use super::RouteHandlers;
use super::helpers::{binary_plist, octet_stream};

impl RouteHandlers {
    /// Runs one pairing step on this connection's session.
    ///
    /// Without a [`PairingState`] the route stays unimplemented, which is what
    /// the control layer reports for a route the protocol serves and this crate does
    /// not.
    pub(super) fn pairing_reply(
        &mut self,
        step: impl FnOnce(&mut PairingSession) -> Result<PairingReply, PairingError>,
    ) -> RouteReply {
        let Some(session) = self.pairing.as_mut() else {
            return RouteReply::not_implemented();
        };
        match step(session) {
            Ok(PairingReply::Silence) => RouteReply::ok(),
            Ok(PairingReply::Plist(value)) => binary_plist(value),
            Ok(PairingReply::Octets(body)) => octet_stream(body),
            //: the default reply without a content
            // type, and the connection is closed afterwards.
            Ok(PairingReply::Disconnect) => RouteReply::ok().closing(),
            Err(error) => RouteReply::new(error.status(), error.reason()),
        }
    }

    /// Port of `raop_handler_pairsetup_pin`
    pub(super) fn pair_setup_pin(&mut self, request: &RouteRequest<'_>) -> RouteReply {
        //: the protocol requires the header block to
        // mention the binary plist format and answers 470 otherwise. It searches
        // the whole head, the port only its `Content-Type`.
        let is_plist = request
            .head
            .header("content-type")
            .is_some_and(|value| value.contains("apple-binary-plist"));
        if !is_plist {
            let error = PairingError::NotPlist;
            return RouteReply::new(error.status(), error.reason());
        }
        let body = request.body;
        self.pairing_reply(|session| session.setup_pin(body))
    }
}
