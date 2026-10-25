// SPDX-License-Identifier: GPL-3.0-or-later
//! `/info`, `/fp-setup` and the capability documents.

use crate::control::{RouteReply, RouteRequest};
use crate::fairplay::{HANDSHAKE_REQUEST_LEN, SETUP_REQUEST_LEN};
use crate::plist;

use super::super::types::*;
use super::RouteHandlers;
use super::helpers::{
    audio_formats, audio_latencies, binary_plist, displays, octet_stream, qualifier,
};

impl RouteHandlers {
    /// Port of `raop_handler_info`
    ///
    /// Three request shapes reach this handler: a plist `qualifier` request that
    /// asks for a DNS-SD TXT record, a full `GET /info`, and a Bluetooth LE
    /// discovery request without a `CSeq`.
    pub(crate) fn info(&self, request: &RouteRequest<'_>) -> RouteReply {
        let mut dictionary = plist::Dictionary::new();
        let has_cseq = request.head.header("cseq").is_some();
        let content_type = request.head.header("content-type");

        //: the client names the TXT record it wants,
        // either in a binary plist qualifier or, for Bluetooth LE discovery
        // without a CSeq, in the URL.
        let mut add_airplay_txt = false;
        let mut add_raop_txt = false;
        if let Some(content_type) = content_type {
            if content_type.contains("application/x-apple-binary-plist") {
                match qualifier(request.body).as_deref() {
                    Some("txtAirPlay") => add_airplay_txt = true,
                    Some("txtRAOP") => add_raop_txt = true,
                    _ => {}
                }
            }
        } else if !has_cseq {
            add_airplay_txt = request.head.target.contains("txtAirPlay");
            add_raop_txt = request.head.target.contains("txtRAOP");
        }
        if add_airplay_txt {
            let txt = self.identity.txt_airplay.clone().unwrap_or_default();
            dictionary.insert("txtAirPlay".to_owned(), plist::Value::Data(txt));
        }
        if add_raop_txt {
            let txt = self.identity.txt_raop.clone().unwrap_or_default();
            dictionary.insert("txtRAOP".to_owned(), plist::Value::Data(txt));
        }
        //: a request that asked for a TXT record gets
        // nothing else, because it is the Bluetooth LE discovery path.
        if content_type.is_some() {
            return binary_plist(plist::Value::Dictionary(dictionary));
        }

        dictionary.insert(
            "deviceID".to_owned(),
            self.identity.device_id.clone().into(),
        );
        dictionary.insert(
            "macAddress".to_owned(),
            self.identity.device_id.clone().into(),
        );
        dictionary.insert(
            "pk".to_owned(),
            plist::Value::Data(self.identity.public_key.clone()),
        );
        dictionary.insert("features".to_owned(), self.identity.features.into());
        dictionary.insert("name".to_owned(), self.identity.name.clone().into());
        dictionary.insert("pi".to_owned(), self.identity.pi.clone().into());
        dictionary.insert("vv".to_owned(), u64::from(self.identity.vv).into());
        dictionary.insert("statusFlags".to_owned(), STATUS_FLAGS.into());
        dictionary.insert("keepAliveLowPower".to_owned(), 1u64.into());
        dictionary.insert(
            "sourceVersion".to_owned(),
            self.identity.source_version.clone().into(),
        );
        dictionary.insert("keepAliveSendStatsAsBody".to_owned(), true.into());
        dictionary.insert("model".to_owned(), self.identity.model.clone().into());

        //: the Bluetooth LE response stops here.
        if !has_cseq {
            return binary_plist(plist::Value::Dictionary(dictionary));
        }

        let volume = self
            .client_volume
            .lock()
            .map(|volume| *volume)
            .unwrap_or(self.identity.initial_volume);
        dictionary.insert("initialVolume".to_owned(), volume.into());
        dictionary.insert("audioLatencies".to_owned(), audio_latencies());
        dictionary.insert("audioFormats".to_owned(), audio_formats());
        dictionary.insert("displays".to_owned(), displays(&self.identity));
        binary_plist(plist::Value::Dictionary(dictionary))
    }

    /// Port of `raop_handler_fpsetup`
    ///
    /// A 16-byte challenge starts a session and is answered with a 142-byte
    /// reply, a 164-byte challenge completes it and is answered with 32 bytes.
    /// Any other length is a client error the protocol only logs
    ///, and a version or mode this crate does not
    /// implement answers `501 Not Implemented` like the protocol's version check
    pub(crate) fn fairplay_setup(&mut self, request: &RouteRequest<'_>) -> RouteReply {
        let body = request.body;
        if body.len() == SETUP_REQUEST_LEN {
            match self.fairplay.setup(body) {
                Ok(response) => octet_stream(response.to_vec()),
                Err(_) => RouteReply::not_implemented(),
            }
        } else if body.len() == HANDSHAKE_REQUEST_LEN {
            match self.fairplay.handshake(body) {
                Ok(response) => octet_stream(response.to_vec()),
                Err(_) => RouteReply::not_implemented(),
            }
        } else {
            RouteReply::ok()
        }
    }
}
