// SPDX-License-Identifier: GPL-3.0-or-later
//! `SET_PARAMETER`, `GET_PARAMETER` and `/feedback`.

use crate::control::{RequestTrace, RouteReply, RouteRequest};

use super::super::types::*;
use super::RouteHandlers;
use super::helpers::now_millis;

impl RouteHandlers {
    /// Port of `raop_handler_set_parameter`
    ///
    /// The protocol reads the body of a `text/parameters` request with `sscanf` and hands the
    /// result to its media layer; cover art and the DMAP listing are routed to callbacks the
    /// same way. This crate parses every parameter line instead of only the first, reports
    /// each one, and passes artwork and metadata to the callbacks a caller installed. A
    /// content type with no callback is answered `200` and dropped, which is what a receiver
    /// without that feature does.
    pub(crate) fn set_parameter(&mut self, request: &RouteRequest<'_>) -> RouteReply {
        let Some(content_type) = request.head.header("content-type") else {
            // The protocol answers the same status for a request that says nothing
            // about what it carries (`:1135-1139`).
            return RouteReply::new(451, "Parameter not understood");
        };
        let media_type = content_type.trim();
        if media_type == "image/jpeg" || media_type == "image/png" {
            if let Some(callback) = self.artwork.as_mut() {
                callback(media_type, request.body);
            }
            return RouteReply::new(200, "OK");
        }
        if media_type == "application/x-dmap-tagged" {
            if let Some(callback) = self.metadata.as_mut() {
                callback(request.body);
            }
            return RouteReply::new(200, "OK");
        }
        if media_type != "text/parameters" {
            return RouteReply::new(200, "OK");
        }
        // Every line is read, not just the first: the protocol reads the start of the body
        // (`:1146`, `:1155`), but a client that sends `progress` before `volume` would have
        // its volume request dropped. The debug line carries the line that was understood,
        // so a session that changes nothing can be traced to what actually arrived.
        let mut understood = false;
        for line in request.body.split(|byte| *byte == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let Ok(line) = std::str::from_utf8(line) else {
                continue;
            };
            let parsed = line
                .strip_prefix("volume: ")
                .and_then(|value| value.trim().parse::<f32>().ok())
                // A value no media layer can use is ignored rather than passed on:
                // the protocol's `sscanf` would leave its variable at zero.
                .filter(|volume| volume.is_finite())
                .map(SetParameter::Volume)
                .or_else(|| {
                    line.strip_prefix("progress: ").and_then(|value| {
                        let mut parts = value.trim().split('/');
                        let start = parts.next()?.parse().ok()?;
                        let current = parts.next()?.parse().ok()?;
                        let end = parts.next()?.parse().ok()?;
                        parts.next().is_none().then_some(SetParameter::Progress {
                            start,
                            current,
                            end,
                        })
                    })
                });
            let Some(parsed) = parsed else {
                continue;
            };
            log::debug!("set_parameter: {parsed:?} from {line:?}");
            if let SetParameter::Volume(level) = &parsed {
                // The client's value is what the receiver plays at from here on, and
                // what it answers with when asked; the protocol does the same through its
                // renderer. The scale is decibels: -30 is silence and 0 is full, and a
                // value outside it is clamped the way the protocol clamps it. `-144` is the
                // client's mute signal and is kept as sent, because it is what
                // `GET_PARAMETER` reports back.
                let value = f64::from(*level);
                // A positive value is not decibels (0 is full scale), so it is a slider
                // position and is kept as sent rather than clamped to full; `GET_PARAMETER`
                // then answers the same number the client gave.
                let db = if value > 0.0 {
                    value.min(100.0)
                } else if value == -144.0 {
                    -144.0
                } else {
                    value.clamp(-30.0, 0.0)
                };
                if let Ok(mut volume) = self.client_volume.lock() {
                    *volume = db;
                }
            }
            understood = true;
            if let Some(callback) = self.parameter.as_mut() {
                callback(parsed);
            }
        }
        if !understood {
            // A body this crate did not understand is exactly what a "the volume does
            // nothing" session needs to show: it is read back here, bounded, and only at
            // debug level.
            log::debug!(
                "set_parameter: nothing understood from {:?}",
                String::from_utf8_lossy(&request.body[..request.body.len().min(80)])
            );
        }
        RouteReply::new(200, "OK")
    }

    /// Port of `raop_handler_get_parameter`
    ///
    /// A client that asks about `volume` gets the value its own player reported,
    /// which the protocol reads from its media callbacks and defaults to `0.0`
    /// without them (`:1093-1097`). This crate has no media layer, so it answers
    /// that default instead of inventing a level.
    pub(crate) fn get_parameter(&mut self, request: &RouteRequest<'_>) -> RouteReply {
        let Some(content_type) = request.head.header("content-type") else {
            return RouteReply::new(451, "Parameter not understood");
        };
        if content_type.trim() != "text/parameters" {
            return RouteReply::new(200, "OK");
        }
        if request.body.starts_with(b"volume") {
            let volume = self
                .client_volume
                .lock()
                .map(|volume| *volume)
                .unwrap_or(0.0);
            return RouteReply::new(200, "OK")
                .with_header("Content-Type", "text/parameters")
                .with_body(format!("volume: {volume:9.6}\r\n").into_bytes());
        }
        RouteReply::new(200, "OK")
    }

    /// Reports one served request to the trace callback of this connection.
    pub(super) fn report_trace(&mut self, trace: &RequestTrace<'_>) {
        if let Some(callback) = self.trace.as_mut() {
            callback(trace);
        }
    }

    /// Port of `raop_handler_feedback`
    pub(super) fn feedback_reply(&mut self) -> RouteReply {
        self.feedback_clock
            .store(now_millis(), std::sync::atomic::Ordering::Relaxed);
        if let Some(callback) = self.feedback.as_mut() {
            callback();
        }
        RouteReply::ok()
    }
}
