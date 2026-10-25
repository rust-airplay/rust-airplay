// SPDX-License-Identifier: GPL-3.0-or-later
//! Values several routes share: plists, capability documents and identifiers.

use crate::control::RouteReply;
use crate::plist::{self, Plist};

use super::super::types::*;

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Streams one `SETUP` request may ask for.
///
/// A real client asks for one audio stream and, while mirroring, one more; the
/// bound keeps a request from making this receiver build an unbounded answer.
pub(super) const MAX_SETUP_STREAMS: usize = 4;

pub(super) fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or(0)
}

/// `qualifier` array of a `GET /info` request, first string entry
pub(super) fn qualifier(body: &[u8]) -> Option<String> {
    let request = Plist::parse(body).ok()?;
    let first = request.get_array("qualifier").ok()?.first()?;
    first.as_string().map(str::to_owned)
}

/// Wraps `value` into a binary plist response
///
/// Encoding a dictionary of strings, integers, reals, booleans and data cannot
/// fail, so the `500` is a safety net rather than an expected answer: a client
/// must never receive a truncated body it would parse as a valid plist.
pub(super) fn binary_plist(value: plist::Value) -> RouteReply {
    match Plist::from_value(value).encode_binary() {
        Ok(body) => RouteReply::ok()
            .with_header("Content-Type", "application/x-apple-binary-plist")
            .with_body(body),
        Err(_) => RouteReply::new(500, "Internal Server Error"),
    }
}

/// FairPlay reply with an opaque body
pub(super) fn octet_stream(body: Vec<u8>) -> RouteReply {
    RouteReply::ok()
        .with_header("Content-Type", "application/octet-stream")
        .with_body(body)
}

/// `audioLatencies` array.
pub(super) fn audio_latencies() -> plist::Value {
    let default = |audio_type_identifier: u64| {
        plist::dictionary([
            ("type", plist::Value::from(audio_type_identifier)),
            ("inputLatencyMicros", plist::Value::from(0u64)),
            ("audioType", plist::Value::from("default")),
            ("outputLatencyMicros", plist::Value::from(false)),
        ])
    };
    plist::Value::Array(vec![default(100), default(101)])
}

/// `audioFormats` array.
pub(super) fn audio_formats() -> plist::Value {
    let format = |audio_type_identifier: u64| {
        plist::dictionary([
            (
                "audioOutputFormats",
                plist::Value::from(AUDIO_OUTPUT_FORMATS),
            ),
            ("type", plist::Value::from(audio_type_identifier)),
            (
                "audioInputFormats",
                plist::Value::from(AUDIO_OUTPUT_FORMATS),
            ),
        ])
    };
    plist::Value::Array(vec![format(100), format(101)])
}

/// `displays` array.
///
/// The single entry describes the virtual display the receiver renders to.
pub(super) fn displays(identity: &DeviceIdentity) -> plist::Value {
    // The protocol sends the frame interval and divides by the refresh rate
    //; a rate that is not positive would divide by zero,
    // so the port reports `0.0` for an interval it cannot compute.
    let refresh_interval = if identity.refresh_rate > 0.0 {
        1.0 / identity.refresh_rate
    } else {
        0.0
    };
    let display = plist::dictionary([
        ("uuid", plist::Value::from(DISPLAY_UUID)),
        ("widthPhysical", plist::Value::from(0u64)),
        ("heightPhysical", plist::Value::from(0u64)),
        ("width", plist::Value::from(identity.width)),
        ("height", plist::Value::from(identity.height)),
        ("widthPixels", plist::Value::from(identity.width)),
        ("heightPixels", plist::Value::from(identity.height)),
        ("rotation", plist::Value::from(false)),
        ("refreshRate", plist::Value::from(refresh_interval)),
        ("maxFPS", plist::Value::from(identity.max_fps)),
        ("overscanned", plist::Value::from(identity.overscanned)),
        ("features", plist::Value::from(DISPLAY_FEATURES)),
    ]);
    plist::Value::Array(vec![display])
}

pub(super) fn describe_plist(plist: &Plist) -> String {
    fn describe(value: &plist::Value, depth: usize) -> String {
        let indent = "  ".repeat(depth);
        match value {
            plist::Value::Dictionary(dictionary) => {
                let mut out = format!("dict({})", dictionary.len());
                for (key, value) in dictionary {
                    out.push_str(&format!(
                        "\n{indent}  {key}: {}",
                        describe(value, depth + 1)
                    ));
                }
                out
            }
            plist::Value::Array(values) => {
                let mut out = format!("array({})", values.len());
                for (index, value) in values.iter().enumerate() {
                    out.push_str(&format!(
                        "\n{indent}  [{index}]: {}",
                        describe(value, depth + 1)
                    ));
                }
                out
            }
            plist::Value::Data(bytes) => {
                let shown: Vec<String> = bytes
                    .iter()
                    .take(16)
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                format!(
                    "data({} bytes){}{}",
                    bytes.len(),
                    if bytes.is_empty() { "" } else { " " },
                    shown.join("")
                )
            }
            plist::Value::Boolean(value) => format!("bool({value})"),
            plist::Value::Integer(value) => format!("int({value})"),
            plist::Value::Real(value) => format!("real({value})"),
            plist::Value::String(value) => format!("string({value:?})"),
            plist::Value::Uid(value) => format!("uid({value:?})"),
            other => format!("{other:?}"),
        }
    }
    match plist.root_dictionary() {
        Some(dictionary) => {
            let mut out = String::new();
            for (key, value) in dictionary {
                out.push_str(&format!("  {key}: {}\n", describe(value, 1)));
            }
            out
        }
        None => "  (not a dictionary)\n".to_owned(),
    }
}

/// The `streamConnectionID` of one `SETUP` stream entry, if it names a usable one.
///
/// The value is a 64-bit identifier a client may write as a *signed* number, and a
/// device does: one sent `Integer(-4578581632668906207)`, which is
/// `0xc0759c4371a44d21`. The protocol formats it with `%llu`
///, which prints those same bits
/// as unsigned, so the value is **reinterpreted** rather than converted: a negative
/// number is not an out-of-range identifier, it is the same identifier written down
/// differently, and converting it instead makes the stream unkeyable in a session
/// where the client named it all along.
///
/// A real is read too, because that is another way a client writes a number, but only
/// when it is a whole one: this value is a key input, and a rounded one derives a
/// stream nobody can read.
pub(crate) fn stream_connection_id(stream: &plist::Dictionary) -> Option<u64> {
    let value = stream.get("streamConnectionID")?;
    if let Some(unsigned) = value.as_unsigned_integer() {
        return Some(unsigned);
    }
    if let Some(signed) = value.as_signed_integer() {
        return Some(u64::from_ne_bytes(signed.to_ne_bytes()));
    }
    let real = value.as_real()?;
    if !real.is_finite() || real.fract() != 0.0 {
        return None;
    }
    #[allow(clippy::cast_possible_truncation)]
    let signed = real as i64;
    #[allow(clippy::cast_precision_loss)]
    let round_trips = (signed as f64) == real;
    round_trips.then(|| u64::from_ne_bytes(signed.to_ne_bytes()))
}
