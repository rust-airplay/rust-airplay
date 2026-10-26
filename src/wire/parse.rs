// SPDX-License-Identifier: GPL-3.0-or-later
//! Parsing an RTSP/HTTP request head and body.

use std::fmt;

use super::limits::{DEFAULT_MAX_HEAD, HeadLimits};
use super::message::MessageHead;

/// Why a request could not be framed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// More bytes are needed before the message is whole; read more and try again.
    Incomplete,
    /// The input is malformed. The string names the part that was refused, so a caller can
    /// log it without turning a parser into a prose generator.
    Invalid(&'static str),
    /// A bound was exceeded. The caller answers `431 Request Header Fields Too Large` for a
    /// head and drops a body it cannot accept.
    TooLarge {
        /// Size the message asked for, in bytes or fields.
        declared: usize,
        /// Largest size this parser accepts.
        maximum: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete => f.write_str("incomplete input"),
            Self::Invalid(reason) => write!(f, "invalid input: {reason}"),
            Self::TooLarge { declared, maximum } => {
                write!(f, "size {declared} exceeds maximum {maximum}")
            }
        }
    }
}
impl std::error::Error for ParseError {}

/// Parses one request head bounded by [`DEFAULT_MAX_HEAD`].
///
/// # Examples
///
/// ```
/// use rust_airplay::wire::parse_request_head;
///
/// let head = parse_request_head(b"SETUP rtsp://receiver/1 RTSP/1.0\r\nCSeq: 3\r\n\r\n")
///     .expect("a complete request");
/// assert_eq!(head.method, "SETUP");
/// assert_eq!(head.target, "rtsp://receiver/1");
/// assert_eq!(head.header("cseq"), Some("3"));
/// ```
pub fn parse_request_head(input: &[u8]) -> Result<MessageHead, ParseError> {
    parse_request_head_with_maximum(input, DEFAULT_MAX_HEAD)
}

/// Parses one request head, rejecting a header block larger than `maximum`.
///
/// Returns [`ParseError::Incomplete`] while the terminating CRLF CRLF is still
/// missing and the accumulated input is within `maximum`, and
/// [`ParseError::TooLarge`] once a head without terminator outgrows the bound or
/// the terminator itself sits past it. The per-field bounds of [`HeadLimits`]
/// apply as well.
pub fn parse_request_head_with_maximum(
    input: &[u8],
    maximum: usize,
) -> Result<MessageHead, ParseError> {
    parse_request_head_with_limits(
        input,
        HeadLimits {
            max_head: maximum,
            ..HeadLimits::default()
        },
    )
}

/// Parses one request head, rejecting it when it breaks any bound of `limits`.
///
/// # Errors
///
/// Returns [`ParseError::Incomplete`] while the head is still incomplete,
/// [`ParseError::TooLarge`] for a bound the caller turns into `431`, and
/// [`ParseError::Invalid`] for a head that is malformed or uses framing the parser does not
/// support.
pub fn parse_request_head_with_limits(
    input: &[u8],
    limits: HeadLimits,
) -> Result<MessageHead, ParseError> {
    let end = match input.windows(4).position(|window| window == b"\r\n\r\n") {
        Some(end) if end + 4 <= limits.max_head => end,
        Some(end) => {
            return Err(ParseError::TooLarge {
                declared: end + 4,
                maximum: limits.max_head,
            });
        }
        None if input.len() > limits.max_head => {
            return Err(ParseError::TooLarge {
                declared: input.len(),
                maximum: limits.max_head,
            });
        }
        None => return Err(ParseError::Incomplete),
    };
    let text = std::str::from_utf8(&input[..end]).map_err(|_| ParseError::Invalid("headers"))?;
    let mut lines = text.split("\r\n");
    let first = lines.next().ok_or(ParseError::Invalid("start line"))?;
    let mut fields = first.split_ascii_whitespace();
    let method = fields.next().ok_or(ParseError::Invalid("method"))?;
    let target = fields.next().ok_or(ParseError::Invalid("target"))?;
    let version = fields.next().ok_or(ParseError::Invalid("version"))?;
    if fields.next().is_some() || (!version.starts_with("RTSP/") && !version.starts_with("HTTP/")) {
        return Err(ParseError::Invalid("start line"));
    }
    // bounds the protocol to
    // four bytes and the version number to three and rejects anything longer as
    // malformed. Without the bound a client could reflect an arbitrarily long
    // token back through the status line, which is why the port rejects it too.
    let (protocol, number) = version
        .split_once('/')
        .ok_or(ParseError::Invalid("version"))?;
    if protocol.len() != 4 || number.len() != 3 {
        return Err(ParseError::Invalid("version"));
    }
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: Option<&str> = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(ParseError::Invalid("header"))?;
        if name.is_empty() || name.bytes().any(|byte| byte <= 0x20 || byte >= 0x7f) {
            return Err(ParseError::Invalid("header name"));
        }
        let value = value.trim();
        // The three per-field bounds of,
        // which the protocol checks in its request handler and answers with `431`.
        if name.len() > limits.max_field_len {
            return Err(ParseError::TooLarge {
                declared: name.len(),
                maximum: limits.max_field_len,
            });
        }
        if value.len() > limits.max_value_len {
            return Err(ParseError::TooLarge {
                declared: value.len(),
                maximum: limits.max_value_len,
            });
        }
        // llhttp would decode a chunked body and drop the connection on any
        // other transfer coding. Neither is worth implementing here, because no
        // AirPlay client sends one, so a request that asks for either is refused
        // instead of being framed by its `Content-Length` and desynchronising the
        // stream.
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(ParseError::Invalid("transfer-encoding"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            // Only decimal digits are a length, and a second header would leave
            // the message boundary ambiguous, so neither is accepted.
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(ParseError::Invalid("content-length"));
            }
            if content_length.is_some() {
                return Err(ParseError::Invalid("content-length"));
            }
            content_length = Some(value);
        }
        headers.push((name.to_ascii_lowercase(), value.to_owned()));
        if headers.len() > limits.max_fields {
            return Err(ParseError::TooLarge {
                declared: headers.len(),
                maximum: limits.max_fields,
            });
        }
    }
    Ok(MessageHead {
        method: method.to_owned(),
        target: target.to_owned(),
        version: version.to_owned(),
        headers,
        consumed: end + 4,
    })
}

/// Takes the first `length` bytes as the body.
///
/// Returns [`ParseError::Incomplete`] when the input carries fewer bytes than the head
/// promised, which is the normal state of a body still arriving in pieces.
///
/// # Errors
///
/// Returns [`ParseError::Incomplete`] for input shorter than `length`.
pub fn split_body(input: &[u8], length: usize) -> Result<&[u8], ParseError> {
    input.get(..length).ok_or(ParseError::Incomplete)
}
