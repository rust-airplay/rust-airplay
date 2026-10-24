// SPDX-License-Identifier: GPL-3.0-or-later
//! Incremental, bounded RTSP/HTTP wire parsing.
//!
//! A control connection is a byte stream, not a sequence of messages: a request can arrive
//! in pieces, two requests can arrive in one read, and a peer can send a header block larger
//! than any receiver should buffer. [`parse_request_head`] is the incremental half - it
//! returns [`ParseError::Incomplete`] until the head is whole - and [`split_body`] is the
//! other: once the head says how long the body is, the caller reads exactly that many bytes.
//!
//! Every bound here is a refusal rather than a truncation. A head this module cannot frame is
//! answered with `431` by the caller, and a request that asks for an unsupported transfer
//! coding is refused because framing it by `Content-Length` instead would desynchronise the
//! connection.

use std::fmt;

/// Largest request body accepted by default: eight mebibytes.
///
/// The largest body an AirPlay client sends is a `SETUP` plist, which is measured in
/// kilobytes; the bound exists so a peer cannot make a receiver allocate without limit.
pub const DEFAULT_MAX_BODY: usize = 8 * 1024 * 1024;
/// Largest accepted request head: start line plus headers, including the
/// terminating CRLF CRLF. Callers accumulate the head before parsing it, so it
/// needs its own bound even though bodies already have one.
pub const DEFAULT_MAX_HEAD: usize = 64 * 1024;

/// Largest number of header fields one request may carry.
///
/// The protocol rejects a request beyond this, or beyond one of the two lengths
/// below, with `431 Request Header Fields Too Large`
pub const DEFAULT_MAX_FIELDS: usize = 20;

/// Longest accepted header field name.
pub const DEFAULT_MAX_FIELD_LEN: usize = 64;

/// Longest accepted header field value.
pub const DEFAULT_MAX_VALUE_LEN: usize = 1024;

/// Bounds one request head has to respect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadLimits {
    /// Largest total size of the head, including the terminating CRLF CRLF.
    pub max_head: usize,
    /// Largest number of header fields.
    pub max_fields: usize,
    /// Longest header field name.
    pub max_field_len: usize,
    /// Longest header field value.
    pub max_value_len: usize,
}

impl Default for HeadLimits {
    fn default() -> Self {
        Self {
            max_head: DEFAULT_MAX_HEAD,
            max_fields: DEFAULT_MAX_FIELDS,
            max_field_len: DEFAULT_MAX_FIELD_LEN,
            max_value_len: DEFAULT_MAX_VALUE_LEN,
        }
    }
}

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

/// One parsed request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageHead {
    /// Request method, in the case the client wrote it: `GET`, `SETUP`, `POST`.
    pub method: String,
    /// Request target, which is a route (`/info`) or an absolute URL.
    pub target: String,
    /// Protocol and version, such as `RTSP/1.0`.
    pub version: String,
    /// Header fields in the order they arrived, names lower-cased so lookups can ignore
    /// case without copying them again.
    pub headers: Vec<(String, String)>,
    /// Bytes the head occupied, including the terminating `CRLF CRLF`. The body starts
    /// there.
    pub consumed: usize,
}
impl MessageHead {
    /// Looks up a header field, ignoring case.
    ///
    /// A repeated field returns its first value; framing fields a receiver depends on
    /// (`Content-Length`) are already refused when repeated, and other fields are not.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
    /// Reads `Content-Length`, bounded by `maximum`.
    ///
    /// A message without the header has a zero-length body. Only decimal digits are a
    /// length: the protocol accepts a sign or a hexadecimal prefix, both of which one peer can
    /// read differently from another, and this port refuses them.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Invalid`] for a value that is not a decimal length and
    /// [`ParseError::TooLarge`] when it exceeds `maximum`.
    pub fn content_length(&self, maximum: usize) -> Result<usize, ParseError> {
        let Some(value) = self.header("content-length") else {
            return Ok(0);
        };
        let value = value.trim();
        // Only decimal digits are a length: a sign, a space or a hexadecimal
        // prefix would be read by one peer and refused by another.
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ParseError::Invalid("content-length"));
        }
        let length = value
            .parse::<usize>()
            .map_err(|_| ParseError::Invalid("content-length"))?;
        if length > maximum {
            return Err(ParseError::TooLarge {
                declared: length,
                maximum,
            });
        }
        Ok(length)
    }
}

/// Parses one request head bounded by [`DEFAULT_MAX_HEAD`].
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_headers_incrementally() {
        let input = b"SETUP /stream RTSP/1.0\r\nCSeq: 7\r\nContent-Length: 4\r\n\r\ndata";
        let head = parse_request_head(input).unwrap();
        assert_eq!(head.header("cseq"), Some("7"));
        assert_eq!(head.content_length(16), Ok(4));
        assert_eq!(split_body(&input[head.consumed..], 4), Ok(&b"data"[..]));
    }
    #[test]
    fn rejects_malformed_and_oversized_headers() {
        assert_eq!(
            parse_request_head(b"GET / HTTP/1.1\r\nBad\r\n\r\n"),
            Err(ParseError::Invalid("header"))
        );
        let head = parse_request_head(b"POST / HTTP/1.1\r\nContent-Length: 99\r\n\r\n").unwrap();
        assert_eq!(
            head.content_length(10),
            Err(ParseError::TooLarge {
                declared: 99,
                maximum: 10
            })
        );
    }

    #[test]
    fn rejects_an_unbounded_protocol_or_version() {
        // A long token would otherwise be echoed back in the status line.
        let long = format!(
            "GET /info RTSP/1.{}000000000000\r\nCSeq: 1\r\n\r\n",
            "0".repeat(190)
        );
        assert_eq!(
            parse_request_head(long.as_bytes()),
            Err(ParseError::Invalid("version"))
        );
        assert_eq!(
            parse_request_head(b"GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                .map(|head| head.version)
                .as_deref(),
            Ok("RTSP/1.0")
        );
        // The protocol itself is bounded too, and the longest accepted token is
        // the eight bytes the protocol copies into its own buffer. A protocol that is
        // not one of the two this crate knows is rejected by the start line check.
        assert_eq!(
            parse_request_head(b"GET /info RTSPX/1.0\r\nCSeq: 1\r\n\r\n"),
            Err(ParseError::Invalid("start line"))
        );
        assert_eq!(
            parse_request_head(b"POST /reverse RTSP/2.0\r\nCSeq: 1\r\n\r\n")
                .map(|head| head.version)
                .as_deref(),
            Ok("RTSP/2.0")
        );
    }

    #[test]
    fn rejects_a_conflicting_content_length() {
        assert_eq!(
            parse_request_head(
                b"POST /pair-setup RTSP/1.0\r\nContent-Length: 0\r\nContent-Length: 4\r\n\r\n"
            ),
            Err(ParseError::Invalid("content-length"))
        );
        // Even a repeated header with the same value is refused: the port does
        // not need two statements about one message boundary.
        assert_eq!(
            parse_request_head(
                b"POST /pair-setup RTSP/1.0\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n"
            ),
            Err(ParseError::Invalid("content-length"))
        );
        for bad in [
            &b"POST /pair-setup RTSP/1.0\r\nContent-Length: +5\r\n\r\n"[..],
            b"POST /pair-setup RTSP/1.0\r\nContent-Length: -5\r\n\r\n",
            b"POST /pair-setup RTSP/1.0\r\nContent-Length: 0x5\r\n\r\n",
            b"POST /pair-setup RTSP/1.0\r\nContent-Length:\r\n\r\n",
        ] {
            assert_eq!(
                parse_request_head(bad),
                Err(ParseError::Invalid("content-length")),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn rejects_a_transfer_encoding() {
        // Neither chunked framing nor any other transfer coding is implemented,
        // so a message that asks for one is refused instead of being framed by
        // its `Content-Length`.
        assert_eq!(
            parse_request_head(b"POST /pair-setup RTSP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(ParseError::Invalid("transfer-encoding"))
        );
        assert_eq!(
            parse_request_head(
                b"POST /pair-setup RTSP/1.0\r\nTransfer-Encoding: gzip\r\nContent-Length: 0\r\n\r\n"
            ),
            Err(ParseError::Invalid("transfer-encoding"))
        );
    }

    #[test]
    fn applies_the_per_field_header_bounds() {
        let limits = HeadLimits::default();
        let field = "X".repeat(limits.max_field_len);
        let value = "v".repeat(limits.max_value_len);
        let allowed = format!("GET /info RTSP/1.0\r\n{field}: {value}\r\n\r\n");
        assert!(parse_request_head(allowed.as_bytes()).is_ok());

        let long_field = format!(
            "GET /info RTSP/1.0\r\n{}: v\r\n\r\n",
            "X".repeat(limits.max_field_len + 1)
        );
        assert_eq!(
            parse_request_head(long_field.as_bytes()),
            Err(ParseError::TooLarge {
                declared: limits.max_field_len + 1,
                maximum: limits.max_field_len,
            })
        );
        let long_value = format!(
            "GET /info RTSP/1.0\r\nX-A: {}\r\n\r\n",
            "v".repeat(limits.max_value_len + 1)
        );
        assert_eq!(
            parse_request_head(long_value.as_bytes()),
            Err(ParseError::TooLarge {
                declared: limits.max_value_len + 1,
                maximum: limits.max_value_len,
            })
        );
        let mut many = String::from("GET /info RTSP/1.0\r\n");
        for index in 0..=limits.max_fields {
            many.push_str(&format!("X-{index}: v\r\n"));
        }
        many.push_str("\r\n");
        assert_eq!(
            parse_request_head(many.as_bytes()),
            Err(ParseError::TooLarge {
                declared: limits.max_fields + 1,
                maximum: limits.max_fields,
            })
        );
    }

    #[test]
    fn reports_incomplete_and_oversized_heads() {
        assert_eq!(
            parse_request_head(b"SETUP /stream RTSP/1.0\r\nCSeq: 7\r\n"),
            Err(ParseError::Incomplete)
        );
        assert_eq!(
            parse_request_head_with_maximum(&[b'X'; 100], 16),
            Err(ParseError::TooLarge {
                declared: 100,
                maximum: 16
            })
        );
        let mut oversized = vec![b'A'; 40];
        oversized.extend_from_slice(b"\r\n\r\n");
        assert_eq!(
            parse_request_head_with_maximum(&oversized, 16),
            Err(ParseError::TooLarge {
                declared: 44,
                maximum: 16
            })
        );
    }

    #[test]
    fn rejects_bad_start_lines_and_header_encoding() {
        assert_eq!(
            parse_request_head(b"GET /\r\n\r\n"),
            Err(ParseError::Invalid("version"))
        );
        assert_eq!(
            parse_request_head(b"GET / HTTP/1.1 extra\r\n\r\n"),
            Err(ParseError::Invalid("start line"))
        );
        assert_eq!(
            parse_request_head(b"GET / FTP/1.0\r\n\r\n"),
            Err(ParseError::Invalid("start line"))
        );
        assert_eq!(
            parse_request_head(b"GET / HTTP/1.1\r\nX: \xff\r\n\r\n"),
            Err(ParseError::Invalid("headers"))
        );
        assert_eq!(
            parse_request_head(b"GET / HTTP/1.1\r\nBad Header: 1\r\n\r\n"),
            Err(ParseError::Invalid("header name"))
        );
    }

    #[test]
    fn leaves_pipelined_requests_to_the_caller() {
        let input = b"POST /x HTTP/1.1\r\nCSeq: 1\r\nContent-Length: 4\r\n\r\ndataOPTIONS * RTSP/1.0\r\nCSeq: 2\r\n\r\n";
        let first = parse_request_head(input).unwrap();
        assert_eq!(first.content_length(64), Ok(4));
        assert_eq!(split_body(&input[first.consumed..], 4).unwrap(), b"data");
        let rest = &input[first.consumed + 4..];
        let second = parse_request_head(rest).unwrap();
        assert_eq!(second.header("cseq"), Some("2"));
        assert_eq!(second.consumed, rest.len());
    }
}
