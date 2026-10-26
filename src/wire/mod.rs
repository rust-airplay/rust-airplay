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

/// Largest request body accepted by default: eight mebibytes.
///
/// The largest body an AirPlay client sends is a `SETUP` plist, which is measured in
/// kilobytes; the bound exists so a peer cannot make a receiver allocate without limit.
mod limits;
mod message;
mod parse;

pub use limits::{
    DEFAULT_MAX_BODY, DEFAULT_MAX_FIELD_LEN, DEFAULT_MAX_FIELDS, DEFAULT_MAX_HEAD,
    DEFAULT_MAX_VALUE_LEN, HeadLimits,
};
pub use message::MessageHead;
pub use parse::{
    ParseError, parse_request_head, parse_request_head_with_limits,
    parse_request_head_with_maximum, split_body,
};

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
