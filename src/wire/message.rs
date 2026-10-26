// SPDX-License-Identifier: GPL-3.0-or-later
//! The parsed start line and headers of one message.

use super::parse::ParseError;

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
