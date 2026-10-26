// SPDX-License-Identifier: GPL-3.0-or-later
//! The `Digest` authorization header and its response.

/// Fields of a `Digest` authorization header this crate has to check.
///
/// The protocol extracts the same names by searching the header with `strstr` and
/// writing a NUL into the copy it made (,
/// `get_token`); this type is what a read-only parse produces.
#[derive(Clone, PartialEq, Eq)]
pub struct DigestAuthorization {
    /// `username` field.
    pub username: String,
    /// `realm` field.
    pub realm: String,
    /// `nonce` field, which has to be the one this connection handed out.
    pub nonce: String,
    /// `uri` field, as sent by the client.
    pub uri: String,
    /// `response` field: the digest the client computed.
    pub response: String,
    /// `qop` field, when the client used the `auth` variant.
    pub qop: Option<String>,
    /// `nc` field, the client's request counter.
    pub nonce_count: Option<String>,
    /// `cnonce` field, the client's own nonce.
    pub client_nonce: Option<String>,
}

impl std::fmt::Debug for DigestAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `response` is the credential the client computed; the rest describe the
        // challenge and are not secret.
        formatter
            .debug_struct("DigestAuthorization")
            .field("username", &self.username)
            .field("realm", &self.realm)
            .field("nonce", &self.nonce)
            .field("uri", &self.uri)
            .field("response", &"<redacted>")
            .field("qop", &self.qop)
            .field("nonce_count", &self.nonce_count)
            .field("client_nonce", &self.client_nonce)
            .finish()
    }
}

/// Parses a `Digest` authorization header.
///
/// Returns `None` when a field the digest needs is missing or malformed, so a
/// caller answers `401` instead of computing a digest from missing pieces
pub fn parse_digest_authorization(header: &str) -> Option<DigestAuthorization> {
    let (scheme, fields) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("digest") {
        return None;
    }
    let mut username = None;
    let mut realm = None;
    let mut nonce = None;
    let mut uri = None;
    let mut response = None;
    let mut qop = None;
    let mut nonce_count = None;
    let mut client_nonce = None;
    for field in fields.split(',') {
        let (name, value) = field.split_once('=')?;
        let value = value.trim().trim_matches('"');
        if value.is_empty() {
            return None;
        }
        match name.trim().to_ascii_lowercase().as_str() {
            "username" => username = Some(value.to_owned()),
            "realm" => realm = Some(value.to_owned()),
            "nonce" => nonce = Some(value.to_owned()),
            "uri" => uri = Some(value.to_owned()),
            "response" => response = Some(value.to_owned()),
            "qop" => qop = Some(value.to_owned()),
            "nc" => nonce_count = Some(value.to_owned()),
            "cnonce" => client_nonce = Some(value.to_owned()),
            // Unknown fields are ignored, as RFC 2617 allows.
            _ => {}
        }
    }
    Some(DigestAuthorization {
        username: username?,
        realm: realm?,
        nonce: nonce?,
        uri: uri?,
        response: response?,
        qop,
        nonce_count,
        client_nonce,
    })
}

/// Compares two byte strings without returning early on the first difference.
///
/// A digest and a nonce are secrets in the sense that a timing signal about them
/// helps an attacker, so the comparison folds every byte.
pub fn constant_time_eq(expected: &[u8], actual: &[u8]) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    let mut difference = 0u8;
    for (expected, actual) in expected.iter().zip(actual) {
        difference |= expected ^ actual;
    }
    difference == 0
}

/// Lower-case hexadecimal MD5 of `input`, the encoding Digest authentication and
/// the RAOP device identifier use.
pub fn md5_hex(input: &[u8]) -> String {
    crate::crypto::md5_concat(&[input])
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Digest response of a password-protected request
///, including the `qop=auth` variant.
#[allow(clippy::too_many_arguments)]
pub fn digest_auth_response(
    method: &str,
    username: &str,
    realm: &str,
    password: &str,
    nonce: &str,
    uri: &str,
    qop: Option<&str>,
    nonce_count: Option<&str>,
    client_nonce: Option<&str>,
) -> String {
    let ha1 = md5_hex(format!("{username}:{realm}:{password}").as_bytes());
    let ha2 = md5_hex(format!("{method}:{uri}").as_bytes());
    let tail = match (qop, nonce_count, client_nonce) {
        (Some(qop), Some(nc), Some(cnonce)) => format!("{nonce}:{nc}:{cnonce}:{qop}:{ha2}"),
        _ => format!("{nonce}:{ha2}"),
    };
    md5_hex(format!("{ha1}:{tail}").as_bytes())
}
