// SPDX-License-Identifier: GPL-3.0-or-later
//! The bounds a request head is parsed under.

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
