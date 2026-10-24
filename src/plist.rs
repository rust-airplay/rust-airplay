// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded property-list access for AirPlay control payloads.
//!
//! # Duplicate keys
//!
//! A property list is a tree whose dictionaries map a string key to a value, so
//! a body that names the same key twice keeps one entry: the later value
//! replaces the earlier one. Both the reader this module wraps and the
//! [`Dictionary`] it re-exports behave that way, which is why a handler that
//! reads a key always sees the value a client wrote last. A reader that has to
//! reject such a body instead can count keys while walking the structure in
//! `check_structure`; today the control plane only reads a handful of
//! independent keys, so the map behavior is what the handlers are written
//! against and `plist_spec.rs` pins it.
//!
//! AirPlay speaks the binary and XML property-list formats: `SETUP` and `/pair-verify` bodies
//! are property lists, and responses are written as one. This module provides the two rules the
//! rest of the crate depends on:
//!
//! - the payload size is checked before the parser runs;
//! - typed access returns a typed error instead of panicking, so a malformed or truncated
//!   request body can never abort the process.
//!
//! Values are handed out as [`plist::Value`] on purpose: navigation of deeper
//! structures (for example `streams[]`) needs the full value API, and this crate
//! has no reason to hide it.

use std::io::Cursor;

/// Property-list value the accessors of this module work with.
///
/// Re-exported so a caller that builds a response, such as the control service
/// handlers, needs only [`crate::plist`] rather than the backing implementation
/// crate.
pub use plist::Value;

/// Dictionary value of a property list, re-exported with [`Value`].
pub use plist::Dictionary;

/// Largest accepted plist payload. Matches the control-plane body bound in
/// [`crate::control`]; real AirPlay plists are a few kilobytes at most.
pub const MAX_PLIST_BYTES: usize = 64 * 1024;

/// Largest nesting depth a property list may use.
///
/// The backing parser descends recursively, so a deeply nested list that is far
/// below the size bound would abort the process with a stack overflow instead of
/// returning an error. Real AirPlay payloads nest three or four levels
///, so the bound is
/// generous and still far away from the stack limit.
pub const MAX_PLIST_DEPTH: usize = 32;

/// Largest number of objects one property list may contain.
pub const MAX_PLIST_OBJECTS: usize = 4096;

/// Reasons a property list could not be read or written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlistError {
    /// The payload is larger than the configured bound and was not parsed.
    TooLarge {
        /// Size of the rejected payload.
        declared: usize,
        /// Configured bound.
        maximum: usize,
    },
    /// The payload is not a property list the parser accepted.
    Decode(String),
    /// A value could not be serialized.
    Encode(String),
    /// A required key is absent.
    MissingKey(&'static str),
    /// A key exists with a different value type.
    WrongType {
        /// Key whose value has the unexpected type.
        key: &'static str,
        /// Type the caller expected.
        expected: &'static str,
    },
}

impl std::fmt::Display for PlistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { declared, maximum } => {
                write!(f, "plist size {declared} exceeds maximum {maximum}")
            }
            Self::Decode(reason) => write!(f, "invalid plist: {reason}"),
            Self::Encode(reason) => write!(f, "cannot encode plist: {reason}"),
            Self::MissingKey(key) => write!(f, "missing plist key {key}"),
            Self::WrongType { key, expected } => {
                write!(f, "plist key {key} is not a {expected}")
            }
        }
    }
}

impl std::error::Error for PlistError {}

/// A parsed property list.
#[derive(Debug, Clone, PartialEq)]
pub struct Plist {
    value: plist::Value,
}

impl Plist {
    /// Parses a binary or XML property list, bounded by [`MAX_PLIST_BYTES`].
    pub fn parse(bytes: &[u8]) -> Result<Self, PlistError> {
        Self::parse_with_maximum(bytes, MAX_PLIST_BYTES)
    }
    /// Parses a binary or XML property list with an explicit size bound.
    ///
    /// The bound is checked before the parser runs, so an oversized request
    /// cannot drive the allocation of a large value tree. The structure is
    /// checked before that as well: a payload too deeply nested to be parsed
    /// without exhausting the stack is rejected instead of being handed to the
    /// recursive parser ([`MAX_PLIST_DEPTH`], [`MAX_PLIST_OBJECTS`]).
    pub fn parse_with_maximum(bytes: &[u8], maximum: usize) -> Result<Self, PlistError> {
        if bytes.len() > maximum {
            return Err(PlistError::TooLarge {
                declared: bytes.len(),
                maximum,
            });
        }
        check_structure(bytes)?;
        let value = plist::Value::from_reader(Cursor::new(bytes))
            .map_err(|error| PlistError::Decode(error.to_string()))?;
        Ok(Self { value })
    }

    /// Wraps an already built value, for example a response under construction.
    pub fn from_value(value: plist::Value) -> Self {
        Self { value }
    }

    /// Borrows the wrapped value.
    pub fn value(&self) -> &plist::Value {
        &self.value
    }

    /// Unwraps the value.
    pub fn into_value(self) -> plist::Value {
        self.value
    }

    /// Borrows the root dictionary, or `None` when the root is not a dictionary.
    pub fn root_dictionary(&self) -> Option<&plist::Dictionary> {
        self.value.as_dictionary()
    }

    /// Looks up a key without requiring it to exist, mirroring how the protocol
    /// checks optional request fields before reading them.
    pub fn get(&self, key: &str) -> Option<&plist::Value> {
        self.root_dictionary()?.get(key)
    }

    /// Whether the root dictionary contains `key`.
    pub fn has_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    fn entry(&self, key: &'static str) -> Result<&plist::Value, PlistError> {
        self.get(key).ok_or(PlistError::MissingKey(key))
    }

    fn typed<'a, T>(
        &'a self,
        key: &'static str,
        expected: &'static str,
        read: impl FnOnce(&'a plist::Value) -> Option<T>,
    ) -> Result<T, PlistError> {
        read(self.entry(key)?).ok_or(PlistError::WrongType { key, expected })
    }

    /// Reads a string value.
    pub fn get_string(&self, key: &'static str) -> Result<&str, PlistError> {
        self.typed(key, "string", |value| value.as_string())
    }

    /// Reads a data value, as used for keys, IVs, proofs and authentication tags.
    pub fn get_data(&self, key: &'static str) -> Result<&[u8], PlistError> {
        self.typed(key, "data", |value| value.as_data())
    }

    /// Reads an unsigned integer value.
    pub fn get_unsigned(&self, key: &'static str) -> Result<u64, PlistError> {
        self.typed(key, "integer", |value| value.as_unsigned_integer())
    }

    /// Reads a boolean value.
    pub fn get_boolean(&self, key: &'static str) -> Result<bool, PlistError> {
        self.typed(key, "boolean", |value| value.as_boolean())
    }

    /// Reads an array value, as used for the `streams` key of a SETUP request.
    pub fn get_array(&self, key: &'static str) -> Result<&[plist::Value], PlistError> {
        self.typed(key, "array", |value| value.as_array().map(Vec::as_slice))
    }

    /// Reads a nested dictionary value.
    pub fn get_dictionary(&self, key: &'static str) -> Result<&plist::Dictionary, PlistError> {
        self.typed(key, "dictionary", |value| value.as_dictionary())
    }

    /// Serializes this value as a binary plist, the format AirPlay responses use.
    pub fn encode_binary(&self) -> Result<Vec<u8>, PlistError> {
        let mut bytes = Vec::new();
        self.value
            .to_writer_binary(&mut bytes)
            .map_err(|error| PlistError::Encode(error.to_string()))?;
        Ok(bytes)
    }

    /// Serializes this value as an XML plist.
    pub fn encode_xml(&self) -> Result<Vec<u8>, PlistError> {
        let mut bytes = Vec::new();
        self.value
            .to_writer_xml(&mut bytes)
            .map_err(|error| PlistError::Encode(error.to_string()))?;
        Ok(bytes)
    }
}

/// Rejects a property list whose structure is too deep or too large to parse.
///
/// The check is iterative on purpose: it exists because the parser behind this
/// module descends recursively and a small payload can abort the process before
/// any error can be reported. A payload this function accepts is still validated
/// by the parser itself.
fn check_structure(bytes: &[u8]) -> Result<(), PlistError> {
    if bytes.starts_with(b"bplist") {
        check_binary(bytes)
    } else if bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        == Some(b'<')
    {
        check_xml(bytes)
    } else {
        // Not one of the two formats this module knows; the parser reports it.
        Ok(())
    }
}

/// Rejects a binary property list that nests or counts beyond the bounds.
fn check_binary(input: &[u8]) -> Result<(), PlistError> {
    const TRAILER: usize = 32;
    if input.len() < TRAILER {
        return Err(PlistError::Decode("binary plist is too short".to_owned()));
    }
    let trailer = &input[input.len() - TRAILER..];
    let offset_size = usize::from(trailer[6]);
    let reference_size = usize::from(trailer[7]);
    if !(1..=8).contains(&offset_size) || !(1..=8).contains(&reference_size) {
        return Err(PlistError::Decode(
            "binary plist declares an unusable object table".to_owned(),
        ));
    }
    let objects = read_unsigned(&trailer[8..16])?;
    let root = read_unsigned(&trailer[16..24])?;
    let table = read_unsigned(&trailer[24..32])?;
    if objects == 0 || objects > MAX_PLIST_OBJECTS {
        return Err(PlistError::Decode(format!(
            "binary plist declares {objects} objects"
        )));
    }
    if root >= objects {
        return Err(PlistError::Decode("binary plist has no root".to_owned()));
    }
    let table_end = table
        .checked_add(objects * offset_size)
        .ok_or_else(|| PlistError::Decode("binary plist object table overflows".to_owned()))?;
    if table_end > input.len() {
        return Err(PlistError::Decode(
            "binary plist object table lies outside the payload".to_owned(),
        ));
    }

    // One explicit work stack instead of recursion, so the walk itself cannot
    // exhaust the stack; the step budget bounds a payload whose references form
    // a cycle or a shared subtree.
    let mut pending = vec![(root, 1usize)];
    let mut steps = 0usize;
    while let Some((index, depth)) = pending.pop() {
        steps += 1;
        if steps > MAX_PLIST_OBJECTS * 8 {
            return Err(PlistError::Decode(
                "binary plist structure is too large".to_owned(),
            ));
        }
        if depth > MAX_PLIST_DEPTH {
            return Err(PlistError::Decode(format!(
                "binary plist nests deeper than {MAX_PLIST_DEPTH}"
            )));
        }
        if index >= objects {
            return Err(PlistError::Decode(
                "binary plist references a missing object".to_owned(),
            ));
        }
        let entry = table + index * offset_size;
        let offset = read_unsigned(
            input
                .get(entry..entry + offset_size)
                .ok_or_else(|| PlistError::Decode("truncated object table".to_owned()))?,
        )?;
        let marker = *input
            .get(offset)
            .ok_or_else(|| PlistError::Decode("object outside the payload".to_owned()))?;
        let mut cursor = offset + 1;
        let mut count = usize::from(marker & 0x0f);
        if count == 0x0f {
            let size_marker = *input
                .get(cursor)
                .ok_or_else(|| PlistError::Decode("truncated object count".to_owned()))?;
            let bytes = 1usize << (size_marker & 0x0f);
            if size_marker >> 4 != 0x1 || bytes > 8 {
                return Err(PlistError::Decode("invalid object count".to_owned()));
            }
            cursor += 1;
            count = read_unsigned(
                input
                    .get(cursor..cursor + bytes)
                    .ok_or_else(|| PlistError::Decode("truncated object count".to_owned()))?,
            )?;
            cursor += bytes;
        }
        let references = match marker >> 4 {
            // Array and set hold `count` references, a dictionary holds twice as
            // many: one key and one value per entry.
            0xa | 0xc => count,
            0xd => count
                .checked_mul(2)
                .ok_or_else(|| PlistError::Decode("dictionary entry count overflows".to_owned()))?,
            _ => 0,
        };
        for _ in 0..references {
            let child = read_unsigned(
                input
                    .get(cursor..cursor + reference_size)
                    .ok_or_else(|| PlistError::Decode("truncated object".to_owned()))?,
            )?;
            cursor += reference_size;
            pending.push((child, depth + 1));
        }
    }
    Ok(())
}

/// Rejects an XML property list that nests or counts beyond the bounds.
fn check_xml(input: &[u8]) -> Result<(), PlistError> {
    let text = std::str::from_utf8(input)
        .map_err(|_| PlistError::Decode("xml plist is not utf-8".to_owned()))?;
    let mut depth = 0usize;
    let mut containers = 0usize;
    for tag in text.split('<').skip(1) {
        let body = tag.split('>').next().unwrap_or(tag);
        let closing = body.starts_with('/');
        let name = body.trim_start_matches('/');
        let container = name.starts_with("array") || name.starts_with("dict");
        if !container {
            continue;
        }
        if closing {
            depth = depth.saturating_sub(1);
            continue;
        }
        // A self-closing tag opens and closes in one step.
        if body.ends_with('/') {
            containers += 1;
            continue;
        }
        depth += 1;
        containers += 1;
        if depth > MAX_PLIST_DEPTH || containers > MAX_PLIST_OBJECTS {
            return Err(PlistError::Decode(format!(
                "xml plist nests deeper than {MAX_PLIST_DEPTH} or holds more than {MAX_PLIST_OBJECTS} containers"
            )));
        }
    }
    Ok(())
}

/// Reads one big-endian unsigned integer of up to eight bytes.
fn read_unsigned(bytes: &[u8]) -> Result<usize, PlistError> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(PlistError::Decode(
            "binary plist integer has an unusable size".to_owned(),
        ));
    }
    let mut value = 0usize;
    for byte in bytes {
        value = value
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or_else(|| PlistError::Decode("binary plist integer overflows".to_owned()))?;
    }
    Ok(value)
}

/// Builds a dictionary value from key/value pairs, preserving insertion order.
pub fn dictionary<K: Into<String>>(
    entries: impl IntoIterator<Item = (K, plist::Value)>,
) -> plist::Value {
    let mut dict = plist::Dictionary::new();
    for (key, value) in entries {
        dict.insert(key.into(), value);
    }
    plist::Value::Dictionary(dict)
}

#[cfg(test)]
mod tests;
