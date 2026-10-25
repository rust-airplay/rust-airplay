// SPDX-License-Identifier: GPL-3.0-or-later
//! The plist value wrapper, its limits and its error.

use std::io::Cursor;

use super::check::check_structure;

/// Largest accepted plist payload. Matches the control-plane body bound.
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
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_airplay::plist::{self, Plist};
    ///
    /// let value = plist::dictionary([
    ///     ("name", "Living room".into()),
    ///     ("port", 7000u64.into()),
    /// ]);
    /// let encoded = Plist::from_value(value).encode_binary().expect("encoded");
    /// let parsed = Plist::parse(&encoded).expect("parsed");
    /// assert_eq!(parsed.get_string("name").expect("name"), "Living room");
    /// assert_eq!(parsed.get_unsigned("port").expect("port"), 7000);
    /// ```
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
