// SPDX-License-Identifier: GPL-3.0-or-later
//! Structural bounds checked before a plist is handed to the parser.

use super::types::{MAX_PLIST_DEPTH, MAX_PLIST_OBJECTS, PlistError};

pub(super) fn check_structure(bytes: &[u8]) -> Result<(), PlistError> {
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
