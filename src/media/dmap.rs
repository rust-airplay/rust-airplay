// SPDX-License-Identifier: GPL-3.0-or-later
//! The metadata a client sends while it plays.
//!
//! An AirPlay audio client sends its now-playing information as a DMAP listing: one outer
//! item tagged `mlit` whose length covers the rest, then items of a four-character tag, a
//! thirty-two-bit big-endian length and a value. Upstream reads the same structure and
//! prints a text line per string tag (`uxplay.cpp:2150-2270`), and this module is that
//! reading: the tags it knows become labelled text, and a tag it does not know is not
//! guessed at, because a length typed as a string would be printed as garbage.
//!
//! `-md` is a file of these lines, which is what a caller writes with [`text`].

/// The labels upstream gives the string tags it knows (`uxplay.cpp:2166-2270`).
///
/// A tag outside this table is skipped rather than printed: DMAP items carry numbers and
/// dates as well as strings, and their bytes are not text.
const LABELS: &[(&[u8; 4], &str)] = &[
    (b"asaa", "Album artist"),
    (b"asal", "Album"),
    (b"asar", "Artist"),
    (b"ascm", "Comment"),
    (b"ascn", "Content description"),
    (b"ascp", "Composer"),
    (b"asct", "Category"),
    (b"asdt", "Description"),
    (b"asfm", "Format"),
    (b"asgn", "Genre"),
    (b"asky", "Keywords"),
    (b"aslc", "Long Content Description"),
    (b"assa", "Sort Artist"),
    (b"assc", "Sort Composer"),
    (b"assl", "Sort Album artist"),
    (b"assn", "Sort Name"),
    (b"asss", "Sort Series"),
    (b"assu", "Sort Album"),
    (b"minm", "Title"),
];

/// One string item of a listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// The four-character tag, as sent.
    pub tag: String,
    /// The label upstream gives it.
    pub label: &'static str,
    /// The value, when it is text.
    pub value: String,
}

/// Reads a DMAP listing into its string items.
///
/// An item whose value is not UTF-8 is skipped: the tag says it is a string, so a value
/// that does not decode is a malformed listing rather than text in some other encoding.
#[must_use]
pub fn items(bytes: &[u8]) -> Vec<Item> {
    let Some((tag, body)) = item(bytes) else {
        return Vec::new();
    };
    if tag != *b"mlit" {
        return Vec::new();
    }
    let mut items = Vec::new();
    let mut rest = body;
    while let Some((tag, value)) = item(rest) {
        let consumed = 8 + value.len();
        rest = &rest[consumed..];
        let Some((_, label)) = LABELS.iter().find(|(known, _)| *known == &tag) else {
            continue;
        };
        let Ok(value) = std::str::from_utf8(value) else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        items.push(Item {
            tag: String::from_utf8_lossy(&tag).into_owned(),
            label,
            value: value.to_owned(),
        });
    }
    items
}

/// Reads a listing as the text upstream writes to a `-md` file.
#[must_use]
pub fn text(bytes: &[u8]) -> String {
    items(bytes)
        .iter()
        .map(|item| format!("{}: {}\n", item.label, item.value))
        .collect()
}

/// Reads one `tag` + `length` + value, or `None` when the bytes are shorter than they say.
fn item(bytes: &[u8]) -> Option<([u8; 4], &[u8])> {
    let tag: [u8; 4] = bytes.get(0..4)?.try_into().ok()?;
    let length = u32::from_be_bytes(bytes.get(4..8)?.try_into().ok()?) as usize;
    let value = bytes.get(8..8 + length)?;
    Some((tag, value))
}

#[cfg(test)]
mod tests {
    use super::{items, text};

    /// A listing with the items a client sends.
    fn listing(entries: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (tag, value) in entries {
            body.extend_from_slice(*tag);
            body.extend_from_slice(&(value.len() as u32).to_be_bytes());
            body.extend_from_slice(value);
        }
        let mut out = Vec::new();
        out.extend_from_slice(b"mlit");
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn a_listing_becomes_labelled_text() {
        let bytes = listing(&[
            (b"minm", b"Track one"),
            (b"asar", b"An artist"),
            (b"asal", b"An album"),
        ]);
        let items = items(&bytes);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].label, "Title");
        assert_eq!(items[0].value, "Track one");
        assert_eq!(
            text(&bytes),
            "Title: Track one\nArtist: An artist\nAlbum: An album\n"
        );
    }

    #[test]
    fn an_unknown_or_non_text_item_is_skipped() {
        // `asbr` is the bitrate, an integer; printing its bytes as a string is the mistake
        // the label table exists to avoid.
        let bytes = listing(&[
            (b"minm", b"Title"),
            (b"asbr", &[0x00, 0x00, 0x01, 0x00]),
            (b"asar", &[0xff, 0xfe]),
        ]);
        let items = items(&bytes);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].value, "Title");
    }

    #[test]
    fn a_listing_that_is_not_mlit_or_is_short_reads_as_nothing() {
        assert!(items(b"").is_empty());
        assert!(items(b"mcon\x00\x00\x00\x00").is_empty());
        // A length beyond the bytes is a truncated listing, not a partial one.
        assert!(items(b"mlit\x00\x00\x00\x08minm").is_empty());
    }
}
