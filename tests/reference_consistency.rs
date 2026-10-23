// SPDX-License-Identifier: GPL-3.0-or-later
//! Every upstream reference in this crate names a commit.
//!
//! The port is written against a pinned checkout, and a line number without a
//! commit is a claim nobody can check later. This test fails when a reference
//! names a hash that is neither the pinned port target nor the recorded
//! difference-check baseline (`docs/ARCHITECTURE.md` section 0).
//!
//! It cannot see a reference that forgot its hash entirely: those are reviewed
//! by reading, and the plan's W8 exit check repeats that. What it does catch is
//! the silent case, where a later edit copies a reference from a newer checkout.

use std::path::{Path, PathBuf};

/// Commit the port targets, recorded in `docs/MIGRATION_PLAN.md`.
const PINNED: &str = "517cbb1240d9b9f69330c55b957cdd52b4175b2a";

/// Commit of the upstream difference check, recorded in section 0 of the plan.
const DIFFERENCE_BASELINE: &str = "3dbf7ceee65932154e85a2f83963d53520a799fa";

/// Prefix every reference uses.
const REFERENCE: &str = "upstream/UxPlay@";

#[test]
fn upstream_references_name_a_known_commit() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    for directory in ["src", "tests"] {
        collect(&root.join(directory), &mut sources);
    }
    assert!(!sources.is_empty(), "no sources found under {root:?}");

    let mut unknown = Vec::new();
    for path in sources {
        let text = std::fs::read_to_string(&path).expect("a source file is readable");
        for (number, line) in text.lines().enumerate() {
            for hash in hashes(line) {
                // A reference may shorten the hash to the eight characters git
                // prints, so the written form has to be a prefix of a known one.
                let known = [PINNED, DIFFERENCE_BASELINE]
                    .iter()
                    .any(|allowed| allowed.starts_with(hash));
                if !known {
                    unknown.push(format!(
                        "{}:{}: {REFERENCE}{hash}",
                        path.strip_prefix(root).unwrap_or(&path).display(),
                        number + 1
                    ));
                }
            }
        }
    }
    assert!(
        unknown.is_empty(),
        "these references name a commit this crate was not written against:\n{}",
        unknown.join("\n")
    );
}

/// Hashes of the references on one line, truncated or not.
fn hashes(line: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = line;
    while let Some(index) = rest.find(REFERENCE) {
        rest = &rest[index + REFERENCE.len()..];
        let end = rest
            .find(|character: char| !character.is_ascii_hexdigit())
            .unwrap_or(rest.len());
        // The full hash is what the plan records; a shorter one is still a
        // reference, and comparing prefixes keeps both spellings checkable.
        let hash = &rest[..end];
        // Seven characters is the shortest unambiguous form git prints.
        if hash.len() >= 7 {
            found.push(hash);
        }
    }
    found
}

/// Collects every Rust file below `directory`.
fn collect(directory: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

#[test]
fn hashes_are_found_in_the_forms_the_code_uses() {
    assert_eq!(
        hashes("//! (`upstream/UxPlay@3dbf7cee:lib/raop.c:225`)"),
        ["3dbf7cee"]
    );
    assert_eq!(hashes(&format!("// ({REFERENCE}{PINNED})")), [PINNED]);
    assert_eq!(hashes("upstream/UxPlay/lib/raop.c:225"), Vec::<&str>::new());
    assert_eq!(hashes("upstream/UxPlay@ not a hash"), Vec::<&str>::new());
}
