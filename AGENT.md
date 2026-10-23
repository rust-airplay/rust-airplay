# Working on this repository

This file describes how to build, test and change the code. It is written for an automated
contributor, so it states the gates and the rules plainly.

## Layout

This repository is one crate: the AirPlay protocol library. Playback and programs are
separate repositories, and nothing here may depend on them.

```
src/                    the library
tests/                  protocol, property and differential tests, with fixtures
tools/oracle/           a C oracle built from UxPlay, for the differential tests
tools/plist_fixtures.py
docs/                   API, build guide, architecture; English and Chinese
upstream/UxPlay/        the checkout the oracle builds from; not vendored
```

## Gates

A change is finished when these pass:

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

One suite needs more than a Rust toolchain and is not part of the list above:

```sh
pwsh -File tools/oracle/run.ps1
```

It compares this implementation with UxPlay's own C code, and needs `upstream/UxPlay` at the
pinned commit and MSYS2. Run it for changes to the mirror keystream, the counter, audio
decryption, the pairing vectors or the FairPlay transforms: it is the only test that can tell
a plausible implementation from a correct one.

## Rules

No `unsafe`. The crate forbids it.

No C dependency and no `-sys` crate. `cargo tree` must stay free of both: a machine with no
media libraries has to be able to build and test this repository, and crates.io users get a
library they can compile anywhere.

The library reads no environment variable, chooses no path, and prints nothing. Values arrive
through `Config`; progress leaves through `log`.

The boundary hands over coded frames, not decoded ones. Decoding belongs to a backend
repository, so a change that wants a codec here is a change in the wrong crate.

No blocking call in a receive loop. Rendering happens on threads fed by bounded queues,
because a loop that blocks stops reading its socket, and the client stalls with it.

Every public item is documented. `missing_docs` is a warning today; in review, treat it as an
error.

A comment explains why. The code says what it does, so a comment earns its place by recording
a measurement, a rule taken from upstream, or a mistake that would otherwise be repeated.

## Documentation

Every document except this one exists twice, as `<name>.md` and `<name>.zh-CN.md`. The English
version is the primary one.

No emoji, in any document.

Say what was run against a device and what was only tested. A claim that a platform works
should say which device it was verified on.

## Working from upstream

`upstream/UxPlay` is a checkout at commit `57ea83411d5f7e0b38c5841987439340543f025c`. It is
not vendored and must not be edited.

When porting behaviour from it, read the source rather than the header defaults: a constant in
a header is what a build starts from, and the program may change it before use. That
distinction has cost more time in this project than any other, and the mDNS feature bitmap is
the example to remember. Cite the file and line where behaviour is not obvious, and when a rule
can be measured, commit the measurement as a test.

## Tools

`tools/oracle/` builds a C program from the upstream sources and prints their intermediate
values. It is faster to ask it than to reason about the protocol when a rule is in doubt.

## Commits

One commit per coherent change. The message says what was wrong and why the change fixes it,
in that order. If the change was measured, the message carries the number. A list of files
touched is not useful to a reader later.
