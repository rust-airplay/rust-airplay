# Working on this repository

This file describes how to build, test and change the code. It is written for an automated
contributor, so it states the gates and the rules plainly.

## Layout

This repository is one crate: the AirPlay protocol library. Playback and programs are
separate repositories, and nothing here may depend on them.

```
src/                    the library
├── receiver/           Config, state, serve, AudioTask, MirrorTask
├── server/             control service; handlers/ (types, routes/), pairing/ (state, session)
├── media/              audio/, mirror/, ports/, timing/, control, dmap, pace
├── control/            route table, dispatch, session, wire types
├── wire/, plist/, render/, discovery/, pairing/, playfair/
tests/                  protocol, property and integration tests, with fixtures
tools/                  helpers that generate test fixtures; not part of the crate
docs/                   API, architecture, build guide, backend guide; English and Chinese
examples/               a complete renderer implementation
Cargo.lock              committed; CI and the MSRV job use it
```

Unit tests live with their module: inline as `#[cfg(test)] mod tests` by default, or in
`<module>/tests.rs` when the module is a directory and its suite is large. `tests/` is only
for tests that use the public API; a unit test there could not see private items. No
directory under `src/` holds only a `tests.rs`.

`playfair_tables.rs` and `playfair/hand_garble_generated.rs` are generated tables. Change the
generator, not the table, unless the task is explicitly about the generated data.

## Gates

A change is finished when all of these pass:

```sh
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo test --doc --locked
cargo clippy --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
cargo package --list --locked
```

`cargo package --list` is not a build: it shows what a published crate would contain, which is
how a new document or example is caught missing from `include` in `Cargo.toml`. Dependency
changes are made with `cargo update` and committed with the lockfile; a CI run never resolves
a different graph on its own.

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

Every public item is documented, and `missing_docs` is denied. A public type or function
without a doc comment does not compile.

A comment explains why. The code says what it does, so a comment earns its place by recording a
measurement, a rule the protocol imposes, or a mistake that would otherwise be repeated.

## Documentation

Every guide under `docs/`, and the README and MIGRATION documents, exist twice as
`<name>.md` and `<name>.zh-CN.md`; the English version is the primary one. `CHANGELOG.md`,
`THIRD_PARTY_NOTICES.md` and this file are single-language records and are exempt.

No emoji, in any document.

Say what was run against a device and what was only tested. A claim that a platform works
should say which device it was verified on.

The rustdoc is part of the documentation and is held to the same standard: an item describes
its contract, its errors and, where the question is "how do I hold this", an example that
compiles.

## Commits

One commit per coherent change. The message says what was wrong and why the change fixes it,
in that order. If the change was measured, the message carries the number. A list of files
touched is not useful to a reader later.
