# Migration: one workspace becomes four repositories

中文见 [MIGRATION.zh-CN.md](MIGRATION.zh-CN.md)。

This repository used to be a workspace holding three crates: the library, a command-line
receiver and a GStreamer backend. It is the library now, and nothing else. The other two
crates live in repositories of their own, and a desktop client will follow them.

## What stays here

```
src/                    the library
tests/                  the protocol and differential tests, and their fixtures
docs/                   API, build guide, architecture, in English and Chinese
tools/oracle/           the C oracle the differential tests compare against
tools/plist_fixtures.py
upstream/               the UxPlay checkout the oracle builds from; not vendored
```

Everything a program needs to run a receiver is here: discovery, the control protocol,
pairing, FairPlay, stream decryption, framing, the timing exchange, pacing, and the
`Renderer` boundary. What is not here is decoding and playback.

## What moved out

| Moved | To | Notes |
| --- | --- | --- |
| `crates/rust-airplay-gstreamer` | `https://github.com/rust-airplay/rust-airplay-gstream` | renamed `rust-airplay-gstream`; the library is `rust_airplay_gstream` |
| `tools/eld_probe.c` | the same backend repository | it is a decoder diagnostic, so it belongs beside the decoder |
| `crates/rust-airplay-cli` | `https://github.com/rust-airplay/parlor-cli` | renamed package `parlor-cli`, binary `parlor` |

The backend and the client depend on this library through Git, not through a path:

```toml
rust-airplay = { git = "https://github.com/rust-airplay/rust-airplay", branch = "main" }
```

That means the order of the first push matters: this repository, then the backend, then the
client. Until this one is on the remote, `cargo build` in either of the others fails while
resolving dependencies - it is not a code problem.

## What changed in this crate

- The package is the workspace root. There is no `[workspace]` table and no `crates/`
  directory: `cargo build`, `cargo test` and the three gates run from the root.
- `Cargo.lock` is no longer committed. A library that other crates depend on should not pin
  its dependencies for them.
- Repository and package metadata point at `github.com/rust-airplay/rust-airplay`.
- The `Renderer` boundary now carries the coding: `VideoConfig::codec` is `H264` or `H265`,
  reported from the codec packet the client sends. A backend chooses its parser and decoder
  from it, and a stream that changed coding mid-session could not be missed.
- The video stream is opened on the first frame rather than when a connection arrives,
  because the client's codec configuration arrives before its first frame and that is the
  first moment the coding is known.
- Docs describe the library only. The command-line options moved to the client's README.

## Gates

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

The differential test against UxPlay is still here and still ignored by default; it needs
`upstream/UxPlay` at the pinned commit and MSYS2:

```sh
pwsh -File tools/oracle/run.ps1
```
