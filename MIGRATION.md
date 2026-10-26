# Migration: one workspace becomes four repositories

中文见 [MIGRATION.zh-CN.md](MIGRATION.zh-CN.md)。

This repository used to be a workspace holding three crates: the library, a command-line
receiver and a GStreamer backend. It is the library now, and nothing else. The other two
crates live in repositories of their own, and a desktop client will follow them.

## What stays here

```
src/                    the library
tests/                  the protocol and integration tests, and their fixtures
docs/                   API, build guide, architecture, backend guide, in English and Chinese
examples/               a complete renderer implementation
tools/                  helpers that generate test fixtures
```

Everything a program needs to run a receiver is here: discovery, the control protocol,
pairing, FairPlay, stream decryption, framing, the timing exchange, pacing, and the
`Renderer` boundary. Decoding and playback live in the backend repository.

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
  directory: `cargo build`, `cargo test` and the gates run from the root.
- `Cargo.lock` is committed. It pins the graph CI, the MSRV job and release builds use; a
  downstream crate still resolves its own dependencies.
- Repository and package metadata point at `github.com/rust-airplay/rust-airplay`.
- The `Renderer` boundary now carries the coding: `VideoConfig::codec` is `H264` or `H265`,
  reported from the codec packet the client sends. A backend chooses its parser and decoder
  from it, and a stream that changed coding mid-session could not be missed.
- The video stream is opened on the first frame rather than when a connection arrives,
  because the client's codec configuration arrives before its first frame and that is the
  first moment the coding is known.
- Docs describe the library only. The command-line options moved to the client's README.

## The 0.3.0 release

`0.3.0` is the release after `0.2.0`. It is a breaking pre-1.0 step, not a patch:

- `Config`, `ServerConfig`, `SetupRequest`, the codec enums, `RenderError`, `PinMode` and
  `SessionAuth` are `#[non_exhaustive]`. Construct the configuration types through
  `Config::new` or `ServerConfig::default`, and give a match a wildcard arm.
- `Config` gained `bind`, `advertise` and `debug_setup_body`; `ServerConfig` construction from
  a struct literal has to become field assignment or a default value.
- `serve(config, shutdown)` is the receiver with a caller-supplied stop condition. `run` is
  the Ctrl+C case, and `serve` returns after the control service stops and the advertisement
  is withdrawn.
- `SetupStream` gained `control_port`, `SetupRequest` gained `debug_body`, and
  `RouteHandler` gained a default `teardown()` hook.
- `FLUSH` now reaches the handler and calls `AudioStream::flush`; `VideoStream::set_pace` is
  called with the measured interval when the receiver does not pace video itself.
- `nohold` takes over the previous connection from the same host only.
- Source headers and third-party notices now state GPL-3.0-or-later consistently.
- `wire` and `pairing` were split into submodules, and the receiver's task bodies moved out
  of `serve`; every documented public path is unchanged.

## Gates

```sh
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo test --doc --locked
cargo clippy --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
cargo package --list --locked
```
