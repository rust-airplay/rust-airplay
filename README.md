# rust-airplay

A Rust library for building AirPlay 1 and AirPlay 2 receivers.

It advertises a receiver over mDNS, answers the AirPlay control protocol, pairs clients,
receives screen mirroring and audio, decrypts both, and hands coded frames to a renderer. It
stops at the coding boundary: decoding and playback are a backend's job, because a backend is
one technology and one dependency tree.

## Where the library stops

| The library | The program |
| --- | --- |
| discovery, pairing, FairPlay, RTSP routes | where the identity is stored |
| media sockets, decryption, RTP, framing | where a renderer comes from |
| timestamps, pacing, volume conversion | how the PIN and errors are shown |
| a `log` record for everything that happens | which records are printed, and to what |

The library opens no file of its own, reads no environment variable and prints nothing. The
files it can write are asked for explicitly: `Config::trace_log` and the two diagnostic dumps.

## Adding it

```toml
[dependencies]
rust-airplay = "0.1"
```

Rust 1.85 or newer, 2024 edition. The crate links no C library.

## Starting a receiver

```rust,no_run
use std::sync::Arc;

use rust_airplay::{Config, NullRenderer};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let config = Config::new("Living room", [0x42; 32], Arc::new(NullRenderer::new()));
rust_airplay::run(config).await?;
# Ok(())
# }
```

`Config::new` fills in every default and leaves the three values a receiver cannot invent: the
name a client sees, the 32-byte seed its identity derives from, and what plays the media. Each
of those, and every other field of `Config`, is a value the caller resolved: the library does
not read the environment, does not choose a path and does not parse a command line.

Three fields decide what a program has to do around `run`:

- `seed` is the secret the identity derives from. The same seed keeps the receiver
  recognisable to clients that paired with it before, so a program stores it.
- `clients` is the set of already verified client keys, and `on_client` is called when one
  joins. A program reads and writes that list.
- `on_pin` is called with the one-time PIN as it is drawn. It is the one thing a person at the
  keyboard has to see, and the library does not print.

`run` serves clients until the process stops: it is not a server object with a shutdown
handle, and a program ends it the way it ends any other process.

## Playing the media

`Renderer` is the seam. It has three methods - `open_audio`, `open_video`, `set_volume` - and
two streams, `AudioStream` and `VideoStream`. What crosses the seam is already coded: an audio
frame's payload, or a video access unit in Annex-B form with its parameter sets in front of
it. A backend therefore needs a decoder and a device, and nothing about AirPlay.

- [docs/BACKEND.md](docs/BACKEND.md) is the contract, in the order a backend meets it, with a
  complete minimal implementation and a checklist.
- `examples/recorder.rs` is that implementation, compiled with the crate.
- [rust-airplay-gstream](https://github.com/rust-airplay/rust-airplay-gstream) is a complete
  backend: GStreamer for audio, `gst-launch-1.0` for video.

`NullRenderer` accepts everything and plays nothing. It is what a session can run against
without a sound card, and what a new backend can be compared with.

## Documentation

- [docs/BACKEND.md](docs/BACKEND.md) and [BACKEND.zh-CN.md](docs/BACKEND.zh-CN.md): how to
  implement a playback backend
- [docs/API.md](docs/API.md) and [API.zh-CN.md](docs/API.zh-CN.md): configuration, the renderer
  traits, the modules
- [docs/BUILD.md](docs/BUILD.md) and [BUILD.zh-CN.md](docs/BUILD.zh-CN.md): the toolchain and
  the gates
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
  [ARCHITECTURE.zh-CN.md](docs/ARCHITECTURE.zh-CN.md): the crates and the path a session takes
- [CHANGELOG.md](CHANGELOG.md): what each release contains
- [MIGRATION.md](MIGRATION.md): how this repository came out of a single workspace
- [AGENT.md](AGENT.md): notes for automated contributors

The API reference is the rustdoc built from the source: `cargo doc --open`, or the rendered
documentation on [docs.rs](https://docs.rs/rust-airplay).

## Status

Version 0.1.0. The public API is the one this release documents; a breaking change before 1.0
is possible but not planned. Version 1.0 is the point where the API is frozen and the backend
can be published beside this crate.

## Licence

GPL-3.0-or-later, because parts of it are translations of GPL and LGPL sources. A program that
links this crate is bound by the same licence; see [LICENSE](LICENSE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

中文：[README.zh-CN.md](README.zh-CN.md)。
