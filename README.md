# rust-airplay

An AirPlay 1/2 receiver as a library.

`rust-airplay` advertises a receiver over mDNS, answers the AirPlay control protocol, pairs
clients, receives screen mirroring and audio, decrypts them, and hands coded frames to a
renderer. It opens no files, reads no environment variables and prints nothing, so the
program that embeds it decides where the logs go and where the identity is kept.

The library stops at the coding boundary: what reaches a renderer is an Annex-B access unit
with its parameter sets in front of it, or one audio frame's payload. Decoding and playback
belong to a backend, because a backend is one technology and one repository. The GStreamer
one is [rust-airplay-gstream](https://github.com/rust-airplay/rust-airplay-gstream).

## Adding it

```toml
[dependencies]
rust-airplay = "0.1"
```

Rust 1.85 or newer. The crate links no C library.

## Starting a receiver

```rust,no_run
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use rust_airplay::server::PinMode;
use rust_airplay::{AudioCodec, Config, NullRenderer};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let config = Config {
    name: "Living room".to_owned(),
    port: 7000,
    seed: [0x42; 32],
    device_id: None,
    pin: PinMode::OneTime,
    password: None,
    audio_codec: AudioCodec::AacEld,
    renderer: Arc::new(NullRenderer::new()),
    clients: Arc::new(Mutex::new(HashSet::new())),
    on_client: None,
    trace_log: None,
    dump_video: None,
    dump_audio: None,
    pace_video: false,
    audio_latency: std::time::Duration::from_millis(250),
    initial_volume: rust_airplay::Volume::FULL,
    volume_curve: rust_airplay::VolumeCurve::default(),
    log_streaming_reports: false,
    features: None,
    client_policy: rust_airplay::server::ClientPolicy::default(),
    ports: rust_airplay::media::ports::MediaPorts::automatic(),
    nohold: false,
    feedback_timeout: None,
    display: rust_airplay::server::Display::default(),
};

rust_airplay::run(config).await?;
# Ok(())
# }
```

`run` serves clients until the process is asked to stop. Two fields are worth explaining
because they are where a receiver's behaviour across restarts comes from. `seed` is the
secret the identity derives from, so passing the same seed keeps the receiver recognisable.
`clients` is the set of client keys already verified, and `on_client` is called when a new
one joins, which is the moment to write it down.

## Playing the media

`Renderer` is the boundary: `open_audio`, `open_video`, `set_volume`. `VideoConfig::codec`
says which coding the frames are in, and `VideoFrame` carries Annex-B bytes, so a backend
needs a byte-stream decoder and nothing else. `NullRenderer` accepts everything and plays
nothing, which is useful for testing and for inspecting a session on a machine with no sound
card.

## Logging

Records go through the `log` crate at `info`, `warn` and `debug`. Nothing is printed without
a logger installed. The PIN a client must type is among the `info` records, so a program that
wants to show it prominently should install a logger that does.

## Documentation

- [docs/API.md](docs/API.md) and [API.zh-CN.md](docs/API.zh-CN.md): configuration, the renderer traits, the modules
- [docs/PARAMETERS.md](docs/PARAMETERS.md) and [PARAMETERS.zh-CN.md](docs/PARAMETERS.zh-CN.md): every UxPlay command-line option, and where it lives here
- [docs/BUILD.md](docs/BUILD.md) and [BUILD.zh-CN.md](docs/BUILD.zh-CN.md): the toolchain and the gates
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [ARCHITECTURE.zh-CN.md](docs/ARCHITECTURE.zh-CN.md): the crates and the path a session takes
- [MIGRATION.md](MIGRATION.md): how this repository came out of a single workspace
- [AGENT.md](AGENT.md): notes for automated contributors

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

中文：[README.zh-CN.md](README.zh-CN.md)。
