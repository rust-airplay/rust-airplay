# API

Chinese: [API.zh-CN.md](API.zh-CN.md). The generated reference is on
[docs.rs/rust-airplay](https://docs.rs/rust-airplay), and the repository's
[BACKEND.md](BACKEND.md) is the guide to the renderer contract.

The crate is organised as one program-level module ([`receiver`]) and the protocol pieces it is
built from. A program uses `receiver` and the types it names in `Config`; everything else is
public because the pieces are useful alone - a test may want the mirror decryptor without a
socket, and a tool may want the discovery text records without a receiver.

## Running a receiver

```rust
pub async fn run(config: Config) -> Result<(), Error>
```

`run` does the whole job: it binds the control service, registers the mDNS records, binds the
media sockets, waits for the process to be asked to stop, and serves clients. Each control
connection gets its own handler set; the media session is shared between them, because a
client's audio key arrives in one `SETUP` and the mirror stream identifier in a later one,
possibly on a different connection.

`Ok()` means the receiver was asked to stop. `Err` is a failure that prevented it from
starting:

- the control port cannot be bound,
- the mDNS records cannot be registered,
- one of the media sockets cannot be opened.

A session that fails after the receiver is running is reported through `log` and does not stop
the receiver.

```rust
use std::sync::Arc;

use rust_airplay::{Config, NullRenderer};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let config = Config::new("Living room", [0x42; 32], Arc::new(NullRenderer::new()));
rust_airplay::run(config).await?;
# Ok(())
# }
```

[`Config::new`] fills in every default and takes the three values a receiver cannot invent:
the name, the identity seed and the renderer.

## `Config`

Everything the receiver needs is a field. The library reads no environment variable, makes no
path decision and prints nothing; the only files it opens are the ones a caller names
(`trace_log`, `dump_video`, `dump_audio`).

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | `String` | the name clients see in their menu |
| `port` | `u16` | control port; `0` binds an ephemeral one and advertises whichever it got |
| `seed` | `[u8; 32]` | the secret every identity key derives from; the same seed keeps a receiver recognisable across restarts |
| `device_id` | `Option<String>` | hardware address to advertise. Derived from the seed when `None` |
| `pin` | `PinMode` | `Disabled`, `OneTime`, or `Fixed(digits)`. The PIN is reported through `on_pin` |
| `password` | `Option<String>` | when set, `SETUP` also requires this digest password |
| `audio_codec` | `AudioCodec` | the coding used when a client never states its `ct` in `SETUP`; a declaration always wins |
| `renderer` | `Arc<dyn Renderer>` | what plays the media |
| `clients` | `Arc<Mutex<HashSet<[u8; 32]>>>` | client keys already verified. Read at startup, added to as clients are verified |
| `on_client` | `Option<ClientCallback>` | called the first time a client is verified, so the caller can persist the key |
| `trace_log` | `Option<PathBuf>` | when set, request traces are appended here |
| `dump_video` | `Option<PathBuf>` | when set, the first video frames are appended here as Annex-B |
| `dump_audio` | `Option<PathBuf>` | when set, audio payloads are appended here behind a length |
| `pace_video` | `bool` | hold mirror video to its capture spacing. Off by default; a mirror is judged by how quickly it follows the device |
| `audio_latency` | `Duration` | the delay a client schedules against, in `Audio-Latency` on `RECORD`; 250 ms by default, at most ten seconds |
| `initial_volume` | `Volume` | the linear gain a session starts at; unity by default |
| `volume_curve` | `VolumeCurve` | how a client's decibels become that gain: flat or tapered, with the `-30..0` range rescaled |
| `log_streaming_reports` | `bool` | write the client's once-a-second streaming reports to the log |
| `on_pin` | `Option<PinCallback>` | called with the one-time PIN as it is drawn, from a background thread |
| `on_artwork` | `Option<ArtworkCallback>` | called with the content type and bytes of artwork a client sends |
| `on_metadata` | `Option<MetadataCallback>` | called with the DMAP listing a client sends; `media::dmap::text` turns it into lines |
| `on_remote_control` | `Option<RemoteControlCallback>` | called with the `DACP-ID` and `Active-Remote` a request carries |
| `features` | `Option<u64>` | advertised feature bitmap; `None` keeps `server::DEFAULT_FEATURES` |
| `display` | `server::Display` | the size, refresh rate, frame cap and overscan a client reads from `/info` |
| `client_policy` | `server::ClientPolicy` | which clients may start a session, checked in `SETUP`; a refused client is answered `403 Forbidden` |
| `ports` | `media::ports::MediaPorts` | the four media ports; `0` lets the system choose, `MediaPorts::legacy` is the traditional fixed layout |
| `nohold` | `bool` | a new client takes over from the current one instead of being refused |
| `feedback_timeout` | `Option<Duration>` | close a session whose client stopped sending `/feedback` |

The callback types are `Arc<dyn Fn(..) + Send + Sync>` and are called from the thread that met
the event: `on_client` from the connection that verified the client, `on_pin` from the thread
that watches for a pending PIN. Work that is slow or blocking belongs on another thread.

## The renderer contract

```rust
pub trait Renderer: Debug + Send + Sync {
    fn open_audio(&self, config: AudioConfig) -> Result<Box<dyn AudioStream>, RenderError>;
    fn open_video(&self, config: VideoConfig) -> Result<Box<dyn VideoStream>, RenderError>;
    fn set_volume(&self, volume: Volume) -> Result<(), RenderError>;
}

pub trait AudioStream: Debug + Send + Sync {
    fn push(&self, frame: AudioFrame) -> Result<(), RenderError>;
    fn flush(&self) -> Result<(), RenderError>;
    fn close(&self) -> Result<(), RenderError>;
}

pub trait VideoStream: Debug + Send + Sync {
    fn push(&self, frame: VideoFrame) -> Result<(), RenderError>;
    fn set_pace(&self, until_next_seconds: f64) -> Result<(), RenderError> { Ok(()) }
    fn flush(&self) -> Result<(), RenderError>;
    fn pause(&self) -> Result<(), RenderError> { Ok(()) }
    fn resume(&self) -> Result<(), RenderError> { Ok(()) }
    fn close(&self) -> Result<(), RenderError>;
}
```

What reaches a backend is coded, not decoded: an Annex-B access unit with its parameter sets
already in front of it, or one audio frame's payload. `VideoConfig::codec` says which coding
the frames are in - `h264parse` cannot read an HEVC unit and an HEVC decoder cannot read
H.264 - and it is known before the first frame because the client's codec packet precedes it.

Both streams are `'static` and are moved onto the threads that write them, so `push` may block;
the receive loop keeps reading the socket meanwhile. The full contract, with the frame units,
the flush and pause semantics and a complete implementation, is in [BACKEND.md](BACKEND.md).

`NullRenderer` accepts everything and plays nothing. It counts streams, frames, bytes, flushes
and closes, which makes it usable both as a test double and as a way to run a session on a
machine with no media stack.

## Media values

| Type | Contents |
| --- | --- |
| `AudioCodec` | `Alac` or `AacEld`; `from_compression_type` maps a client's `ct` |
| `AudioConfig` | codec, sample rate, channels, and samples per frame from the client's `spf` |
| `AudioFrame` | the coded payload; the timestamp counts samples at the session rate |
| `VideoCodec` | `H264` or `H265` |
| `VideoConfig` | width and height when the client stated them, and the coding |
| `VideoFrame` | an Annex-B access unit, an NTP Q32.32 timestamp, and whether it is a key frame |
| `Volume` | a linear gain from silence to unity, clamped on construction |
| `VolumeCurve` | slider position to gain; flat or tapered, with the decibel range configurable |
| `RenderError` | `Unavailable` when the machine cannot serve the stream, `Failed` when playback failed |

## Server and control types

| Type | Purpose |
| --- | --- |
| `server::Server` | binds the control port and serves connections; `Server::bind`, `local_addr`, `run` |
| `server::ServerConfig` | bind address, connection limit, idle timeout, takeover, feedback timeout |
| `server::RouteHandlers` | the RTSP routes of one connection, plus the callbacks a program installs |
| `server::DeviceIdentity` | the name, model, address and public key a client reads |
| `server::PinMode`, `server::PairingState` | PIN policy and the receiver-wide pairing service |
| `server::SetupPorts`, `server::SetupRequest`, `server::SetupStream` | what a `SETUP` promised and what a client asked for |
| `server::Display` | the screen geometry advertised in `/info` |
| `server::ClientPolicy` | allow and block lists, applied in `SETUP` |
| `server::DEFAULT_FEATURES` | the feature bitmap a receiver starts from |
| `control::Route`, `control::RouteHandler` | the route table and the trait a handler set implements |
| `wire::MessageHead`, `control::RouteRequest`, `control::RouteReply` | a parsed request and the answer a handler builds |

`server::Server` is the layer a program uses when it wants its own connection policy; `receiver`
is the same work already assembled.

## Discovery

| Type | Purpose |
| --- | --- |
| `discovery::Protection` | whether a client needs a PIN, a password, or nothing |
| `discovery::Advertisement` | the `_raop._tcp` and `_airplay._tcp` records for one identity |
| `discovery::Advertiser` | registers and unregisters them; keeps the full names |
| `discovery::DiscoveryError` | why registration failed |

`Advertisement::txt_records` returns the two text records as byte strings, which is also what
`GET /info?txtAirPlay` answers, so both places describe one receiver.

## Media modules

| Item | Purpose |
| --- | --- |
| `media::ports::MediaPorts`, `MediaSockets` | the four ports and the sockets bound to them |
| `media::audio::AudioSession`, `ReorderWindow`, `FlushHandle` | RTP audio: decryption, reordering, resend requests, flush |
| `media::mirror::MirrorSession`, `StreamInfo`, `Geometry`, `MirrorKind` | the mirror stream: header parsing, AES-CTR, codec data, geometry, pause |
| `media::control::parse_control_packet`, `resend_request` | the UDP control socket |
| `media::dmap::items`, `text` | now-playing metadata |
| `media::timing::RemoteClock` | the client's clock offset |
| `media::pace::Pacer` | timestamp to local time, for pacing |

## Primitives

`plist`, `wire`, `rtp`, `ntp`, `crypto`, `fairplay` and `srp` are the protocol primitives the
modules above are built from. They are public because a test, a tool or a protocol experiment
may need one without the rest; each documents its bounds and its error cases and does not
normalise its input silently.

## Logging

The library writes `log` records and never prints. `info` carries the progress of a session
(the receiver, the ports, the advertised names, the streams opening), `warn` a session that
went wrong, `debug` packet-level detail. Nothing appears if the program installs no logger.

The two things a person must see are not log lines: the PIN arrives through `on_pin`, and an
error that stops the receiver is the returned `Error`. A program may print either however it
likes.

## Program responsibilities

| The library decides | The program decides |
| --- | --- |
| protocol, media, timing | where the seed and the client list are stored |
| when a stream is opened or flushed | what plays it |
| what the PIN is | how the PIN is shown |
| what a trace line contains | where the trace goes |

A program that persists the seed and the client list gets a receiver that stays recognisable
across restarts; one that does not gets a receiver that looks new every time, which is a
legitimate choice.

## Versioning

Version 0.2.0. The public API is what this release documents; a breaking change before 1.0 is
possible and is noted in the changelog. The crate is GPL-3.0-or-later.

[`receiver`]: https://docs.rs/rust-airplay/latest/rust_airplay/receiver/index.html
