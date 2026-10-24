# API

Chinese: [API.zh-CN.md](API.zh-CN.md). The generated reference is on
[docs.rs/rust-airplay](https://docs.rs/rust-airplay).

## Running a receiver

```rust
pub async fn run(config: Config) -> Result<(), Error>
```

This future does the whole job. It binds the control service, registers the mDNS records,
binds the media sockets, watches the process for a stop signal, and serves clients. Each
control connection gets its own handler set, but the media session is shared, because a
client's audio key arrives in one `SETUP` and the mirror stream identifier in a later one,
possibly on a different connection.

It returns `Ok(())` when the process is asked to stop, and `Err` only for a failure that
prevents a receiver from starting:

- the control port cannot be bound,
- the mDNS records cannot be registered,
- one of the media sockets cannot be opened.

A session that fails after the receiver is running is reported through `log` and the
receiver keeps serving. Dropping the future has the same effect as a stop signal.

## `Config`

Everything the receiver needs is here, and anything the caller can decide is a field
instead of a hidden default. The library reads no environment variable and opens no file.

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | `String` | the name clients see in their menu |
| `port` | `u16` | control port; `0` binds an ephemeral one and advertises it |
| `seed` | `[u8; 32]` | the secret an identity derives from. Passing a stored seed keeps a receiver recognisable across restarts |
| `device_id` | `Option<String>` | the hardware address to advertise, when the caller wants a specific one. Derived from the seed when `None` |
| `pin` | `PinMode` | `Disabled`, `OneTime`, or `Fixed(digits)`. The PIN is surfaced through `log`, so a program that wants to display it differently can install its own logger |
| `password` | `Option<String>` | when set, `SETUP` also requires this digest password |
| `audio_codec` | `AudioCodec` | `Alac` or `AacEld`, used when a client does not state its own `ct` in `SETUP` |
| `renderer` | `Arc<dyn Renderer>` | what plays the media |
| `clients` | `Arc<Mutex<HashSet<[u8; 32]>>>` | client keys already verified. The receiver reads it at startup and adds to it as clients are verified |
| `on_client` | `Option<ClientCallback>` | called the first time a client is verified, so the caller can persist the key |
| `trace_log` | `Option<PathBuf>` | when set, request traces are appended here |
| `dump_video` | `Option<PathBuf>` | when set, the first video frames are appended here as Annex-B |
| `dump_audio` | `Option<PathBuf>` | when set, audio payloads are appended here behind a length |
| `pace_video` | `bool` | whether mirror video is held back to its capture spacing. Off by default: a mirror is judged by how quickly it follows the device |
| `audio_latency` | `Duration` | the audio delay a client schedules against, reported in `Audio-Latency` on `RECORD`; upstream's `-al`, from 0 to 10 seconds |
| `initial_volume` | `Volume` | the slider position a session starts at; upstream's `-vol` |
| `volume_curve` | `VolumeCurve` | how a client's decibels become a gain: flat or tapered, with the `-30..0` range rescaled; upstream's `-db` and `-taper` |
| `log_streaming_reports` | `bool` | write the client's once-a-second streaming reports to the log; upstream's `-FPSdata` |
| `on_pin` | `Option<PinCallback>` | called with the one-time PIN as it is drawn, from a background thread |
| `on_artwork` | `Option<ArtworkCallback>` | called with the content type and bytes of artwork a client sends; upstream's `-ca` |
| `on_metadata` | `Option<MetadataCallback>` | called with the DMAP listing a client sends; `media::dmap::text` turns it into the lines of an `-md` file |
| `on_remote_control` | `Option<RemoteControlCallback>` | called with the `DACP-ID` and `Active-Remote` a request carries; upstream's `-dacp` |
| `features` | `Option<u64>` | the advertised feature bitmap; `None` keeps the default, bit 42 allows HEVC and bit 4 claims HLS |
| `display` | `server::Display` | the size, refresh rate, frame cap and overscan a client reads from `/info`; upstream's `-s`, `-fps` and `-o` |
| `client_policy` | `server::ClientPolicy` | which clients may start a session, checked in `SETUP`; a refused client is answered `403 Forbidden` |
| `ports` | `media::ports::MediaPorts` | the four media ports; `0` lets the system choose, and `MediaPorts::legacy()` is upstream's fixed layout |
| `nohold` | `bool` | a new client takes over from the current one instead of being refused |
| `feedback_timeout` | `Option<Duration>` | close a session whose client stopped sending `/feedback`; upstream's `-reset` |

`ClientCallback` is `Arc<dyn Fn(&[u8; 32]) + Send + Sync>`. It runs on the connection that
verified the client, so an implementation that writes a file should keep the work small or
hand it to another thread.

## The renderer trait

```rust
pub trait Renderer: Debug + Send + Sync {
    fn open_audio(&self, config: AudioConfig) -> Result<Box<dyn AudioStream>, RenderError>;
    fn open_video(&self, config: VideoConfig) -> Result<Box<dyn VideoStream>, RenderError>;
    fn set_volume(&self, volume: Volume) -> Result<(), RenderError>;
}
```

The library decrypts and frames the stream but does not decode it. What reaches a renderer
is a coded frame: an Annex-B access unit with its parameter sets already in front of it, or
one audio frame's payload. `VideoConfig::codec` says which coding the frames are in, because
`h264parse` cannot read an HEVC unit and an HEVC decoder cannot read H.264.

A stream is opened once per session, and both are `'static`, because the session moves each
one onto a thread that does nothing but write frames. This is the part of the design that
matters most to an implementor: a write may block as long as it likes, and the receive loop
carries on reading the socket meanwhile. That is why a queue sits in front of every stream,
and why a backend that needs to block is not a problem.

`AudioStream` takes `AudioFrame` and has `set_volume`, `flush`, `close`. `VideoStream` takes
`VideoFrame` and has `set_pace`, `flush`, `close`.

- `push` may block. It is called from a dedicated thread.
- `close` means the session has no more media. It does not have to destroy the stream.
- Dropping a stream must release whatever the backend holds.

`NullRenderer` implements the trait by accepting everything and playing nothing. It counts
what it was given, which makes it useful in tests as well as for inspecting a session.

## Media types

| Type | Contents |
| --- | --- |
| `AudioConfig` | codec, sample rate, channels, samples per frame; the last two come from the client's `spf` when it states one |
| `AudioFrame` | the coded payload and a timestamp in samples of the session rate |
| `VideoConfig` | width and height when the client stated them, and the coding of the frames |
| `VideoFrame` | an Annex-B access unit, a timestamp, and whether it is a key frame |
| `Volume` | silence to full volume, clamped on construction |
| `RenderError` | `Unavailable` when nothing can play, `Failed` when playback went wrong |

The audio timestamp counts samples, not nanoseconds, because that is what the client sends.
A renderer that schedules against a clock has to convert it; the GStreamer backend does.

## Modules

`receiver` is the only module a program needs to run a receiver. The others are public
because the pieces are individually useful, for instance in a test that wants to check the
decryption without running a server.

| Module | Contents |
| --- | --- |
| `receiver` | `run`, `Config`, `Error`, `ClientCallback` |
| `render` | the renderer traits and the media types above |
| `discovery` | `Advertisement`, `Advertiser`, `Protection`, and the text records |
| `server` | `Server`, `RouteHandlers`, `DeviceIdentity`, `PairingState`, `PinMode`, `SetupPorts` |
| `control` | the RTSP request parser and the route table |
| `media` | audio reordering, mirror decryption, the datagram sockets, the clock exchange |
| `pairing` | the `/pair-verify` and `/pair-setup` cryptography |
| `srp`, `crypto`, `fairplay`, `plist`, `rtp`, `ntp`, `wire` | the primitives those are built on |

## The command-line receiver

A command-line receiver is a separate program, not part of this crate:
[parlor-cli](https://github.com/rust-airplay/parlor-cli). Its README lists the options. The
library keeps every such decision out of itself on purpose - no environment variables, no
paths, no printing - so a program is where those belong.

## Logging

The library emits `log` records. `info` carries the progress a person watching a session
wants to see, `warn` carries a session that went wrong, and `debug` carries packet-level
detail. Nothing is printed if no logger is installed. The command-line receiver installs a
logger that writes `info` and below to standard output and warnings to standard error.
