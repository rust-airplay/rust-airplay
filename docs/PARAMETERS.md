# Parameters: upstream's command line as this library's API

Chinese: [PARAMETERS.zh-CN.md](PARAMETERS.zh-CN.md).

UxPlay is a program, and everything it can be told is a command-line option. This project is
a library, so the same decisions have to be reachable as values. This page maps one to the
other, in both directions, and says what is implemented and what is planned. A reader should
be able to look up an upstream option here and know where the equivalent lives - or that it
does not exist yet.

Three surfaces are involved:

- **Config** in this crate (`rust_airplay::Config`), for the protocol, the session, the media
  policy and discovery.
- **Options** in a backend (`rust_airplay_gstream::Options`), for decoding and playback.
- **the program**, for file locations, log formatting and printing. This library owns none of
  those on purpose.

## Implemented

| Upstream | What it does | Here |
| --- | --- | --- |
| `-n name` | the name clients see | `Config::name` |
| `-nh` | do not append `@hostname` to the name | the caller builds `Config::name`; no hostname is appended by the library |
| `-pin[xxxx]` | require a PIN, optionally fixed | `Config::pin` (`PinMode::OneTime` or `PinMode::Fixed`) |
| `-pw [pwd]` | require the `SETUP` digest password | `Config::password` |
| `-m [mac]` | the advertised hardware address | `Config::device_id`; derived from the seed when `None` |
| `-key [fn]` | the private key, and its file | `Config::seed`; storing it is the program's job |
| `-reg [fn]` | the register of clients already paired | `Config::clients` and `Config::on_client` |
| `-p n` | the control port | `Config::port` |
| `-p` (no value) | upstream's fixed media port layout | `Config::ports` set to `MediaPorts::legacy()` |
| `-p` with explicit ports | fixed timing, control, data and mirror ports | `Config::ports` |
| `-al x` | audio delay reported to the client | `Config::audio_latency` |
| `-s wxh@r` | the display size, refresh rate and frame cap a client is offered | `Config::display` |
| `-fps n` | the highest frame rate asked of the client | `Config::display.max_fps` |
| `-o` | overscanned display | `Config::display.overscanned` |
| `-h265` | allow HEVC and offer 4K | `Config::features` with bit 42 set, and `Config::display` at 3840x2160; the program decides the default size |
| `-hls` (feature bit only) | tell clients HLS is supported | `Config::features` with bit 4 set; the routes themselves are still `501` |
| `-nohold` | a new client takes over from the current one | `Config::nohold` |
| `-reset n` | close a session with no feedback for n seconds | `Config::feedback_timeout` |
| `-FPSdata` | show the client's streaming reports | `Config::log_streaming_reports` |
| `-ca [fn]` | cover art, or a file to write it to | `Config::on_artwork`; writing a file is the program's |
| `-md <fn>` | metadata text to a file | `Config::on_metadata` with `media::dmap::text` |
| `-dacp [fn]` | export the remote-control identifiers | `Config::on_remote_control` |
| `-taper` | the tapered volume profile | `Config::volume_curve.taper` |
| `-db l:h` | the decibel range the slider is rescaled onto | `Config::volume_curve.low_db` and `high_db` |
| `-restrict` | admit only the devices in the allow list | `Config::client_policy.restrict` |
| `-allow <deviceID>` | a device that is admitted | `Config::client_policy.allow` |
| `-block <deviceID>` | a device that is never admitted | `Config::client_policy.block` |
| `-vol <v>` | the volume a session starts at | `Config::initial_volume` |
| `-as ...` | the audio sink | `Options::audio_sink` in the backend |
| `-vs ...` | the video sink | `Options::video_sink` |
| `-vp ...` | the video parser | `Options::video_parser` |
| `-vd ...` | the video decoder | `Options::video_decoder` |
| `-d` and friends | logging | the `log` crate; the program installs a logger |

Two behaviours are parameters even though upstream has no option for them, because a
library cannot decide them: `Config::pace_video` (hold video to its capture spacing) and
`Config::renderer` (what plays the media).

## Backend-only

These are about decoding and presentation, so they belong to a backend's `Options`, not to
this crate:

| Upstream | What it does | Where |
| --- | --- | --- |
| `-avdec` | force software decoding | a decoder string in `Options::video_decoder` |
| `-vc ...` | the video converter | part of `Options::video_decoder` |
| `-v4l2`, `-bt709`, `-srgb` | platform decoding and colour | pipeline strings, not yet surfaced |
| `-f {H,V,I}`, `-r {R,L}` | flip and rotate | not yet surfaced |
| `-o`, `-fs` | overscan, full screen | sink properties, not yet surfaced |
| `-vs 0`, `-as 0`, `-a` | no video window, no audio | `--render null`, or a null sink in the backend |
| `-vrtp`, `-artp` | re-pay the decoded stream somewhere else | not implemented |
| `-nc`, `-nofreeze` | window lifetime after a session | not implemented |

## Client-only

| Upstream | What it does | Where |
| --- | --- | --- |
| `-key [fn]`, `-reg [fn]` | where the seed and the client list are stored | the program decides; `parlor-cli` keeps both under the user's application data directory |
| `-d` | log level and format | the program's logger |

## Where this leaves the table

Every upstream option is now in exactly one place: implemented on a library value, a backend
option, a program decision, or the not-supported list below with a reason. There is no
"planned" tier left to read as a promise.

## Not supported

These are not planned, and the reason is a decision rather than missing time.

| Upstream | Why not |
| --- | --- |
| `-hls`, `-lang`, `-slang`, `-custom`, `-rpi` | HTTP Live Streaming needs a player, a playlist fetcher and an event channel to the client; the receiver routes were removed rather than answered `200` while doing nothing, and the feature bits stay clear. |
| `-mp4` | Recording needs the media path to keep a muxer and a file between sessions; the library owns neither a file nor a codec. |
| `-p2p` | Apple peer-to-peer discovery has no equivalent in `mdns-sd`; the discovery layer would have to grow a second transport. |
| `-scrsv` | A screensaver is the program's business, and this library is the program's library. |
| `POST /reverse` | The event channel exists to carry HLS playlist requests from the receiver to the client. Without HLS there is nothing to carry, so the route answers `501` instead of holding open a socket that will never be written to. |
| `-vsync`, `-async` | Both select a clock to synchronise against. This receiver anchors each stream on the arrival of its first frame and paces by the stream's own timestamps, which a device session showed keeps audio and video together without an absolute conversion; the exchange cannot supply one at finer than a second. |
