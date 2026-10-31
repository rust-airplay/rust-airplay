# Architecture

Chinese: [ARCHITECTURE.zh-CN.md](ARCHITECTURE.zh-CN.md).

## The crate

This repository is one crate: the library. It depends on no other crate of this project,
which is what lets it build on a machine with no media libraries at all, and it is what makes
it publishable on its own.

Everything that is not the protocol lives elsewhere, one repository per decision:

| Repository | What it is |
| --- | --- |
| `rust-airplay` (this one) | discovery, the control protocol, pairing, decryption, framing, timing, the renderer boundary |
| [rust-airplay-gstream](https://github.com/rust-airplay/rust-airplay-gstream) | decoding and playback through GStreamer |
| [parlor-cli](https://github.com/rust-airplay/parlor-cli) | the command-line program |

A backend depends on this crate and implements `Renderer`; a program depends on both. The
direction is one way: nothing here knows that a backend or a program exists.

## Code layout

The module tree follows the protocol's own seams; a directory is a set of related
submodules, not a separate crate:

```
src/
├── receiver/       Config, shared state, the serve loop, AudioTask, MirrorTask
├── server/         control service; handlers/ (types, routes/) and pairing/ (state, session)
├── media/          audio/, mirror/, ports/, timing/, control, dmap, pace
├── control/        route table, dispatch, one connection's session, wire types
├── wire/           head limits, MessageHead, parser and body split
├── plist/          value wrapper, structural bounds, binary/XML checks
├── render/         traits, codecs, frames, volume, NullRenderer
├── discovery/      Advertisement and the mdns-sd registrar
├── pairing/        Apple-labelled key derivations and Digest helpers
├── playfair/       PlayFair garble and session-key layers
└── playfair_tables.rs, playfair/hand_garble_generated.rs
                    generated tables; not edited by hand
```

Unit tests live beside the module they test: in the file for a small suite, or in
`<module>/tests.rs` when the module is already a directory and the suite is large. The
integration tests in `tests/` use only the public API.

## What a session looks like

A client finds the receiver through mDNS, opens a TCP connection to the control port, and
speaks RTSP over it.

1. `GET /info` returns the same text record the receiver advertises, so a client that read
   it either way sees one advertisement.
2. `POST /pair-verify` proves the client holds the key it paired with. A client that has
   never paired uses `POST /pair-setup`, where the SRP exchange and a PIN on screen prove
   the user is in the room.
3. `POST /fp-setup` is the FairPlay handshake a mirroring client expects before it will
   send encrypted video.
4. `SETUP` names the streams. The reply carries the ports the receiver bound, and the
   request carries the keys the session will use.
5. `RECORD` starts playback. Media then arrives on the timing, control and data sockets,
   and the mirrored screen on the mirror listener.
6. `TEARDOWN`, or the connection closing, ends the session.

The audio key and the mirror identifier are the reason the session is shared between
connections. A client sends the audio key in one `SETUP`, then sends the mirror stream's
`streamConnectionID` in a later `SETUP` without repeating the key. Since the receiver builds
a handler set per connection, per-connection state would lose the key; the key therefore
belongs to the session.

## One media session at a time

The shared key slots hold **one** media session, not a mixer. Several control connections may
exist at once, but the latest `SETUP` that carries an audio key or a mirror identifier owns
the sockets, the renderer streams and the flush state; an earlier stream is replaced rather
than played alongside the new one. This is the shape a reconnecting client needs, and it is
also the reason a second authenticated client can take the session over. `nohold` controls
the connection lifetime: when enabled, a new connection from the **same host** closes the
previous one from that host. A connection from another host keeps its slot, but a successful
new `SETUP` still becomes the current media session. Programs that need stronger isolation
must enforce it outside this crate (network policy, separate receiver instances, or a client
registry used before the connection is accepted).

## Receiving media

Audio arrives as RTP over UDP. Each packet is decrypted with AES-CBC, where the reset is per
packet, and put into a bounded reordering window. When a sequence number is missing and the
client advertised one, the receiver asks for it again on the control socket; that request is
what turns a lost packet into a recoverable one. Frames leave the window in order, and a gap
that cannot be filled is counted and skipped so a stream that is missing one packet keeps
playing.

Mirroring arrives over TCP as packets behind a 128-byte header. The keystream for a packet
is AES-CTR over the stream's key and IV, and where a packet's bytes are taken from is the
subtle part: it starts where the previous packet ended, whole blocks at a time. A packet
that does not fill its final block leaves the rest of that block for the next packet, and
those bytes exist nowhere in the stream because they are the tail of a block that was
already read past. The counter then advances by the blocks the packet's own bytes filled.
The rule is written down this precisely because a test checks it byte by byte against a known
packet sequence, and because a version that reads the stream as an ordinary counter produces
noise rather than an error.

Frames leave the media path as Annex-B access units. A client that sends its parameter sets
separately gets them prepended to the frame they belong to.

## Flushing and pausing

A client that sends `FLUSH` is saying the picture it is about to send is not the one on
screen: after a pause, a seek, or a switch of media. The queued frames are stale, so the
queue is emptied and its generation bumped; the writer owns the renderer's stream and notices
the generation, which is how a backend that had already taken a frame is told to drop it.

A mirroring client also says when it stops and resumes, in the option of a codec packet
(`0x56`/`0x5e` stop, `0x16`/`0x1e` resume). That is not the same
as a quiet stream: the picture on screen is the one it stopped on. The receiver drops the
queued frames and reports the transition; a backend that wants to freeze its window has the
signal to do it.

## Keeping audio and video together

A mirroring client sends two streams with timestamps that have nothing in common. A mirror
frame carries NTP fixed point - the high half counts seconds since the device booted, which
one session showed as 8355 - and consecutive frames differ by about 143 million ticks, which
is 2^32 times thirty-three milliseconds. An audio frame carries an RTP counter that starts at
a random value and advances 480 samples a frame at 44.1 kHz. Subtracting one from the other
is subtracting two arbitrary origins, and every attempt to convert between them absolutely
was wrong by millions of seconds.

What the streams do share is a rate, so the receiver anchors each on the arrival of its first
frame and advances it by that rate: 2^32 ticks a second for the mirror stream, the sample
rate for audio. The client captures both at the same instant and sends them together, so the
two anchors are a network's width apart and stay there.

The timing exchange is not what does this, and it took a device session to establish why. Its
answers carry whole seconds, so its delay and offset are quantised at a second; the offset it
reports is a residual that is zero by construction on the exchange that fixes the epoch. It
is kept for the epoch it establishes - which converts a client timestamp to a local one for
diagnostics - and not for scheduling.

Waiting is bounded in both writers. A client sends a second of mirror frames in a few tens of
milliseconds, so pacing the burst at capture spacing would show the last frame of it a second
late; past forty milliseconds a frame is shown at once and the anchor moves to it. Pacing is
off by default for video altogether: a mirror is judged by how quickly it follows the device,
and `pace_video` trades that for even spacing when someone wants it.

## Rendering

Frames cross a trait boundary as owned buffers with a timestamp. The receive loop must never
wait for a renderer, so each stream is written from its own thread, fed by a queue.

A video queue has two phases. While the stream is still opening - the writer starts the
pipeline on the first frame, and a decoder and a window take a few hundred milliseconds - the
queue may grow to the smaller of thirty frames or five hundred milliseconds, whichever comes
first. That is enough for the opening burst without adding a second of latency to a mirror.
Once the stream plays and the backlog has drained below eight frames, the steady depth is
eight. An overflow does not trim one frame: the whole queue is cleared and delivery waits for
the next key frame, because a P frame whose reference was dropped decodes incorrectly until
an IDR arrives. A short freeze is visible; a group of pictures referring to a missing frame is
a long, corrupted picture. The periodic log carries packets in, frames received, frames
written, queue depth and frames dropped, so a queue that is falling behind is visible.

Audio has a queue of its own for the same reason, with a much smaller depth: a coded audio
frame is a few hundred bytes, and its timestamps are what a renderer paces against.

## Threads

`receiver::run` is async and serves every connection on the caller's Tokio runtime. Blocking
work has threads: the video writer (which owns the renderer's video stream), the audio writer
(which owns the renderer's audio stream and applies flushes), the mDNS advertiser, and the thread that watches for a
pending PIN. A renderer is therefore shared between the audio and video threads and must be
`Send + Sync`; its streams are moved onto the thread that writes them, and `push` may block.

The control connection itself never blocks on a renderer: it updates state, answers requests,
and hands media identifiers to the session that owns the sockets.

What crosses the boundary is coded, not decoded. A video frame is an Annex-B access unit with
its parameter sets already in front of it, so a backend needs a byte-stream decoder and no
knowledge of the protocol; an audio frame is one payload, one buffer, because a raw AAC-ELD
frame has neither a sync word nor a sample rate and a byte stream cannot say where it ends.
`VideoConfig::codec` says which coding the frames are in, and it is read from the codec
packet the client sends before its first frame. That is why the stream is opened on the first
frame rather than when a connection arrives.

Decoding and playback are another repository's job, and this is the reason a backend can be
written in a few dozen lines: it implements `Renderer`, chooses a decoder from `codec`, and
writes frames out.

## Discovery

The receiver registers both `_raop._tcp` and `_airplay._tcp` and fills their text records
with what a current client reads. Those values are load-bearing rather than cosmetic: bit 27
of the feature bitmap, for example, picks which client-pairing protocol the client uses.
Values are pinned field by field in the tests, and they were taken from a running receiver
rather than from a header, because a header records what a build starts from and the program
may change it before advertising.

## Security boundaries

These are the limits a program should know before exposing a receiver:

- The control protocol is RTSP in the clear. A PIN or password authenticates the control
  connection to the receiver; it does not encrypt the session, and it is not a substitute
  for network isolation.
- The `clients` list is an access predicate only while a PIN is configured, because that is
  when `/pair-verify` can use it without locking out a first legacy client. With the PIN
  disabled it is a record of verified keys, not an allow-list. A program that needs a real
  allow-list enforces it before accepting the connection.
- `/pair-pin-start` is reachable without authentication, as the protocol defines it. The
  pending PIN is bounded by the failure count and the 30-second lockout, so this endpoint
  does not give an unauthenticated peer an unbounded guessing oracle, but it can still make
  a PIN appear on screen.
- Media source filtering is by host: UDP datagrams and the mirror TCP connection must come
  from the session's control host. It is not a per-process or per-port boundary; another
  process on the same host shares that address.
- `ClientPolicy` and the `deviceID` a client sends are routing hints, not proof of identity:
  a peer chooses that value. Pairing keys and the PIN/password are what authenticate.
- The audio and video dumps are diagnostics. They are fed through bounded queues, so a slow
  disk can drop diagnostic frames; they never make the receive loop wait. A trace line
  carries headers and status, never a body, a key or a signature.
- One media session is current at a time, as described above. A second authenticated client
  can replace it; use separate receivers or network policy when that is not acceptable.

## Identity

An identity is 32 bytes of seed. The device identifier and the keys a session uses are
derived from it, so one seed is one receiver, and a client that paired with it once
recognises it after a restart. A client key is remembered after a session has carried it,
which is the honest limit: a client that never completed a session has not proved anything
yet.

The library stores neither the seed nor the client list. A program that persists them is what
makes a receiver recognisable; a program that does not is a receiver that looks new every
time, and that is a legitimate choice for a receiver that should not remember anything.
