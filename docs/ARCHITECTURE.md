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

A video queue has two depths. While the stream is still opening - the writer starts the
pipeline on the first frame, and a decoder and a window take a few hundred milliseconds - the
queue may grow to a hundred and twenty frames, because a quarter of a second of unsent frames
is not an overflow and dropping them during a group of pictures leaves the decoder referring
to pictures it never saw. Once the stream plays and the backlog has drained, the queue keeps
eight frames: a frame that does not fit means the renderer is behind, the oldest goes, and the
log says the picture may be damaged until the next key frame. Both numbers exist because the
opposite choices both had a visible failure: dropping during the opening burst corrupted the
picture, and switching to the steady depth while the opening backlog was still queued emptied
it and waited for a key frame a client never sends.

Audio has a queue of its own for the same reason, with a much smaller depth: a coded audio
frame is a few hundred bytes, and its timestamps are what a renderer paces against.

## Threads

`receiver::run` is async and serves every connection on the caller's Tokio runtime. Blocking
work has threads: the video writer (which owns the renderer's video stream), the audio pump
(which pushes frames into an `appsrc`), the mDNS advertiser, and the thread that watches for a
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

## Identity

An identity is 32 bytes of seed. The device identifier and the keys a session uses are
derived from it, so one seed is one receiver, and a client that paired with it once
recognises it after a restart. A client key is remembered after a session has carried it,
which is the honest limit: a client that never completed a session has not proved anything
yet.

The library stores neither the seed nor the client list. A program that persists them is what
makes a receiver recognisable; a program that does not is a receiver that looks new every
time, and that is a legitimate choice for a receiver that should not remember anything.
