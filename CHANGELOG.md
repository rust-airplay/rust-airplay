# Changelog

## 0.3.0

### Fixed

- The mirror queue no longer drops only the oldest frame. An overflow clears the queued
  group and delivery waits for the next key frame, because a P frame whose reference was
  dropped cannot be decoded; the startup allowance is thirty frames or five hundred
  milliseconds, whichever comes first.
- The receiver no longer calls `VideoStream::set_pace` when `pace_video` is off: off now
  means full speed and backend backpressure, not a delegated pace. The trait documents the
  cumulative-deadline contract for a caller that uses it directly.
- The mirror reporter now separates frames received from frames written, and includes queue
  depth and dropped frames; the teardown line reports the same totals. A frame falling behind
  is visible instead of looking like a healthy stream.
- A second `SETUP` in one process starts a new media session: the audio loop follows the
  key and the clock target of the session that is current, so a reconnecting client is
  decrypted with its own key instead of the first session's. `TEARDOWN` releases the key,
  the clock target and the flush handles.
- `run` returns when Ctrl+C arrives. `serve(config, shutdown)` gives a program or a test its
  own stop condition, and returns after the control service stops and the advertisement is
  withdrawn.
- A password lockout is a bounded window (30 seconds by default) instead of a permanent
  refusal: one unauthenticated client can no longer disable a password-protected receiver
  until the process restarts.
- A legacy `/pair-setup` no longer bypasses the registered-client predicate; a client that
  did not prove a PIN must still be in the list.
- A UDP socket that reports an ICMP unreachable no longer ends the audio session; the
  transient error is counted and the receive loop continues.
- `Config::bind` and `Config::advertise` let a receiver listen on `127.0.0.1` without
  registering mDNS, which is what a test and a single-machine receiver need.
- `FLUSH` is served by the route handler instead of answered `501` by the control layer,
  so the reorder window is flushed and the renderer's `AudioStream::flush` is called;
  `VideoStream::set_pace` is called with the measured frame interval.
- A lost audio packet is asked for again: `controlPort` is read from `SETUP`, a gap in
  the reorder window produces a resend request on the control socket, and the answer
  fills the gap.
- Media datagrams are accepted only from the host that owns the session, a mirror TCP
  connection must come from that host, and a mirror connection that sends nothing is
  dropped after ten seconds.
- A configured password now guards `SET_PARAMETER`, `GET_PARAMETER` and `FLUSH`, not only
  `SETUP`.
- A fixed or one-time PIN is refused for a bounded window after five wrong proofs, and
  asking for a new one-time PIN no longer resets the count.
- `Debug` on `SetupRequest`, `StreamKeys`, `AudioSession`, the audio and video frames,
  `DigestAuthorization` and `FairPlaySession` prints sizes and redacts the material.
- The client volume is shared by every connection of a receiver, so a `GET_PARAMETER` on
  a second connection reads what the first set.
- `SetupRequest::debug_body` is off unless `Config::debug_setup_body` asks for it.
- The plist fixture's `ct` is 2 (ALAC), matching the code and upstream UxPlay.
- The 1.85 minimum is true again: the `let` chains in the control, feedback and mirror
  paths are rewritten as nested conditions, which is what the new MSRV CI job checks.
- The plist check refuses OpenStep/ASCII plists instead of bypassing the depth and object
  bounds; binary and XML plists remain accepted.
- Audio and video dumps write through a bounded queue to a writer thread, so a slow disk
  cannot block a receive loop; when the queue is full the diagnostic copy is dropped.
- The mirror packet reporter is aborted when its connection ends instead of running every
  five seconds for the rest of the process.
- A control connection failure is logged at debug level instead of discarded.
- `nohold` drops the previous connection from the same host only; a connection from
  another host keeps its slot.

### Changed

- `Config`, `ServerConfig`, `SetupRequest`, `AudioCodec`, `VideoCodec`, `RenderError`,
  `PinMode` and `SessionAuth` are `#[non_exhaustive]`: a later release can add a field or
  a variant without a breaking change. Build the configuration types through their
  constructors or defaults.
- CI checks the crate on the minimum supported Rust, and `BUILD.md` describes the CI that
  exists instead of saying there is none.
- `BACKEND.md` states that audio/video synchronization is not provided: the two
  timestamps count different clocks, and a backend that plays both builds the shared
  timeline itself.
- The three large modules are directories now: `media::mirror` (header, crypto, nal, codec,
  session), `server::handlers` (types, routes) and `server::pairing` (state, session). The
  small test files are inline, so no `src` directory contains only a `tests.rs`. Public
  paths are unchanged.
- The next tier is split too: `receiver` (config, state, runtime, serve), `media::audio`
  (packet, session, reorder), `media::ports` (sockets, mirror), `render` (codec, volume,
  frames, traits, null), `control` (route, dispatch, types, session), `media::timing`
  (request, clock) and `server::handlers::routes` (setup, parameters, info, pairing,
  helpers). Public paths are unchanged.
- `receiver::serve` no longer owns the task bodies: the audio receive loop is `AudioTask`
  and the mirror listener is `MirrorTask`, each taking its state explicitly. `playfair`
  separates garble from the session-key layer, `plist` separates the types from the
  structural check, and `discovery` separates the advertisement from the registrar.
- `wire` separates its limits, message head and parser, and `pairing` separates the key
  derivations from the Digest helpers. Public paths are unchanged.
- `Cargo.lock` is committed and CI, the MSRV job and release builds use `--locked`, so the
  tested graph and the published graph are the same. CI regenerates the plist fixtures and
  refuses a diff, and Dependabot tracks Cargo dependencies and Actions.
- Documentation follows the split: `ARCHITECTURE.md` records the module layout, the one media
  session rule and the security boundaries; `README.md` and `API.md` record the 0.3.0
  release and the previous 0.2.0; `BUILD.md` covers the lock policy, the fixture CI and
  Trusted Publishing; `MIGRATION.md` lists the 0.3.0 API changes.

### Added

- `tests/receiver_spec.rs`: two sessions over real sockets, each with its own FairPlay key,
  asserting the decrypted frame, the second audio stream and the released control port.
  It also covers a missing audio packet, the resend request, the renderer flush and the
  audio source filter.
- `MediaSockets::serve_from` and `send_control`, `SetupStream::control_port`,
  `PairingState::with_pin_lockout`, `RouteHandlers::set_client_volume` and
  `set_debug_body`, and the `RouteHandler::teardown` hook.

## 0.2.0

The first release: the protocol and media library for building AirPlay 1 and AirPlay 2
receivers, and the renderer boundary a playback backend implements.

### Protocol

- Discovery over mDNS, with both `_raop._tcp` and `_airplay._tcp` records and the text records a
  current client reads.
- The RTSP control service: `/info`, pairing with a PIN or a password, FairPlay for mirroring,
  `SETUP` for audio and mirror streams, `RECORD`, `FLUSH`, `TEARDOWN`, `/feedback`.
- Audio over RTP: per-packet encryption as AirPlay does it, a bounded reorder window, resend
  requests, and flush.
- Mirroring over TCP: the 128-byte header, the cipher position rule that a plain CTR stream does
  not have, codec data, geometry, pause and resume, and Annex-B framing for a decoder.
- Timing: the NTP exchange and the clock that turns a client timestamp into a local time.
- Client policy: allow and block lists, takeover from a previous client, and a feedback timeout.

### Playback

- `Renderer`, `AudioStream` and `VideoStream` as the boundary; coded frames cross it, never
  decoded ones.
- `NullRenderer` counts a session and plays nothing.
- A complete example backend in `examples/recorder.rs`, and `docs/BACKEND.md` as the guide to
  writing one.

### Documentation

- Every public item is documented, and the examples in that documentation compile as doctests.
- `docs/API.md` maps the types, `docs/ARCHITECTURE.md` the session path, and `docs/BACKEND.md`
  the renderer contract. Each has a Chinese copy beside it.

### Notes

- Minimum supported Rust version: 1.85 (2024 edition).
- The library does not print and does not choose paths; it reports through `log` and through
  callbacks on `Config`.
