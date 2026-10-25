# Changelog

## Unreleased

### Fixed

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

### Added

- `tests/receiver_spec.rs`: two sessions over real sockets, each with its own FairPlay key,
  asserting the decrypted frame, the second audio stream and the released control port.

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
