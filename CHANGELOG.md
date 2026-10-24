# Changelog

## 0.1.0

The first release: an AirPlay 1 and AirPlay 2 receiver as a library, and the renderer boundary
a playback backend implements.

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

### Notes

- Minimum supported Rust version: 1.85 (2024 edition).
- The library does not print and does not choose paths; it reports through `log` and through
  callbacks on `Config`.
- Not implemented, and recorded as such in `docs/PARAMETERS.md`: HLS, recording, peer-to-peer
  discovery, a screensaver, and the reverse event channel those depend on.
