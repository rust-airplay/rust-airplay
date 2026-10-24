# Writing a playback backend

`rust-airplay` receives and decrypts a session; it does not play anything. Playback is a
value the program injects: an implementation of [`Renderer`][renderer]. This document is the
contract, in the order a backend meets it.

`rust-airplay-gstream` is the reference implementation. Read it beside this document.

## The trait

```rust
pub trait Renderer: Debug + Send + Sync {
    fn open_audio(&self, config: AudioConfig) -> Result<Box<dyn AudioStream>, RenderError>;
    fn open_video(&self, config: VideoConfig) -> Result<Box<dyn VideoStream>, RenderError>;
    fn set_volume(&self, volume: Volume) -> Result<(), RenderError>;
}
```

Three methods, because there are three things a receiver does to a session: it opens an audio
stream, opens a video stream, and changes the volume. A session can have audio without video
(an audio-only client) and video without audio (a silent mirror), so the two streams are
independent. One renderer may serve both, and a program may hand two different renderers to
two receivers; nothing in the trait assumes they are the same object.

Every method takes `&self`. The receiver holds the renderer while its media threads hold the
streams, and `open_audio` can be called again after a client reconnects. A backend keeps
mutable state behind its own lock; the reference implementation keeps the playing stream's
volume element in a `Mutex<Option<WeakRef<Element>>>`.

## Threading

- The renderer is `Send + Sync` and is shared by the audio and video paths.
- `push` is called from the thread that owns that stream. For video that is the writer
  thread; for audio it is the task that reads the audio socket. It is not called from the
  protocol connection, and it must not block for long: a slow `push` is backpressure on the
  network read, not a pause.
- A backend that needs its own thread (a pipeline thread, a rendering loop) starts it in
  `open_*` and stops it in `Drop` as well as in `close`. A receiver can drop a stream without
  closing it when a session dies, and a backend that only stops on `close` leaks a thread or a
  device.

## Opening an audio stream

`open_audio` is called when the client has declared its audio coding.

`AudioConfig` carries everything a decoder needs to be built before a frame exists:

| Field | Meaning |
| --- | --- |
| `codec` | `Alac` or `AacEld`, from the client's `ct` (or `Config::audio_codec` when it did not say) |
| `sample_rate` | 44 100, the rate every AirPlay audio format this crate supports uses |
| `channels` | 2 for every client seen so far |
| `samples_per_frame` | the client's `spf`, which is how many samples one frame carries |

A coded frame is one `push`. Unlike video, an audio frame has no start code: the only
boundary is the push itself, so a backend must decode per buffer rather than by scanning
bytes. That is why the reference backend uses `appsrc` for audio and a byte stream for video.

## Frames

`AudioFrame`:

```rust
pub struct AudioFrame {
    pub data: Vec<u8>,
    pub timestamp: u64,
}
```

- `data` is one coded frame, exactly as decrypted, with no container around it.
- `timestamp` is the client's RTP timestamp. It counts **samples**, not seconds and not
  nanoseconds: consecutive frames are `samples_per_frame` apart (480 at 44.1 kHz). Convert
  with `timestamp / sample_rate` before comparing it to a wall clock; treating it as
  nanoseconds puts every frame at a time unrelated to when it plays.

`VideoFrame`:

```rust
pub struct VideoFrame {
    pub data: Vec<u8>,
    pub timestamp: u64,
    pub keyframe: bool,
}
```

- `data` is an Annex-B access unit: the parameter sets (SPS/PPS, or VPS/SPS/PPS for HEVC)
  are prepended when they change, and every NAL unit starts with `00 00 00 01`.
- `timestamp` is an NTP fixed-point Q32.32 value: the high 32 bits are seconds and the low 32
  bits are the fraction. A mirroring client's clock is not the receiver's, so this is useful
  for spacing frames, not for scheduling against the local clock.
- `keyframe` is true for an IDR. A decoder starts there; frames before it cannot be decoded.

## Pacing

Writing a mirror stream as fast as it arrives decodes faster than real time. A mirror stream
is one key frame followed by frames that describe only what changed, so decoding too quickly
drops frames the rest of the stream depends on, and the picture stays partly wrong.

The receiver therefore offers two hooks:

- `VideoStream::set_pace(seconds)`, called before a frame with the interval until the next
  one. The default does nothing; a backend with a clock can sleep or schedule.
- `Config::pace_video`, which asks the receiver itself to hold each frame back before
  calling `push`. It is off by default: a mirror is judged by how quickly the picture follows
  the device, and pacing spends latency to buy smoothness.

## Flushing, pausing, closing

- `flush` means the media already handed over is stale. The client sent `FLUSH` (a seek, a
  mode change), or the receiver dropped frames because it fell behind. Drop what is queued;
  a decoder should also reset so the next key frame starts a clean picture.
- `pause` and `resume` follow the client's own statement that it stopped or resumed sending.
  They default to doing nothing: a pipeline that stops receiving frames already holds its last
  picture.
- `close` ends the stream; the next session opens a new one.

## Volume

`Renderer::set_volume` takes a `Volume`: a linear gain from `0.0` to `1.0`, where `1.0` is
unity. The client speaks decibels and the library converts them; a backend never sees a
decibel value.

`set_volume` is called once before any client connects (with `Config::initial_volume`, another
linear gain) and again whenever a client changes its slider. A backend has to do both:

1. apply the gain to the stream that is playing now, and
2. remember it for streams opened later, because a pipeline usually starts before a client
   says anything about volume.

The reference implementation applies the property to the live `volume` element and keeps the
value for the next `open_audio`.

## Errors

`RenderError::Unavailable` means this machine cannot serve the request (a missing decoder, no
sound card, no display). The session continues without that stream and the reason is reported:
a receiver that silently plays nothing is worse than one that says why.

`RenderError::Failed` means the backend was asked to do something and could not. The receiver
reports it and does not retry; a retry loop inside a backend is a backend that hides its own
failures.

## A minimal backend

This one writes what it is given to files. It is complete: it opens both streams, writes every
frame, handles a flush by discarding nothing (files are append-only) and closes on drop.

```rust
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex};

use rust_airplay::{
    AudioConfig, AudioFrame, AudioStream, RenderError, Renderer, VideoConfig, VideoFrame,
    VideoStream, Volume,
};

struct Recorder {
    audio: Arc<Mutex<Option<File>>>,
    video: Arc<Mutex<Option<File>>>,
    volume: Mutex<Volume>,
}

struct RecordingStream {
    file: Arc<Mutex<Option<File>>>,
}

impl AudioStream for RecordingStream {
    fn push(&self, frame: AudioFrame) -> Result<(), RenderError> {
        let mut slot = self.file.lock().expect("the recorder lock");
        if let Some(file) = slot.as_mut() {
            file.write_all(&frame.data).map_err(|error| RenderError::Failed(error.to_string()))?;
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), RenderError> {
        Ok(())
    }

    fn close(&self) -> Result<(), RenderError> {
        *self.file.lock().expect("the recorder lock") = None;
        Ok(())
    }
}

impl VideoStream for RecordingStream {
    fn push(&self, frame: VideoFrame) -> Result<(), RenderError> {
        let mut slot = self.file.lock().expect("the recorder lock");
        if let Some(file) = slot.as_mut() {
            file.write_all(&frame.data).map_err(|error| RenderError::Failed(error.to_string()))?;
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), RenderError> {
        Ok(())
    }

    fn close(&self) -> Result<(), RenderError> {
        *self.file.lock().expect("the recorder lock") = None;
        Ok(())
    }
}

impl Renderer for Recorder {
    fn open_audio(&self, _config: AudioConfig) -> Result<Box<dyn AudioStream>, RenderError> {
        let file = File::create("audio.aac").map_err(|error| RenderError::Unavailable(error.to_string()))?;
        *self.audio.lock().expect("the recorder lock") = Some(file);
        Ok(Box::new(RecordingStream { file: Arc::clone(&self.audio) }))
    }

    fn open_video(&self, _config: VideoConfig) -> Result<Box<dyn VideoStream>, RenderError> {
        let file = File::create("video.h264").map_err(|error| RenderError::Unavailable(error.to_string()))?;
        *self.video.lock().expect("the recorder lock") = Some(file);
        Ok(Box::new(RecordingStream { file: Arc::clone(&self.video) }))
    }

    fn set_volume(&self, volume: Volume) -> Result<(), RenderError> {
        *self.volume.lock().expect("the volume lock") = volume;
        Ok(())
    }
}
```

Two things the example does not need and a real backend does:

- **A clock.** Frames arrive with timestamps; a player turns those into presentation times.
- **A device.** A sink, a window, or both; where they come from is the backend's business.

`NullRenderer` is the other end of the range: it accepts everything, counts frames, and plays
nothing. It exists so a session can run end to end without a media library, and so a
backend's behaviour can be compared with a known-good consumer.

## Testing a backend

- `NullRenderer` proves the protocol path.
- A recording backend proves the frames: write them and open the result in a normal player.
  A video file of Annex-B units is a valid `.h264` or `.h265` stream; an audio file of coded
  frames needs a container and the coding's configuration, which the tests in the reference
  backend show how to build.
- Runtime tests belong behind an `#[ignore]` and a guard that skips when the environment has
  no media stack; `cargo test -- --ignored` runs them on a machine that has one.

## Checklist

- [ ] `Renderer` is `Send + Sync`; mutable state is behind a lock.
- [ ] `push` does not block for long; work that does belongs on the backend's own thread.
- [ ] The stream stops on `Drop`, not only on `close`.
- [ ] Audio timestamps are divided by the sample rate before becoming a time.
- [ ] Video frames are treated as Annex-B, with parameter sets prepended.
- [ ] `flush` drops queued media and resets the decoder.
- [ ] `set_volume` applies to the live stream and is remembered for the next one.
- [ ] `Unavailable` is used for an environment that cannot serve a stream; `Failed` for a
      request that could not be carried out.
- [ ] A missing media stack is reported once, and the receiver keeps serving clients.

[renderer]: https://docs.rs/rust-airplay/latest/rust_airplay/render/trait.Renderer.html
