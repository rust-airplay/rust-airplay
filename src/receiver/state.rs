// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared state, queue helpers and the session key.

use std::sync::{Arc, Condvar, Mutex, PoisonError};

use crate::crypto::sha512_concat;
use crate::render::{AudioCodec, AudioConfig};
pub(super) fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The stream type a mirroring client asks for, whose entry carries the
/// `streamConnectionID` the mirror keys are derived from
pub(super) const MIRROR_STREAM_TYPE: u16 = 110;

/// The device identifier a seed derives its keys from.
///
/// Derived rather than random so that one seed is one receiver: a client that paired with
/// it once recognises it again, which is the whole point of remembering keys.
pub(super) fn derived_device_id(seed: &[u8; 32]) -> String {
    let digest = sha512_concat(&[b"rust-airplay-device-id", seed]);
    let mut octets = [0u8; 6];
    octets.copy_from_slice(&digest[..6]);
    octets[0] = (octets[0] & 0xfc) | 0x02;
    octets
        .iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Lower-case hex, for the places a log names a key without carrying it anywhere.
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Frames a mirror session may hold for its renderer before it starts dropping them.
///
/// The queue exists so that waiting for a picture is not waiting inside the receive
/// loop. It is bounded because a client that sends faster than a decoder decodes must
/// not be able to make a receiver allocate without limit; a frame dropped when it is
/// full is reported, because a dropped frame is one the rest of the stream may depend
/// on. Thirty-two frames is about a second of a screen, which is longer than any
/// stall a decoder produces and far below anything a receiver would notice holding.
pub(super) const QUEUED_FRAMES: usize = 8;

/// How many frames may wait while the video stream is still being opened.
///
/// The writer opens the stream on the first frame, and a decoder plus a window take a few
/// hundred milliseconds. At sixty frames a second that is more than the steady-state depth,
/// and dropping frames during a GOP is what makes the picture corrupt: every frame after the
/// gap refers to a frame the decoder never saw. The queue is allowed to grow until the stream
/// is open, and the backlog is written as fast as the renderer takes it.
pub(super) const STARTUP_QUEUED_FRAMES: usize = 120;

/// One frame waiting for the video writer.
///
/// The bytes, the client's timestamp, whether it is a key frame, when it arrived, the
/// coding it is in and the geometry the session announced: everything the writer needs to
/// open a stream on the first frame and pace the rest.
pub(super) type QueuedVideo = (
    Vec<u8>,
    u64,
    bool,
    u64,
    crate::render::VideoCodec,
    Option<crate::media::mirror::Geometry>,
);

/// Frames waiting for the renderer, where a full queue drops the **oldest**.
///
/// A channel would be the obvious thing and it is wrong here. `SyncSender` refuses the
/// newest frame when it is full, so the frames it already holds are the ones that stay
/// queued — the renderer works through a picture that is a second old while the client
/// keeps sending, and what grows is exactly how far behind the screen is.
///
/// Dropping the oldest bounds the lag at the queue's depth instead. The picture cost is
/// the same either way — a frame the rest of the stream depends on is gone — but the
/// receiver no longer also drifts further behind the thing it is mirroring.
#[derive(Debug)]
pub(super) struct FreshestFrames {
    state: Mutex<Frames>,
    ready: Condvar,
}

#[derive(Debug, Default)]
pub(super) struct Frames {
    queued: std::collections::VecDeque<QueuedVideo>,
    /// Set when no more frames will arrive, which is what wakes the writer for the last
    /// time.
    ended: bool,
    /// How many frames were dropped to keep the queue at its depth.
    dropped: u64,
    /// Bumped by a flush, so the writer knows the frames it was about to show are stale.
    pub(super) generation: u64,
    /// Set once the queue has drained below the steady depth after the stream opened.
    ///
    /// Before that it may grow, because the frames waiting for a pipeline to open are not an
    /// overflow. Once past it, the strict depth applies for the rest of the session.
    steady: bool,
}

impl FreshestFrames {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(Frames::default()),
            ready: Condvar::new(),
        }
    }

    /// Drops every frame waiting and tells the writer the picture starts over.
    ///
    /// A client sends `FLUSH` when what it played is no longer what it is about to play,
    /// and the frames queued here are the old picture. The generation is what reaches the
    /// writer, because it owns the renderer's stream: dropping the queue without telling
    /// it would leave the backend showing the frames it had already taken.
    pub(super) fn clear(&self) -> u64 {
        let mut state = lock(&self.state);
        state.queued.clear();
        state.generation += 1;
        let generation = state.generation;
        drop(state);
        self.ready.notify_one();
        generation
    }

    /// The generation a flush left behind, for a writer that has to notice it.
    pub(super) fn generation(&self) -> u64 {
        lock(&self.state).generation
    }

    /// Adds a frame, keeping the queue at its depth once the stream is playing.
    ///
    /// While the video stream is still opening the queue may grow to
    /// [`STARTUP_QUEUED_FRAMES`]; after that it is allowed to drain back to
    /// [`QUEUED_FRAMES`] before the strict depth applies again. Switching straight to the
    /// strict depth would judge the frames that were waiting for the pipeline to open as an
    /// overflow.
    ///
    /// Beyond the depth the oldest frame goes, because what the renderer should show is the
    /// newest picture there is. That frame may be one a later frame refers to, which is why a
    /// drop is reported: the picture can be damaged until the next key frame arrives.
    ///
    /// Returns how many are waiting afterwards and whether this call dropped a frame, so a
    /// caller can report a depth without asking a second question.
    pub(super) fn put(&self, frame: QueuedVideo, opened: bool) -> (usize, bool) {
        let mut state = lock(&self.state);
        if state.ended {
            return (0, false);
        }
        if opened && !state.steady && state.queued.len() < QUEUED_FRAMES {
            state.steady = true;
        }
        let limit = if state.steady {
            QUEUED_FRAMES
        } else {
            STARTUP_QUEUED_FRAMES
        };
        let mut dropped = false;
        if state.queued.len() >= limit {
            state.queued.pop_front();
            state.dropped += 1;
            dropped = true;
        }
        state.queued.push_back(frame);
        let depth = state.queued.len();
        drop(state);
        self.ready.notify_one();
        (depth, dropped)
    }

    /// Takes the next frame if one is waiting, without blocking.
    #[cfg(test)]
    pub(super) fn try_take(&self) -> Option<QueuedVideo> {
        lock(&self.state).queued.pop_front()
    }

    /// Takes the next frame, waiting until there is one or the queue has ended.
    pub(super) fn take(&self) -> Option<QueuedVideo> {
        let mut state = lock(&self.state);
        loop {
            if let Some(frame) = state.queued.pop_front() {
                return Some(frame);
            }
            if state.ended {
                return None;
            }
            state = self
                .ready
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    /// Says that no more frames are coming, and wakes whoever is waiting.
    pub(super) fn end(&self) {
        lock(&self.state).ended = true;
        self.ready.notify_all();
    }

    /// How many frames were dropped to keep the queue at its depth.
    pub(super) fn dropped(&self) -> u64 {
        lock(&self.state).dropped
    }
}

/// How many audio frames a writer thread will hold before frames start being dropped.
///
/// Audio packets are small and arrive in bursts, so this is deeper than the video
/// queue: at 44.1 kHz a frame is a few milliseconds, and a second of slack is what a
/// decoder stall needs. It is still bounded, because an unbounded queue turns "the
/// pipeline has stopped" into a growing delay rather than a visible fault.
pub(super) const QUEUED_AUDIO_FRAMES: usize = 256;

pub(super) fn open_audio(
    renderer: &Arc<dyn crate::Renderer>,
    codec: AudioCodec,
    samples_per_frame: u16,
) -> Option<Box<dyn crate::AudioStream>> {
    let config = AudioConfig {
        codec,
        samples_per_frame,
        ..AudioConfig::default()
    };
    match renderer.open_audio(config) {
        Ok(stream) => {
            log::info!(
                "media     audio stream open, {} at {}",
                codec.name(),
                config.sample_rate
            );
            Some(stream)
        }
        Err(error) => {
            log::warn!("rust-airplay: cannot play audio: {error}");
            None
        }
    }
}

/// A future that is ready when the receiver is stopping.
///
/// A receiver ends when the caller asks it to, and its receive loops need to be told: a loop
/// that outlived the control plane would hold a sound card or a window open with nothing to
/// play into it.
pub(super) type Stopping = tokio::sync::watch::Receiver<bool>;

/// The audio key and IV of one session, and the number that tells sessions apart.
///
/// A receiver in a long-running process serves more than one session. Every `SETUP` that
/// carries a key starts one, so the receive loop has to be able to tell the key it is
/// reading from the one it was started with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SessionKey {
    pub(super) key: [u8; 16],
    pub(super) iv: [u8; 16],
    pub(super) generation: u64,
}

/// Waits for the stop signal, or returns at once when it has already fired.
pub(super) async fn stopped(mut signal: Stopping) {
    if *signal.borrow() {
        return;
    }
    let _ = signal.changed().await;
}
