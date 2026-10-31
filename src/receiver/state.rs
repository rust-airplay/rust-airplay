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

/// Frames a playing mirror may hold for its renderer before the queue restarts.
///
/// The queue exists so that waiting for a picture is not waiting inside the receive
/// loop. It is bounded because a client that sends faster than a decoder decodes must
/// not be able to make a receiver allocate without limit. Eight frames is a fraction of
/// a second at a normal mirror rate; an overflow is reported and waits for a key frame
/// rather than trimming one frame out of the middle of a group.
pub(super) const QUEUED_FRAMES: usize = 8;

/// Above this many frames the startup backlog stops growing.
///
/// The writer opens the stream on the first frame, and a decoder plus a window take a few
/// hundred milliseconds. The queue may grow while the stream is closed, but not without a
/// bound. Thirty frames is one second at thirty frames a second, but the time window cuts the
/// allowance at half a second first; the frame cap is there for a stream that arrives in a
/// burst.
pub(super) const STARTUP_QUEUED_FRAMES: usize = 30;

/// How old the startup backlog may become before it is cut to a key frame.
///
/// Thirty frames and five hundred milliseconds are two limits on the same delay: whichever
/// is reached first ends the startup allowance. A device that sends a burst should not make
/// the viewer wait for the whole burst to drain.
pub(super) const STARTUP_WINDOW_NANOS: u64 = 500_000_000;

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

/// Frames waiting for the renderer, with a bounded queue and a key-frame restart.
///
/// A channel would be the obvious thing and it is wrong here. `SyncSender` refuses the
/// newest frame when it is full, so the frames it already holds are the ones that stay
/// queued — the renderer works through a picture that is a second old while the client
/// keeps sending, and what grows is exactly how far behind the screen is.
///
/// This queue bounds both the depth and the age. On overflow it clears the group and waits
/// for the next key frame; trimming one frame would leave every later P frame referring to a
/// picture the decoder never saw.
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
    /// Set once the startup allowance has ended.
    ///
    /// Before that the queue may grow, because the frames waiting for a pipeline to open are
    /// not an overflow. Once past it, the strict depth applies for the rest of the session.
    steady: bool,
    /// Set when a gap was created: frames are dropped until the next key frame.
    ///
    /// P frames refer to earlier frames by number, not by content, so once one is missing the
    /// rest of that group cannot be decoded correctly. Dropping every frame until an IDR is a
    /// short freeze; playing a group with a missing reference is a long, visibly broken picture.
    damaged: bool,
    /// Arrival time of the first startup frame, in the receiver's elapsed nanoseconds.
    startup_started: Option<u64>,
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

    /// Adds a frame, keeping the queue bounded and waiting for a key frame after a gap.
    ///
    /// While the video stream is still opening the queue may grow to
    /// [`STARTUP_QUEUED_FRAMES`] or [`STARTUP_WINDOW_NANOS`], whichever comes first. When the
    /// stream opens and the backlog has drained below [`QUEUED_FRAMES`], the strict depth
    /// applies. An overflow does not drop one frame: the whole queue is cleared and the
    /// writer waits for the next key frame, because a P frame whose reference was dropped
    /// cannot be decoded correctly.
    ///
    /// Returns how many are waiting afterwards and whether this call dropped a frame, so a
    /// caller can report a depth without asking a second question.
    pub(super) fn put(&self, frame: QueuedVideo, opened: bool) -> (usize, bool) {
        let mut state = lock(&self.state);
        if state.ended {
            return (0, false);
        }

        let mut dropped = false;
        if !state.steady {
            let started = *state.startup_started.get_or_insert(frame.3);
            let too_old = frame.3.saturating_sub(started) > STARTUP_WINDOW_NANOS;
            if state.queued.len() >= STARTUP_QUEUED_FRAMES || too_old {
                state.steady = true;
                state.startup_started = None;
                dropped = !state.queued.is_empty();
                state.dropped += state.queued.len() as u64;
                state.queued.clear();
                state.damaged = true;
            } else if opened && state.queued.len() < QUEUED_FRAMES {
                state.steady = true;
                state.startup_started = None;
            }
        }

        // A gap was created. Only a key frame can restart decoding cleanly.
        if state.damaged {
            if !frame.2 {
                state.dropped += 1;
                return (0, true);
            }
            state.damaged = false;
        }

        if state.steady && state.queued.len() >= QUEUED_FRAMES {
            dropped = true;
            state.dropped += state.queued.len() as u64;
            state.queued.clear();
            state.damaged = true;
            if !frame.2 {
                state.dropped += 1;
                return (0, true);
            }
            state.damaged = false;
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

    /// How many frames are waiting for the writer.
    pub(super) fn depth(&self) -> usize {
        lock(&self.state).queued.len()
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
