// SPDX-License-Identifier: GPL-3.0-or-later
//! Delivering audio in sequence order through a bounded reorder window.

use std::collections::VecDeque;

use super::packet::{AudioPayloadKind, WINDOW_CAPACITY};

/// One audio payload, ready for a renderer.
#[derive(Clone, PartialEq, Eq)]
pub struct AudioFrame {
    /// Sequence number this payload arrived with.
    pub sequence: u16,
    /// RTP timestamp of the payload.
    pub timestamp: u32,
    /// Decrypted payload; still encrypted until the decryption slice lands.
    pub payload: Vec<u8>,
    /// What the payload is.
    pub kind: AudioPayloadKind,
}

impl std::fmt::Debug for AudioFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AudioFrame")
            .field("sequence", &self.sequence)
            .field("timestamp", &self.timestamp)
            .field("payload", &format!("<{} bytes>", self.payload.len()))
            .field("kind", &self.kind)
            .finish()
    }
}

/// Delivers audio payloads in sequence order, holding a bounded amount of them.
///
/// A network reorders, duplicates and loses datagrams, so a receiver cannot hand
/// payloads on as they arrive: the renderer needs them in the order the client
/// produced them. The window does that with a fixed number of slots, and when a
/// gap cannot be filled it steps over it and records what was missing, which is
/// the signal the retransmission step will use.
#[derive(Debug)]
pub struct ReorderWindow {
    pub(super) capacity: usize,
    /// Frames waiting for their turn, oldest first; a missing one is `None`.
    pending: VecDeque<Option<AudioFrame>>,
    /// Sequence number the next delivered frame has to carry.
    next: u16,
    /// Whether the first frame has been seen, which fixes the starting point.
    started: bool,
    /// Sequence numbers given up on, oldest first.
    lost: Vec<u16>,
    /// Sequence numbers already asked for, so one gap is not requested on every packet.
    requested: Vec<u16>,
}

impl Default for ReorderWindow {
    fn default() -> Self {
        Self::new(WINDOW_CAPACITY)
    }
}

impl ReorderWindow {
    /// Creates a window that holds at most `capacity` frames.
    ///
    /// A capacity of zero would never deliver anything, so it is raised to one.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            pending: VecDeque::with_capacity(capacity),
            next: 0,
            started: false,
            lost: Vec::new(),
            requested: Vec::new(),
        }
    }

    /// Sequence numbers this window gave up on since they were last taken.
    pub fn take_lost(&mut self) -> Vec<u16> {
        std::mem::take(&mut self.lost)
    }

    /// Sequence numbers missing from the window that have not been asked for yet.
    ///
    /// A gap is visible as a `None` slot between the packet that was delivered and the
    /// one that skipped ahead. Asking once per sequence keeps a burst of packets from
    /// producing a burst of identical requests; a request that is answered fills the
    /// slot, and one that is not is not repeated for the life of the window.
    pub fn take_resend_requests(&mut self, limit: usize) -> Vec<u16> {
        let mut requests = Vec::new();
        for (index, slot) in self.pending.iter().enumerate() {
            if requests.len() >= limit {
                break;
            }
            if slot.is_some() {
                continue;
            }
            let sequence = self.next.wrapping_add(index as u16);
            if self.requested.contains(&sequence) {
                continue;
            }
            self.requested.push(sequence);
            requests.push(sequence);
        }
        requests
    }

    /// Restarts the window at `next`, discarding everything it holds.
    ///
    /// A client sends `FLUSH` when what it played is no longer what it is about to play:
    /// after a pause, a seek, or a switch of media. Everything queued is audio nobody
    /// wants, and the sequence the client names is the next one it considers playable
    /// Without this, resuming
    /// plays back whatever was buffered before the pause.
    pub fn flush(&mut self, next: u16) {
        self.pending.clear();
        self.lost.clear();
        self.requested.clear();
        self.next = next;
        self.started = true;
    }

    /// Frames waiting for a gap to be filled.
    pub fn pending(&self) -> usize {
        self.pending.iter().filter(|slot| slot.is_some()).count()
    }

    /// Accepts a frame and returns the frames that are now in order.
    ///
    /// A frame that is older than what has already been delivered is dropped: it
    /// duplicates audio a renderer has played, and the protocol's buffer drops those
    /// too rather than replaying them. A frame so far ahead that no amount of
    /// waiting could order it is taken as a new starting point, which is what a
    /// stream restart looks like from here.
    pub fn accept(&mut self, frame: AudioFrame) -> Vec<AudioFrame> {
        let mut ready = Vec::new();
        if !self.started {
            self.started = true;
            self.next = frame.sequence;
        }
        // Distance from the frame we are waiting for, in the sequence number's
        // own arithmetic, so the wrap from 65535 to 0 needs no special case. A
        // distance beyond half the space means the frame is from the past: a
        // client that far ahead cannot be told apart from one that restarted.
        let ahead = frame.sequence.wrapping_sub(self.next);
        if ahead > u16::MAX / 2 {
            return ready;
        }
        let mut distance = ahead as usize;
        // Give up on at most one window's worth of gaps for one frame, so a
        // client cannot make this loop run as long as it likes.
        let mut steps = 0;
        while distance >= self.capacity && steps <= self.capacity {
            self.step_over();
            distance = frame.sequence.wrapping_sub(self.next) as usize;
            steps += 1;
        }
        if distance >= self.capacity {
            // The frame is the new stream's first one, so it is delivered rather
            // than dropped: dropping it would leave the window waiting for a
            // sequence the client has already sent.
            self.restart(frame.sequence);
            distance = 0;
        }
        while self.pending.len() < distance {
            self.pending.push_back(None);
        }
        if self.pending.len() == distance {
            self.pending.push_back(Some(frame));
        } else if let Some(slot) = self.pending.get_mut(distance) {
            // A duplicate of something still waiting: the first copy stands.
            if slot.is_none() {
                *slot = Some(frame);
            }
        }
        self.drain(&mut ready);
        ready
    }

    /// Starts over from `sequence`, as a restarted stream does.
    fn restart(&mut self, sequence: u16) {
        self.pending.clear();
        self.next = sequence;
        // The caller sees a stream that starts here, not one with a hole in it:
        // the frames before the jump belong to a session that ended.
        self.lost.clear();
        self.requested.clear();
    }

    /// Gives up on the frame the window is waiting for.
    fn step_over(&mut self) {
        match self.pending.pop_front() {
            Some(Some(frame)) => {
                self.lost.push(frame.sequence);
            }
            _ => self.lost.push(self.next),
        }
        self.next = self.next.wrapping_add(1);
        // A caller that never collects the losses must not make this grow.
        if self.lost.len() > self.capacity {
            self.lost.remove(0);
        }
    }

    /// Takes every frame that is now at the front of the window.
    fn drain(&mut self, ready: &mut Vec<AudioFrame>) {
        while matches!(self.pending.front(), Some(Some(_))) {
            let Some(Some(frame)) = self.pending.pop_front() else {
                return;
            };
            ready.push(frame);
            self.next = self.next.wrapping_add(1);
        }
    }
}
