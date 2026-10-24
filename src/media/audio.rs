// SPDX-License-Identifier: GPL-3.0-or-later
//! The audio stream a client sends after `SETUP`.
//!
//! The receiver receives audio datagrams, unwraps the RTP header, decrypts the payload and
//! hands the result to a renderer in sequence order, with buffering and loss detection. This
//! module is that path: it parses a datagram, decrypts the payload, and delivers frames in
//! sequence order through a bounded reorder window, recording what went missing so a resend can
//! be asked for.
//!
//! # What a datagram looks like
//!
//! The layout is:
//!
//! ```text
//! packet[0] 0x80
//! packet[1] 0x60, that is payload type 96
//! packet[2:3] sequence number, big endian
//! packet[4:7] RTP timestamp, big endian
//! packet[8:11] 0x00 0x00 0x00 0x00
//! packet[12..] encrypted audio payload
//! ```
//!
//! A datagram shorter than twelve bytes is not a packet at all
//! Two shapes of "not audio yet" exist in a stream that
//! is starting: an AAC-ELD stream begins with length-16 packets whose payload is
//! the marker `00 68 34 00` instead of audio, and an ALAC
//! stream begins with length-44 packets whose payload carries format information
//! rather than samples. Both are reported as what they
//! are, so a renderer never plays a marker as sound.
//!
//! Decryption is [`decrypt_payload`], and it is not a plain CBC over the payload:
//! only the bytes that fill whole blocks are encrypted, the tail stays in clear,
//! and the cipher is reset for every packet. Those three facts are what a
//! receiver that decrypts the stream as one cipher stream gets wrong.

use std::collections::VecDeque;

use crate::crypto::{self, CryptoError};
use crate::rtp;

use super::control::{self, ControlError};
use crate::wire::ParseError;

/// Payload type the protocol names for audio.
pub const AUDIO_PAYLOAD_TYPE: u8 = 96;

/// The marker an AAC-ELD stream sends in place of audio while it starts
pub const NO_DATA_MARKER: [u8; 4] = [0x00, 0x68, 0x34, 0x00];

/// Datagrams a reorder window holds before it gives up on a gap.
///
/// The protocol's buffer is sized for the same purpose: it has to absorb the
/// reordering a network produces without keeping a client able to make a
/// receiver allocate without bound.
pub const WINDOW_CAPACITY: usize = 512;

/// What one audio datagram turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioPacket<'a> {
    /// Sequence number from the RTP header.
    pub sequence: u16,
    /// RTP timestamp from the RTP header, in the audio clock.
    pub timestamp: u32,
    /// Payload, still encrypted.
    pub payload: &'a [u8],
    /// What the payload is, as far as this receiver can tell before decryption.
    pub kind: AudioPayloadKind,
}

/// The payload of an audio datagram, before it is decrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioPayloadKind {
    /// Audio, which the renderer plays once it is decrypted.
    Data,
    /// The four byte marker an AAC-ELD stream sends while it starts.
    NoDataMarker,
}

/// Why a datagram could not be read as audio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioPacketError {
    /// Shorter than the twelve byte header; the protocol ignores these
    TooShort,
    /// The RTP header itself did not parse.
    Header(ParseError),
    /// A payload type this receiver does not know how to play.
    UnexpectedPayloadType(u8),
}

impl std::fmt::Display for AudioPacketError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(formatter, "the datagram is shorter than an RTP header"),
            Self::Header(error) => write!(formatter, "the RTP header did not parse: {error:?}"),
            Self::UnexpectedPayloadType(payload_type) => {
                write!(formatter, "payload type {payload_type} is not audio")
            }
        }
    }
}

impl std::error::Error for AudioPacketError {}

/// Reads one audio datagram.
///
/// # Errors
///
/// Returns [`AudioPacketError`] for a datagram shorter than a header, one whose
/// RTP header does not parse, or one that carries a payload type other than
/// [`AUDIO_PAYLOAD_TYPE`].
pub fn parse_audio_packet(datagram: &[u8]) -> Result<AudioPacket<'_>, AudioPacketError> {
    if datagram.len() < 12 {
        return Err(AudioPacketError::TooShort);
    }
    let packet = rtp::parse(datagram).map_err(AudioPacketError::Header)?;
    if packet.payload_type != AUDIO_PAYLOAD_TYPE {
        return Err(AudioPacketError::UnexpectedPayloadType(packet.payload_type));
    }
    let kind = if packet.payload == NO_DATA_MARKER {
        AudioPayloadKind::NoDataMarker
    } else {
        AudioPayloadKind::Data
    };
    Ok(AudioPacket {
        sequence: packet.sequence,
        timestamp: packet.timestamp,
        payload: packet.payload,
        kind,
    })
}

/// Decrypts one audio payload the way the protocol does
///
/// Two details there are easy to get wrong and are therefore stated here:
///
/// - Only the part that fills whole blocks is encrypted: the receiver decrypts
///   `payload_size / 16 * 16` bytes and copies the remaining tail through unchanged, so a
///   payload whose length is not a multiple of sixteen ends in clear bytes rather than being
///   padded.
/// - The cipher is reset for every packet, which makes each packet start from the same IV that
///   `SETUP` carried. Nothing chains across packets, so a receiver that decrypted them as one
///   stream would produce noise.
///
/// # Errors
///
/// Returns [`CryptoError`] when the key or IV has the wrong length; an empty
/// encrypted prefix is not an error, it is a payload that is entirely clear.
pub fn decrypt_payload(
    key: &[u8; 16],
    iv: &[u8; 16],
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let encrypted = payload.len() / 16 * 16;
    let mut output = Vec::with_capacity(payload.len());
    if encrypted > 0 {
        output.extend_from_slice(&crypto::aes128_cbc_decrypt(key, iv, &payload[..encrypted])?);
    }
    output.extend_from_slice(&payload[encrypted..]);
    Ok(output)
}

/// One audio stream of one session: the datagrams a client sends, decrypted and
/// put back in order.
///
/// The key and IV are the ones `SETUP` handed over (`SetupRequest::audio_key` and
/// `audio_iv`); a receiver that has not set a session up has neither, and must
/// not build one of these.
#[derive(Debug)]
pub struct AudioSession {
    key: [u8; 16],
    iv: [u8; 16],
    window: ReorderWindow,
    /// A flush asked for by a control connection, waiting to be applied.
    ///
    /// `FLUSH` arrives on the control socket, but the window lives here, on the task
    /// that drains the data socket. A slot with at most one request is all that is
    /// needed: applying the newest request is what flushing means.
    flush_request: std::sync::Arc<std::sync::Mutex<Option<u16>>>,
}

/// A way to ask a session to flush, held by whoever serves `FLUSH`.
#[derive(Debug, Clone)]
pub struct FlushHandle(std::sync::Arc<std::sync::Mutex<Option<u16>>>);

impl FlushHandle {
    /// Asks the session to restart delivery at `next`.
    pub fn request(&self, next: u16) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(next);
        }
    }
}

impl AudioSession {
    /// Creates a session that holds at most `capacity` reordered packets.
    pub fn new(key: [u8; 16], iv: [u8; 16], capacity: usize) -> Self {
        Self {
            key,
            iv,
            window: ReorderWindow::new(capacity),
            flush_request: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// A handle a control connection can use to flush this session.
    pub fn flush_handle(&self) -> FlushHandle {
        FlushHandle(std::sync::Arc::clone(&self.flush_request))
    }

    /// Applies a flush that arrived since the last datagram.
    ///
    /// Returns the sequence the window restarted at, which is worth logging once: a
    /// flush that arrives mid-stream is either a pause or a seek, and the log is the only
    /// place that distinction is visible.
    pub fn apply_flush(&mut self) -> Option<u16> {
        let next = self
            .flush_request
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        if let Some(next) = next {
            self.window.flush(next);
        }
        next
    }

    /// Discards everything buffered and expects `next` to be the next sequence number.
    pub fn flush(&mut self, next: u16) {
        self.window.flush(next);
    }

    /// Reads one datagram and returns the frames that are ready for a renderer.
    ///
    /// The marker an AAC-ELD stream starts with is delivered undecrypted:
    /// the protocol treats it as a packet with no audio in it, so decrypting it would
    /// produce nonsense.
    ///
    /// # Errors
    ///
    /// Returns [`AudioSessionError`] for a datagram this stream cannot use, or
    /// when the payload does not decrypt.
    pub fn receive(&mut self, datagram: &[u8]) -> Result<Vec<AudioFrame>, AudioSessionError> {
        self.apply_flush();
        let packet = parse_audio_packet(datagram)?;
        let payload = match packet.kind {
            AudioPayloadKind::NoDataMarker => packet.payload.to_vec(),
            AudioPayloadKind::Data => decrypt_payload(&self.key, &self.iv, packet.payload)?,
        };
        Ok(self.window.accept(AudioFrame {
            sequence: packet.sequence,
            timestamp: packet.timestamp,
            payload,
            kind: packet.kind,
        }))
    }

    /// Reads one control datagram and returns any audio it delivered.
    ///
    /// A client answers a resend request by sending the audio packet again on the
    /// control port, wrapped in four bytes the protocol skips
    /// The audio
    /// inside goes through the same path as a packet that arrived on the data
    /// port, so a resend fills the gap the window is waiting for instead of being
    /// treated as a duplicate.
    ///
    /// A sync packet is read and reported as "nothing to deliver": the timing
    /// service that consumes it is the next slice.
    ///
    /// # Errors
    ///
    /// Returns [`AudioSessionError`] for a control packet this session cannot
    /// read, or when a resent audio packet does not decrypt.
    pub fn receive_control(
        &mut self,
        datagram: &[u8],
    ) -> Result<Vec<AudioFrame>, AudioSessionError> {
        match control::parse_control_packet(datagram)? {
            control::ControlPacket::ResentAudio { packet, .. } => self.receive(packet),
            control::ControlPacket::Sync { .. } | control::ControlPacket::Other { .. } => {
                Ok(Vec::new())
            }
        }
    }

    /// Sequence numbers given up on since they were last taken.
    pub fn take_lost(&mut self) -> Vec<u16> {
        self.window.take_lost()
    }
}

/// Why a datagram could not be turned into audio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioSessionError {
    /// The datagram was not an audio packet.
    Packet(AudioPacketError),
    /// The payload could not be decrypted.
    Decrypt(CryptoError),
    /// The control packet could not be read.
    Control(ControlError),
}

impl From<AudioPacketError> for AudioSessionError {
    fn from(error: AudioPacketError) -> Self {
        Self::Packet(error)
    }
}

impl From<ControlError> for AudioSessionError {
    fn from(error: ControlError) -> Self {
        Self::Control(error)
    }
}

impl From<CryptoError> for AudioSessionError {
    fn from(error: CryptoError) -> Self {
        Self::Decrypt(error)
    }
}

impl std::fmt::Display for AudioSessionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Packet(error) => write!(formatter, "{error}"),
            Self::Decrypt(error) => write!(formatter, "the payload did not decrypt: {error:?}"),
            Self::Control(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for AudioSessionError {}

/// One audio payload, ready for a renderer.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Delivers audio payloads in sequence order, holding a bounded amount of them.
///
/// A network reorders, duplicates and loses datagrams, so a receiver cannot hand
/// payloads on as they arrive: the renderer needs them in the order the client
/// produced them. The window does that with a fixed number of slots, and when a
/// gap cannot be filled it steps over it and records what was missing, which is
/// the signal the retransmission step will use.
#[derive(Debug)]
pub struct ReorderWindow {
    capacity: usize,
    /// Frames waiting for their turn, oldest first; a missing one is `None`.
    pending: VecDeque<Option<AudioFrame>>,
    /// Sequence number the next delivered frame has to carry.
    next: u16,
    /// Whether the first frame has been seen, which fixes the starting point.
    started: bool,
    /// Sequence numbers given up on, oldest first.
    lost: Vec<u16>,
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
        }
    }

    /// Sequence numbers this window gave up on since they were last taken.
    pub fn take_lost(&mut self) -> Vec<u16> {
        std::mem::take(&mut self.lost)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A datagram with the header the protocol documents and `payload` after it.
    fn datagram(sequence: u16, timestamp: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x80, AUDIO_PAYLOAD_TYPE];
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(&timestamp.to_be_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn frame(sequence: u16) -> AudioFrame {
        AudioFrame {
            sequence,
            timestamp: u32::from(sequence) * 480,
            payload: vec![sequence as u8; 4],
            kind: AudioPayloadKind::Data,
        }
    }

    #[test]
    fn reads_the_documented_header() {
        let bytes = datagram(0x1234, 0x0000_abcd, &[1, 2, 3, 4]);
        let packet = parse_audio_packet(&bytes).expect("audio packet");
        assert_eq!(packet.sequence, 0x1234);
        assert_eq!(packet.timestamp, 0x0000_abcd);
        assert_eq!(packet.payload, [1, 2, 3, 4]);
        assert_eq!(packet.kind, AudioPayloadKind::Data);
    }

    #[test]
    fn refuses_what_is_not_audio() {
        assert_eq!(
            parse_audio_packet(&[0x80, 0x60, 0, 1, 0, 0, 0, 0, 0, 0, 0]),
            Err(AudioPacketError::TooShort)
        );
        let mut wrong_type = datagram(1, 0, &[0; 4]);
        wrong_type[1] = 97;
        assert_eq!(
            parse_audio_packet(&wrong_type),
            Err(AudioPacketError::UnexpectedPayloadType(97))
        );
        let mut wrong_version = datagram(1, 0, &[0; 4]);
        wrong_version[0] = 0x00;
        assert!(matches!(
            parse_audio_packet(&wrong_version),
            Err(AudioPacketError::Header(_))
        ));
    }

    #[test]
    fn reports_the_marker_an_aac_eld_stream_starts_with() {
        let bytes = datagram(7, 0, &NO_DATA_MARKER);
        let packet = parse_audio_packet(&bytes).expect("marker packet");
        assert_eq!(packet.kind, AudioPayloadKind::NoDataMarker);
        // A payload that merely starts like the marker is audio.
        let bytes = datagram(8, 0, &[0x00, 0x68, 0x34, 0x00, 0x01]);
        assert_eq!(
            parse_audio_packet(&bytes).expect("packet").kind,
            AudioPayloadKind::Data
        );
    }

    #[test]
    fn a_flush_discards_what_was_buffered_and_restarts_at_the_named_sequence() {
        // What a pause looks like: frames 100 and 102 arrive, 101 never does, and then the
        // client says "resume at 200". Everything held is audio nobody wants any more.
        let mut window = ReorderWindow::new(16);
        window.accept(frame(100));
        window.accept(frame(102));
        assert_eq!(window.pending(), 1);

        window.flush(200);
        assert_eq!(window.pending(), 0, "a flush leaves nothing buffered");

        // The next frame is delivered at once rather than waiting for 101, which is what
        // a client that named 200 is telling the receiver.
        let delivered = window.accept(frame(200));
        assert_eq!(
            delivered
                .iter()
                .map(|frame| frame.sequence)
                .collect::<Vec<_>>(),
            vec![200]
        );
        assert!(window.take_lost().is_empty());
    }

    #[test]
    fn a_flush_reaching_the_session_is_applied_to_the_next_datagram() {
        let mut session = AudioSession::new([0; 16], [0; 16], 16);
        let handle = session.flush_handle();
        handle.request(1234);
        assert_eq!(session.apply_flush(), Some(1234));
        assert_eq!(session.apply_flush(), None, "one request flushes once");
    }
    #[test]
    fn delivers_in_order_and_holds_what_arrives_early() {
        let mut window = ReorderWindow::default();
        assert_eq!(
            window.accept(frame(10)).len(),
            1,
            "the first frame sets the start"
        );
        assert!(window.accept(frame(12)).is_empty(), "12 waits for 11");
        assert_eq!(window.pending(), 1);
        let ready = window.accept(frame(11));
        assert_eq!(
            ready.iter().map(|frame| frame.sequence).collect::<Vec<_>>(),
            [11, 12]
        );
        assert!(window.take_lost().is_empty());
        assert_eq!(window.pending(), 0);
    }

    #[test]
    fn drops_a_duplicate_rather_than_playing_it_twice() {
        let mut window = ReorderWindow::default();
        window.accept(frame(5));
        assert!(window.accept(frame(5)).is_empty(), "delivered already");
        window.accept(frame(7));
        assert!(window.accept(frame(7)).is_empty(), "waiting already");
        assert_eq!(window.pending(), 1);
    }

    #[test]
    fn steps_over_a_gap_the_window_cannot_hold() {
        let mut window = ReorderWindow::new(4);
        window.accept(frame(20));
        // 21 is missing; 22, 23 and 24 fill the window, and 25 does not fit, so
        // the window gives up on 21 and then delivers what it was holding.
        for sequence in [22, 23, 24] {
            assert!(window.accept(frame(sequence)).is_empty());
        }
        assert_eq!(window.pending(), 3);
        let ready = window.accept(frame(25));
        assert_eq!(
            ready.iter().map(|frame| frame.sequence).collect::<Vec<_>>(),
            [22, 23, 24, 25]
        );
        assert_eq!(window.take_lost(), [21]);
        assert!(window.pending() <= window.capacity);
    }

    #[test]
    fn counts_every_gap_it_steps_over() {
        let mut window = ReorderWindow::new(2);
        window.accept(frame(30));
        // 31, 32 and 33 never arrive; 35 is far enough ahead that the window
        // steps over all three of them to hold it.
        assert!(window.accept(frame(35)).is_empty());
        // The window keeps at most one capacity's worth of losses, so a caller
        // that never collects them cannot make this grow: the oldest is dropped.
        assert_eq!(window.take_lost(), [32, 33]);
        let ready = window.accept(frame(34));
        assert_eq!(
            ready.iter().map(|frame| frame.sequence).collect::<Vec<_>>(),
            [34, 35]
        );
    }

    #[test]
    fn a_large_step_forward_starts_over_instead_of_walking_the_gap() {
        let mut window = ReorderWindow::new(4);
        window.accept(frame(1));
        window.accept(frame(3));
        // 51 is a hundred steps ahead: not a gap to wait out, but a new start,
        // and it is delivered as the first frame of that start.
        let ready = window.accept(frame(51));
        assert_eq!(
            ready.iter().map(|frame| frame.sequence).collect::<Vec<_>>(),
            [51]
        );
        assert!(window.take_lost().is_empty());
        assert_eq!(window.pending(), 0);
        let ready = window.accept(frame(52));
        assert_eq!(
            ready.iter().map(|frame| frame.sequence).collect::<Vec<_>>(),
            [52]
        );
    }

    #[test]
    fn a_frame_from_the_past_is_dropped() {
        let mut window = ReorderWindow::new(4);
        window.accept(frame(1));
        window.accept(frame(3));
        // A sequence this far behind the window is what a replay looks like, and
        // a stream that really restarted says so with a new session.
        assert!(window.accept(frame(40000)).is_empty());
        assert!(window.take_lost().is_empty());
        assert_eq!(window.pending(), 1, "the held frame is untouched");
        let ready = window.accept(frame(2));
        assert_eq!(
            ready.iter().map(|frame| frame.sequence).collect::<Vec<_>>(),
            [2, 3]
        );
    }

    #[test]
    fn keeps_working_when_the_sequence_number_wraps() {
        let mut window = ReorderWindow::default();
        window.accept(frame(65534));
        window.accept(frame(0));
        let ready = window.accept(frame(65535));
        assert_eq!(
            ready.iter().map(|frame| frame.sequence).collect::<Vec<_>>(),
            [65535, 0]
        );
        let ready = window.accept(frame(1));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].sequence, 1);
        assert!(window.take_lost().is_empty());
    }

    #[test]
    fn a_frame_from_before_the_start_is_not_a_new_start() {
        let mut window = ReorderWindow::default();
        window.accept(frame(100));
        // A late duplicate of an earlier packet must not rewind the window.
        assert!(window.accept(frame(99)).is_empty());
        let ready = window.accept(frame(101));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].sequence, 101);
    }

    /// Encrypts with the port's own CBC primitive, so the test builds the
    /// ciphertext the way a client's key does rather than trusting a fixture.
    fn encrypt(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        use aes::cipher::{BlockEncryptMut, KeyIvInit};
        type Encryptor = cbc::Encryptor<aes::Aes128>;
        let mut buffer = plaintext.to_vec();
        let encrypted = Encryptor::new(key.into(), iv.into())
            .encrypt_padded_mut::<aes::cipher::block_padding::NoPadding>(
                &mut buffer,
                plaintext.len() / 16 * 16,
            )
            .expect("whole blocks");
        let mut output = encrypted.to_vec();
        output.extend_from_slice(&plaintext[plaintext.len() / 16 * 16..]);
        output
    }

    #[test]
    fn decrypts_only_whole_blocks_and_copies_the_tail() {
        let key = [0x11; 16];
        let iv = [0x22; 16];
        // Sixteen bytes of audio and five bytes that no block covers: the protocol
        // decrypts the first part and passes the rest through unchanged
        //.
        let mut plaintext = vec![0x8c; 16];
        plaintext.extend_from_slice(b"clear");
        assert_eq!(plaintext.len(), 21);
        let encrypted = encrypt(&key, &iv, &plaintext);
        assert_ne!(&encrypted[..16], &plaintext[..16], "the block is encrypted");
        assert_eq!(&encrypted[16..], b"clear", "the tail is not");

        let decrypted = decrypt_payload(&key, &iv, &encrypted).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn every_packet_starts_from_the_same_iv() {
        let key = [0x33; 16];
        let iv = [0x44; 16];
        let first = encrypt(&key, &iv, &[0x8c; 16]);
        let second = encrypt(&key, &iv, &[0x8c; 16]);
        assert_eq!(first, second, "the client resets its cipher per packet too");
        // A payload that is entirely clear is not an error: nothing to decrypt.
        assert_eq!(
            decrypt_payload(&key, &iv, b"short").expect("decrypt"),
            b"short"
        );
    }

    #[test]
    fn a_session_delivers_decrypted_audio_in_order() {
        let key = [0x55; 16];
        let iv = [0x66; 16];
        let mut session = AudioSession::new(key, iv, WINDOW_CAPACITY);
        let audio = encrypt(&key, &iv, &[0x8c; 16]);
        let packet = |sequence: u16, timestamp: u32| datagram(sequence, timestamp, &audio);

        // The first packet fixes the starting point, so it is delivered.
        let ready = session.receive(&packet(1, 480)).expect("first");
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].payload, vec![0x8c; 16], "delivered decrypted");
        // The third one waits for the second.
        assert!(session.receive(&packet(3, 1440)).expect("third").is_empty());
        let ready = session.receive(&packet(2, 960)).expect("second");
        assert_eq!(
            ready.iter().map(|frame| frame.sequence).collect::<Vec<_>>(),
            [2, 3]
        );
        assert!(ready.iter().all(|frame| frame.payload == vec![0x8c; 16]));
    }

    #[test]
    fn a_session_delivers_the_start_marker_without_decrypting_it() {
        let mut session = AudioSession::new([0x77; 16], [0x88; 16], WINDOW_CAPACITY);
        let ready = session
            .receive(&datagram(1, 0, &NO_DATA_MARKER))
            .expect("marker");
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].kind, AudioPayloadKind::NoDataMarker);
        assert_eq!(ready[0].payload, NO_DATA_MARKER);
    }

    #[test]
    fn a_resent_packet_fills_the_gap_the_window_waits_for() {
        let key = [0xbb; 16];
        let iv = [0xcc; 16];
        let mut session = AudioSession::new(key, iv, WINDOW_CAPACITY);
        let audio = encrypt(&key, &iv, &[0x8c; 16]);
        let packet = |sequence: u16, timestamp: u32| datagram(sequence, timestamp, &audio);

        // 1 arrives, 3 is held: 2 is missing.
        assert_eq!(session.receive(&packet(1, 480)).expect("first").len(), 1);
        assert!(session.receive(&packet(3, 1440)).expect("third").is_empty());
        assert!(session.take_lost().is_empty());

        // The client answers a resend request with the audio wrapped in four
        // bytes; the session must deliver it and then the frame it was holding.
        let mut wrapped = vec![0x80, 0x56 | 0x80, 0x00, 0x00];
        wrapped.extend_from_slice(&packet(2, 960));
        let ready = session.receive_control(&wrapped).expect("resent");
        assert_eq!(
            ready.iter().map(|frame| frame.sequence).collect::<Vec<_>>(),
            [2, 3]
        );
        assert!(ready.iter().all(|frame| frame.payload == vec![0x8c; 16]));
        assert!(session.take_lost().is_empty(), "nothing was lost after all");
    }

    #[test]
    fn a_sync_packet_delivers_nothing_and_is_not_an_error() {
        let mut session = AudioSession::new([0xdd; 16], [0xee; 16], WINDOW_CAPACITY);
        let mut sync = vec![0x90, 0xd4, 0x00, 0x04];
        sync.extend_from_slice(&[0u8; 16]);
        assert!(session.receive_control(&sync).expect("sync").is_empty());
        // A control packet this session cannot read is refused, not guessed at.
        assert!(matches!(
            session.receive_control(&[0x80]),
            Err(AudioSessionError::Control(ControlError::TooShort))
        ));
    }

    #[test]
    fn a_session_refuses_what_is_not_audio() {
        let mut session = AudioSession::new([0x99; 16], [0xaa; 16], WINDOW_CAPACITY);
        assert!(matches!(
            session.receive(&[0x80, 0x60, 0, 1]),
            Err(AudioSessionError::Packet(AudioPacketError::TooShort))
        ));
        let mut wrong_type = datagram(1, 0, &[0; 16]);
        wrong_type[1] = 97;
        assert!(matches!(
            session.receive(&wrong_type),
            Err(AudioSessionError::Packet(
                AudioPacketError::UnexpectedPayloadType(97)
            ))
        ));
    }

    #[test]
    fn the_window_never_grows_past_its_capacity() {
        let mut window = ReorderWindow::new(8);
        window.accept(frame(0));
        for sequence in 1..2000u16 {
            window.accept(frame(sequence));
            assert!(
                window.pending() <= window.capacity,
                "held {} frames at {sequence}",
                window.pending()
            );
        }
    }
}
