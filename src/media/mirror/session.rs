// SPDX-License-Identifier: GPL-3.0-or-later
//! Turning packets into video frames: decryption, codec data and the census.

use super::codec::{CodecConfig, StreamInfo};
use super::crypto::{MirrorDecryptor, StreamKeys};
use super::header::{Geometry, MirrorError, MirrorHeader, MirrorKind};
use super::nal::{NalError, into_annex_b};
use crate::render::VideoCodec;

/// One video frame a mirroring client sent, ready for a decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoFrame {
    /// The frame's units, each behind a `00 00 00 01` start code: the codec
    /// configuration a client sent ahead of it, then the frame's own units.
    pub data: Vec<u8>,
    /// Units the frame holds, the prepended configuration included.
    pub units: usize,
    /// The client's timestamp, which is the wall-clock time the frame belongs to
    pub timestamp: u64,
    /// Whether the frame starts with an IDR unit, which a decoder needs to start.
    pub idr: bool,
}

/// Why a mirror packet did not become a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The packet does not fit the keystream this receiver is on, which means a
    /// packet was lost or the stream was re-keyed behind its back.
    OffTheStream(MirrorError),
    /// The payload is not the sequence of units it should be.
    NotUnits(NalError),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OffTheStream(error) => write!(formatter, "the packet is off the stream: {error}"),
            Self::NotUnits(error) => write!(formatter, "the frame's units: {error}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// A mirroring client's stream: the packets it sends, turned into video frames.
///
/// The protocol does all of this in one loop over the TCP stream
/// it reads a header and a payload, decrypts the
/// video kinds with [`MirrorDecryptor`], prepends a pending codec configuration,
/// rewrites the length prefixes into start codes, and hands the result to a
/// decoder. This type is that loop without the socket, so the part that can be
/// wrong about the protocol is testable and a caller owns the connection.
#[derive(Debug)]
pub struct MirrorSession {
    decryptor: MirrorDecryptor,
    codec: CodecConfig,
    /// The picture geometry the last codec packet announced.
    geometry: Option<Geometry>,
    /// Whether the client said it stopped sending video, from the codec packet's option.
    paused: bool,
    /// Frames handed out so far, which is what a caller reports to say the stream
    /// is alive.
    frames: u64,
    /// What happened to the packets that did not become frames.
    ///
    /// A packet that carries no frame is normal — a keep-alive, a streaming report, a
    /// codec configuration — so a session that dropped them silently could not say
    /// whether a stream had stopped arriving or had changed into something this
    /// receiver does not recognise. Those are different problems and the counts are
    /// what tells them apart.
    dropped: std::sync::Arc<PacketCensus>,
}

/// How many decrypted packets a census keeps for a report.
const RECENT_PACKETS: usize = 24;

/// What a session did with the packets that were not frames.
///
/// The kinds are the header's own, so a stream that starts sending a second header
/// byte this receiver does not know shows up as `unknown` rather than as silence.
///
/// The counters are shared with whoever reports on the stream: a caller watching a
/// session for a stall needs to read them while the session is being served, and a
/// value the session owns cannot be read at the same time as the session is used.
#[derive(Debug, Default)]
pub struct PacketCensus {
    video: std::sync::atomic::AtomicU64,
    codec: std::sync::atomic::AtomicU64,
    reports: std::sync::atomic::AtomicU64,
    unknown: std::sync::atomic::AtomicU64,
    /// The first two bytes of the first unknown packet, packed as `first << 8 | second`.
    last_unknown: std::sync::atomic::AtomicU32,
    not_units: std::sync::atomic::AtomicU64,
    /// The last packets this session decrypted, oldest first.
    ///
    /// Kept because a keystream that goes out of step is only visible across packets:
    /// the one that broke it is the one before the first payload that could not be
    /// read, and by then it is gone.
    recent: std::sync::Mutex<std::collections::VecDeque<Decrypted>>,
    /// The first payload that was not units, with what it looked like.
    ///
    /// Behind a lock rather than an atomic because it is a description and not a
    /// count, and it is written once.
    first_bad: std::sync::Mutex<Option<PendingBadPacket>>,
}

/// A reading of a [`PacketCensus`], which is what a report prints.
#[derive(Debug, Default, Clone)]
pub struct PacketCounts {
    /// The first unit that could not be read, and the bytes it was read from.
    pub first_bad: Option<PendingBadPacket>,
    /// Video packets that became frames.
    pub video: u64,
    /// Codec configurations, which are kept for the frame they belong to.
    pub codec: u64,
    /// Keep-alives and streaming reports, which carry no picture.
    pub reports: u64,
    /// Packets whose header kind this receiver does not know.
    pub unknown: u64,
    /// The first two bytes of the first unknown packet, for a report.
    pub last_unknown: Option<(u8, u8)>,
    /// Payloads that were not the units they should be, which the protocol passes on
    /// marked rather than treating as fatal.
    pub not_units: u64,
}

/// What a payload that was not units looked like.
///
/// A payload that cannot be read as a sequence of units is either a decryption gone
/// wrong or a framing this receiver does not have; the two are told apart by the
/// bytes, so the first one is kept with the error that was raised on it.
#[derive(Debug, Clone)]
pub struct Decrypted {
    /// Bytes the header declared.
    pub declared: u32,
    /// Carried keystream bytes before it was decrypted.
    pub carried_before: usize,
    /// The block the counter started on.
    pub blocks_before: u64,
    /// The block the counter came to.
    pub blocks_after: u64,
    /// Carried keystream bytes after it.
    pub carried_after: usize,
    /// The first four bytes it decrypted to.
    pub first: [u8; 4],
    /// Whether the packet was an IDR, which is what the two halves of a video packet are
    /// told apart by in a report.
    ///
    /// A flag rather than the description it used to be: this is recorded for every packet
    /// of every session, and a `format!` per frame was a heap allocation in the receive
    /// loop for a word that has two values.
    pub idr: bool,
    /// Whether it became a frame.
    pub read: bool,
}

/// What a payload that was not units looked like.
#[derive(Debug, Clone)]
pub struct PendingBadPacket {
    /// What the reader objected to.
    pub error: NalError,
    /// Bytes the payload started with, in hex.
    pub preview: String,
    /// Bytes the payload held.
    pub length: usize,
    /// The header's payload size, which is what the reader was given.
    pub declared: u32,
}

impl PartialEq for PacketCounts {
    fn eq(&self, other: &Self) -> bool {
        self.video == other.video
            && self.codec == other.codec
            && self.reports == other.reports
            && self.unknown == other.unknown
            && self.last_unknown == other.last_unknown
            && self.not_units == other.not_units
    }
}

impl Eq for PacketCounts {}

impl PacketCensus {
    /// The counts as they stand.
    /// The last packets this session decrypted, oldest first.
    pub fn recent(&self) -> Vec<Decrypted> {
        self.recent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    /// Records one decrypted packet, keeping the last few.
    pub fn saw_decrypted(&self, packet: Decrypted) {
        let mut recent = self
            .recent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // The window is small on purpose: what a desync needs is the packets either
        // side of the first failure, not the history of the session.
        if recent.len() == RECENT_PACKETS {
            recent.pop_front();
        }
        recent.push_back(packet);
    }

    /// The counts as they stand.
    pub fn read(&self) -> PacketCounts {
        use std::sync::atomic::Ordering::Relaxed;
        let packed = self.last_unknown.load(Relaxed);
        PacketCounts {
            video: self.video.load(Relaxed),
            codec: self.codec.load(Relaxed),
            reports: self.reports.load(Relaxed),
            unknown: self.unknown.load(Relaxed),
            last_unknown: (packed != 0)
                .then_some((((packed >> 8) & 0xff) as u8, (packed & 0xff) as u8)),
            not_units: self.not_units.load(Relaxed),
            first_bad: self
                .first_bad
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        }
    }

    /// Counts one packet of a kind.
    fn count(&self, kind: PacketKind) {
        use std::sync::atomic::Ordering::Relaxed;
        match kind {
            PacketKind::Video => {
                self.video.fetch_add(1, Relaxed);
            }
            PacketKind::Codec => {
                self.codec.fetch_add(1, Relaxed);
            }
            PacketKind::Report => {
                self.reports.fetch_add(1, Relaxed);
            }
            PacketKind::NotUnits(described) => {
                self.not_units.fetch_add(1, Relaxed);
                // The first one is kept: a payload that cannot be read says what the
                // reader was given, and every later one is the same failure.
                let mut slot = self
                    .first_bad
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if slot.is_none() {
                    *slot = Some(*described);
                }
            }
            PacketKind::Unknown(first, second) => {
                self.unknown.fetch_add(1, Relaxed);
                // The first one is the one worth keeping: a stream that changed into
                // something unreadable says so once, and later packets are the same
                // change.
                let packed = u32::from(first) << 8 | u32::from(second);
                let _ = self
                    .last_unknown
                    .compare_exchange(0, packed | 0x1_0000, Relaxed, Relaxed);
            }
        }
    }
}

/// The kinds a census counts.
#[derive(Debug, Clone)]
enum PacketKind {
    Video,
    Codec,
    Report,
    /// A payload that was not units, with a description of what it looked like. Boxed
    /// because every other kind is two bytes and this one carries a preview.
    NotUnits(Box<PendingBadPacket>),
    Unknown(u8, u8),
}

impl MirrorSession {
    /// Starts a session on a stream's keys, which `SETUP` carried.
    ///
    /// # Errors
    ///
    /// Returns [`crate::crypto::CryptoError`] when the keys have the wrong shape.
    pub fn new(keys: &StreamKeys) -> Result<Self, crate::crypto::CryptoError> {
        Ok(Self {
            decryptor: MirrorDecryptor::new(keys)?,
            codec: CodecConfig::new(),
            geometry: None,
            paused: false,
            frames: 0,
            dropped: std::sync::Arc::new(PacketCensus::default()),
        })
    }

    /// Starts the stream over, as a re-key does: the new keys begin a new keystream
    /// and the configuration waiting from the old stream is dropped.
    ///
    /// # Errors
    ///
    /// Returns [`crate::crypto::CryptoError`] when the keys have the wrong shape.
    pub fn rekey(&mut self, keys: &StreamKeys) -> Result<(), crate::crypto::CryptoError> {
        self.codec = CodecConfig::new();
        self.geometry = None;
        self.paused = false;
        self.decryptor.rekey(keys)
    }

    /// Frames handed out so far.
    /// What this session did with the packets that were not frames.
    pub fn census(&self) -> std::sync::Arc<PacketCensus> {
        std::sync::Arc::clone(&self.dropped)
    }

    /// Whether the client said it stopped sending video.
    ///
    /// A mirroring client that stops, or an app that covers the screen, sends a codec
    /// packet whose option says so; a receiver that ignores
    /// it keeps a frozen picture on screen as if the stream were merely quiet.
    #[must_use]
    pub fn paused(&self) -> bool {
        self.paused
    }

    /// Everything the stream has said about itself.
    #[must_use]
    pub fn info(&self) -> StreamInfo {
        StreamInfo {
            codec: self.codec(),
            geometry: self.geometry,
            paused: self.paused,
        }
    }

    /// The picture geometry the stream announced, once its configuration packet arrived.
    ///
    /// `None` before it, which a caller that opens a backend stream on the first frame
    /// reads as "the client has not said".
    #[must_use]
    pub fn geometry(&self) -> Option<Geometry> {
        self.geometry
    }

    /// Frames handed out so far.
    pub fn frames(&self) -> u64 {
        self.frames
    }

    /// The coding this stream carries, as far as its configuration has said.
    ///
    /// Before the first codec packet arrives this is H.264, which is what a client sends
    /// unless the receiver asked for anything else. A caller that has to choose a decoder
    /// reads this after the configuration packet and before the first frame, which is the
    /// order a client sends them in.
    #[must_use]
    pub fn codec(&self) -> VideoCodec {
        self.codec.codec()
    }

    /// Takes one packet and returns the frame it carried, if it carried one.
    ///
    /// A packet that is not video is kept for the frame it belongs to instead of
    /// being reported: a keep-alive, a streaming report or a codec configuration
    /// is not something a decoder can be handed. `payload` is the packet's payload
    /// as [`parse_packet`](super::parse_packet) returned it.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError`] when a video payload is not the sequence of units it
    /// should be, and [`MirrorError`] when the packet does not fit the stream the
    /// decryptor is on.
    pub fn receive(
        &mut self,
        header: &MirrorHeader,
        payload: &[u8],
    ) -> Result<Option<VideoFrame>, FrameError> {
        match header.kind {
            MirrorKind::CodecData => {
                // A codec packet that cannot be read is dropped rather than treated
                // as fatal: the client sends another when the format changes.
                self.dropped.count(PacketKind::Codec);
                self.geometry = header.geometry.or(self.geometry);
                // The option's first byte says whether the stream stopped or resumed:
                // `0x56`/`0x5e` stop it, `0x16`/`0x1e` start it again
                //.
                match (header.option >> 8) as u8 {
                    0x56 | 0x5e => self.paused = true,
                    0x16 | 0x1e => self.paused = false,
                    _ => {}
                }
                let _ = self.codec.codec_data(header.timestamp, payload);
                Ok(None)
            }
            MirrorKind::Video { idr } => {
                let carried_before = self.decryptor.carried();
                let blocks_before = self.decryptor.position();
                let mut data = self.decrypt(payload)?;
                // The first bytes, zero padded: a payload shorter than four bytes is a
                // packet that went wrong, and the report still has to be able to say so.
                let mut first = [0u8; 4];
                let shown = data.len().min(4);
                first[..shown].copy_from_slice(&data[..shown]);
                // Read before the payload is rewritten: the counter has already moved
                // past this packet, and the rule is what the position is.
                let carried_after = self.decryptor.carried();
                let blocks_after = self.decryptor.position();
                // What this packet looked like, whatever becomes of it. A closure
                // cannot hold this because the session is borrowed for the whole
                // match, so the record is built here and stored where it is needed.
                let record = |read: bool| Decrypted {
                    idr,
                    declared: payload.len() as u32,
                    carried_before,
                    blocks_before,
                    blocks_after,
                    carried_after,
                    first,
                    read,
                };
                let mut units = match into_annex_b(&mut data) {
                    Ok(units) => units,
                    Err(error) => {
                        self.dropped.saw_decrypted(record(false));
                        // The protocol marks a frame whose units do not add up and passes
                        // it on rather than ending the stream (`:533-536`), so this is
                        // counted and reported instead of being fatal. // The bytes and the reader's objection are what a report needs,
                        // so they are captured where the failure is known.
                        self.dropped
                            .count(PacketKind::NotUnits(Box::new(PendingBadPacket {
                                error,
                                preview: hex_preview(&data),
                                length: data.len(),
                                declared: payload.len() as u32,
                            })));
                        return Err(FrameError::NotUnits(error));
                    }
                };
                if let Some(config) = self.codec.prepend_to(header.timestamp) {
                    // The protocol counts the two units it prepends, so a caller can
                    // report how many a frame holds.
                    units += 2;
                    let mut whole = Vec::with_capacity(config.len() + data.len());
                    whole.extend_from_slice(&config);
                    whole.extend_from_slice(&data);
                    data = whole;
                }
                self.dropped.saw_decrypted(record(true));
                self.dropped.count(PacketKind::Video);
                self.frames += 1;
                Ok(Some(VideoFrame {
                    data,
                    units,
                    timestamp: header.timestamp,
                    idr,
                }))
            }
            // Keep-alives and streaming reports carry nothing a decoder can use, and a
            // packet this crate does not recognise is the one worth being able to see:
            // a stream that changes into something unreadable looks exactly like a
            // stream that stopped, unless the two bytes are recorded.
            MirrorKind::KeepAlive | MirrorKind::StreamingReport => {
                self.dropped.count(PacketKind::Report);
                Ok(None)
            }
            MirrorKind::Unknown { first, second } => {
                self.dropped.count(PacketKind::Unknown(first, second));
                Ok(None)
            }
        }
    }

    /// Decrypts one video payload.
    fn decrypt(&mut self, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
        let mut data = vec![0u8; payload.len()];
        self.decryptor
            .decrypt(payload, &mut data)
            .map_err(FrameError::OffTheStream)?;
        Ok(data)
    }
}

/// The first bytes of a payload, in hex, for a report about one that could not be read.
fn hex_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(32)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}
