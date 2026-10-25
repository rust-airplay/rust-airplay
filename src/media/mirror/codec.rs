// SPDX-License-Identifier: GPL-3.0-or-later
//! The codec configuration a client sends before its first frame.

use super::header::Geometry;
use super::nal::START_CODE;
use crate::render::VideoCodec;

/// The codec configuration a mirroring client sends before it starts video.
///
/// The packet is unencrypted and carries an H.264 sequence parameter set and a
/// picture parameter set, which a decoder needs before the first frame. The protocol
/// does not hand it on where it arrives: it keeps the two units with start codes
/// in front of them and prepends them to the **next video packet**, which carries
/// the same timestamp (
/// and `:754-763`). This type is that rule, and a caller feeds it by calling
/// [`CodecConfig::codec_data`] for a codec packet and
/// [`CodecConfig::prepend_to`] for every video packet, in arrival order.
///
/// The payload of a codec packet is not a plain sequence of units: it starts with
/// six bytes of image size, then the two sizes and their sets
///.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CodecConfig {
    /// The units with start codes, waiting for the video packet they belong to.
    pending: Option<Pending>,
    /// The coding the stream carries, which the first configuration packet settles.
    codec: VideoCodec,
}

/// An SPS and PPS waiting for their video packet.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pending {
    /// Client timestamp of the codec packet, which the video packet has to share
    timestamp: u64,
    /// `00 00 00 01` + SPS + `00 00 00 01` + PPS.
    units: Vec<u8>,
}

/// What a mirror stream says about itself while it runs.
///
/// A codec packet carries the coding, the picture geometry and whether the client is
/// paused; all three are session state rather than frame state, and a caller that opens a
/// backend stream needs them together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamInfo {
    /// The coding the stream carries.
    pub codec: VideoCodec,
    /// The geometry the last codec packet announced, when it announced one.
    pub geometry: Option<Geometry>,
    /// Whether the client said it stopped sending video.
    pub paused: bool,
}

/// Why a codec configuration packet could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecDataError {
    /// Fewer bytes than the six-byte header the two sizes live in.
    TooShort {
        /// Length it has.
        length: usize,
    },
    /// A parameter set does not start with its marker, so this is not the layout it claims.
    NotAParameterSet {
        /// Where the marker should have been.
        offset: usize,
        /// The byte that was there instead.
        byte: u8,
    },
    /// The sizes do not leave room for both units in the payload.
    SizeOutOfRange {
        /// Size the payload claims for the sequence parameter set.
        sps: usize,
        /// Size it claims for the picture parameter set.
        pps: usize,
        /// Bytes actually there.
        length: usize,
    },
}

impl std::fmt::Display for CodecDataError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { length } => write!(
                formatter,
                "the codec packet is {length} bytes, shorter than its header"
            ),
            Self::SizeOutOfRange { sps, pps, length } => write!(
                formatter,
                "the codec packet claims {sps} + {pps} bytes of parameter sets in {length}"
            ),
            Self::NotAParameterSet { offset, byte } => write!(
                formatter,
                "the parameter set at {offset} starts with {byte:#04x}, not its marker"
            ),
        }
    }
}

impl std::error::Error for CodecDataError {}

impl CodecConfig {
    /// An empty configuration: nothing is waiting to be prepended.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads a codec packet (`packet[4] == 0x01`) and keeps what it carries.
    ///
    /// # Errors
    ///
    /// Returns [`CodecDataError`] for a payload that is not a pair of sized
    /// parameter sets, which is dropped rather than prepended to a frame: a
    /// decoder fed a wrong byte stream does not fail cleanly.
    pub fn codec_data(&mut self, timestamp: u64, payload: &[u8]) -> Result<(), CodecDataError> {
        // A mirroring client says which coding it is about to send in the four bytes after
        // the six-byte header: `avc1` for H.264 and `hvc1` for HEVC
        //. A stream sends one or the
        // other and does not change, so the first answer is the answer.
        if payload.get(4..8) == Some(b"hvc1") {
            return self.hevc_data(timestamp, payload);
        }
        // The offsets are the protocol's, and a device's own packet is what shows why they
        // are not the ones the format's description suggests. For an iPad's 1080p H.264
        // configuration:
        //
        // offset 6..8 the sequence set's size, big endian 00 12 = 18
        // offset 8..26 the sequence set itself (18 bytes)
        // offset 26 a byte between the two sets 01
        // offset 27..29 the picture set's size, big endian 00 04 = 4
        // offset 29..33 the picture set itself (4 bytes)
        //
        // So the picture set's size sits at `sps_size + 9` and the set at
        // `sps_size + 11`, one byte later than the
        // AVCDecoderConfigurationRecord layout puts them. This crate had the format's
        // offsets: it read `0x9b86` as a size and refused the packet, which means a
        // configuration a real client sent was dropped by a reader that was right
        // about a document and wrong about the wire.
        let sps_size = read_size(payload, 6).ok_or(CodecDataError::TooShort {
            length: payload.len(),
        })?;
        let sps_at = 8;
        let pps_size_at = sps_size + 9;
        let pps_at = sps_size + 11;
        let pps_size = read_size(payload, pps_size_at).ok_or(CodecDataError::SizeOutOfRange {
            sps: sps_size,
            pps: pps_size_or_zero(payload, pps_size_at),
            length: payload.len(),
        })?;
        let (Some(sps), Some(pps)) = (
            payload.get(sps_at..sps_at + sps_size),
            payload.get(pps_at..pps_at + pps_size),
        ) else {
            return Err(CodecDataError::SizeOutOfRange {
                sps: sps_size,
                pps: pps_size,
                length: payload.len(),
            });
        };
        // A later codec packet replaces an earlier one that was never used, the
        // way the protocol frees the buffer it was holding (`:622-625`).
        let mut units = Vec::with_capacity(sps.len() + pps.len() + 8);
        units.extend_from_slice(&START_CODE);
        units.extend_from_slice(sps);
        units.extend_from_slice(&START_CODE);
        units.extend_from_slice(pps);
        self.pending = Some(Pending { timestamp, units });
        Ok(())
    }

    /// Reads an HEVC configuration packet, which carries three parameter sets.
    ///
    /// The layout is the protocol's and it is
    /// nothing like a `hvcC` box: at offset 0x75 the payload holds `a0 00 01` and a
    /// sixteen-bit size, then the video parameter set; `a1 00 01` and a size, then the
    /// sequence set; `a2 00 01` and a size, then the picture set. The decoder needs all
    /// three behind start codes, in that order.
    fn hevc_data(&mut self, timestamp: u64, payload: &[u8]) -> Result<(), CodecDataError> {
        let mut units = Vec::new();
        let mut at = 0x75usize;
        for marker in [0xa0u8, 0xa1, 0xa2] {
            let header = payload.get(at..at + 5).ok_or(CodecDataError::TooShort {
                length: payload.len(),
            })?;
            if header[0] != marker || header[1] != 0x00 || header[2] != 0x01 {
                return Err(CodecDataError::NotAParameterSet {
                    offset: at,
                    byte: header[0],
                });
            }
            let size = usize::from(u16::from_be_bytes([header[3], header[4]]));
            let start = at + 5;
            let set = payload
                .get(start..start + size)
                .ok_or(CodecDataError::SizeOutOfRange {
                    sps: size,
                    pps: 0,
                    length: payload.len(),
                })?;
            units.extend_from_slice(&START_CODE);
            units.extend_from_slice(set);
            at = start + size;
        }
        self.codec = VideoCodec::H265;
        self.pending = Some(Pending { timestamp, units });
        Ok(())
    }

    /// The coding this stream carries, as far as its configuration said.
    #[must_use]
    pub fn codec(&self) -> VideoCodec {
        self.codec
    }

    /// Whether a configuration is waiting for its video packet.
    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// The configuration waiting for the video packet whose client timestamp is
    /// `timestamp`.
    ///
    /// A video packet with a different timestamp means the codec packet that is
    /// waiting belongs to a stream that is no longer arriving, so it is discarded
    /// and `None` is returned. Calling this for
    /// every video packet in arrival order is what makes the rule the protocol's:
    /// whatever is prepended is prepended exactly once.
    #[must_use]
    pub fn prepend_to(&mut self, timestamp: u64) -> Option<Vec<u8>> {
        match self.pending.take() {
            Some(pending) if pending.timestamp == timestamp => Some(pending.units),
            _ => None,
        }
    }
}

/// Reads a big-endian sixteen-bit size at `offset`, if the payload has it.
fn read_size(payload: &[u8], offset: usize) -> Option<usize> {
    let end = offset.checked_add(2)?;
    let bytes = payload.get(offset..end)?;
    Some(u16::from_be_bytes(bytes.try_into().expect("two bytes")) as usize)
}

/// The size field at `offset` for an error report, or zero when it is not there.
fn pps_size_or_zero(payload: &[u8], offset: usize) -> usize {
    read_size(payload, offset).unwrap_or_default()
}
