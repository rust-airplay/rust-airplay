// SPDX-License-Identifier: GPL-3.0-or-later
//! The mirror packet header: its kind, geometry, timestamp and payload size.

/// Length of the header every mirror packet starts with
/// ( reads exactly 128
/// bytes before it looks at anything else).
pub const HEADER_LEN: usize = 128;

/// Largest payload this crate reads.
///
/// A bound exists so that a client cannot make a receiver allocate without limit,
/// but it has to sit above what a real frame is. The protocol does not bound this at
/// all: it `malloc`s exactly the size the header promised
///, and the
/// `RAOP_PACKET_LEN` of 32768 declared beside it (`:170`) is the buffer for
/// reading the *header*, not a limit on the payload.
///
/// Reading it as a payload limit is what refused a device's first encrypted
/// frame: a 1080p screen that has just changed is 76298 bytes in one packet, and
/// a receiver that refuses that discards the stream at the moment a frame finally
/// arrived. Four mebibytes is above any H.264 or H.265 frame a client sends for a
/// display, and below anything a receiver would notice allocating.
pub const MAX_PAYLOAD: usize = 4 * 1024 * 1024;

/// What a mirror packet carries.
///
/// The protocol identifies the kind by `packet[4]` and `packet[5]`
/// The distinction matters because the video
/// packets are encrypted with the stream's derived keys and the rest are not:
/// decrypting a keep-alive produces nonsense, and not decrypting video produces a
/// black screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorKind {
    /// Encrypted video, whose payload holds one or more NAL units.
    Video {
        /// Whether the payload starts with an IDR frame, which a decoder needs to
        /// start.
        idr: bool,
    },
    /// Unencrypted codec configuration: a sequence parameter set and a picture
    /// parameter set, which a decoder needs before the first frame.
    CodecData,
    /// An unencrypted packet with no payload, sent once a second.
    KeepAlive,
    /// An unencrypted report about the stream, sent once a second.
    StreamingReport,
    /// A pair this crate does not know, kept as it arrived.
    Unknown {
        /// `packet[4]`.
        first: u8,
        /// `packet[5]`.
        second: u8,
    },
}

impl MirrorKind {
    /// Whether the payload is encrypted with the stream's keys.
    pub fn is_encrypted(self) -> bool {
        matches!(self, Self::Video { .. })
    }

    /// Reads the kind from the two bytes the protocol reads it from.
    fn from_header(first: u8, second: u8) -> Self {
        match (first, second) {
            (0x00, 0x00) => Self::Video { idr: false },
            (0x00, 0x10) => Self::Video { idr: true },
            (0x01, 0x00) => Self::CodecData,
            (0x02, 0x00) => Self::KeepAlive,
            (0x05, 0x00) => Self::StreamingReport,
            (first, second) => Self::Unknown { first, second },
        }
    }
}

/// The picture geometry a codec packet announces.
///
/// The codec packet is the only place a mirroring client states these, and it states them
/// as floats that are whole numbers: the source size at 16 and
/// 20, the offsets at 48 and 52, and the size the picture is drawn at at 56 and 60. A
/// receiver that does not read them hands its backend `None` for a size the client already
/// told it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Geometry {
    /// Width the client captured.
    pub width_source: u16,
    /// Height the client captured.
    pub height_source: u16,
    /// Horizontal offset of the picture in the frame.
    pub x_offset: u16,
    /// Vertical offset of the picture in the frame.
    pub y_offset: u16,
    /// Width the picture is drawn at.
    pub width: u16,
    /// Height the picture is drawn at.
    pub height: u16,
}

impl Geometry {
    /// Reads the geometry from a codec packet, or `None` when it does not hold it.
    ///
    /// A float that is not a whole number, or a zero size, is not geometry: the protocol prints
    /// the same values for a person to read and carries on, and a receiver that took a
    /// garbage size would open a pipeline it cannot use.
    #[must_use]
    pub fn from_codec_packet(datagram: &[u8]) -> Option<Self> {
        let read = |offset: usize| -> Option<u16> {
            let bytes: [u8; 4] = datagram.get(offset..offset + 4)?.try_into().ok()?;
            let value = f32::from_le_bytes(bytes);
            let rounded = value.round();
            (rounded.is_finite()
                && value == rounded
                && rounded >= 0.0
                && rounded <= f32::from(u16::MAX))
            .then_some(rounded as u16)
        };
        let geometry = Self {
            width_source: read(16)?,
            height_source: read(20)?,
            x_offset: read(48)?,
            y_offset: read(52)?,
            width: read(56)?,
            height: read(60)?,
        };
        (geometry.width > 0 && geometry.height > 0).then_some(geometry)
    }
}

/// The header of one mirror packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorHeader {
    /// Bytes the payload holds, from `packet[0..4]`.
    pub payload_size: u32,
    /// What the payload is.
    pub kind: MirrorKind,
    /// The two bytes the protocol keeps as the payload's option, from `packet[6..8]`.
    pub option: u16,
    /// The client's timestamp, from `packet[8..16]`.
    ///
    /// The protocol notes that a streaming report has none
    ///, so it is zero there and must not be read as a
    /// time.
    pub timestamp: u64,
    /// The picture geometry a codec packet announces, when it announces one.
    pub geometry: Option<Geometry>,
}

/// Why a mirror packet could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorError {
    /// Shorter than the header every packet starts with.
    TooShort {
        /// Length it has.
        length: usize,
    },
    /// The header promises more payload than the datagram carries.
    Truncated {
        /// Bytes the header promised.
        promised: usize,
        /// Bytes that are there.
        present: usize,
    },
    /// A payload size beyond what a receiver reads.
    TooLarge {
        /// Bytes the header promised.
        promised: usize,
        /// Bytes a receiver accepts.
        maximum: usize,
    },
    /// The state holds more keystream bytes than the packet has.
    Carry {
        /// Keystream bytes being carried.
        carried: usize,
        /// Bytes of payload the packet has.
        length: usize,
    },
    /// The output buffer is not as long as the payload.
    OutputLength {
        /// Bytes of payload.
        length: usize,
        /// Bytes of output.
        output: usize,
    },
}

impl std::fmt::Display for MirrorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { length } => write!(
                formatter,
                "the mirror packet is {length} bytes, shorter than its header"
            ),
            Self::Truncated { promised, present } => write!(
                formatter,
                "the header promises {promised} bytes of payload but {present} are there"
            ),
            Self::TooLarge { promised, maximum } => write!(
                formatter,
                "the header promises {promised} bytes of payload, more than the {maximum} a receiver reads"
            ),
            Self::Carry { carried, length } => write!(
                formatter,
                "{carried} keystream bytes are carried but the packet has {length}"
            ),
            Self::OutputLength { length, output } => write!(
                formatter,
                "the payload is {length} bytes but the output holds {output}"
            ),
        }
    }
}

impl std::error::Error for MirrorError {}

/// Reads one mirror packet.
///
/// # Errors
///
/// Returns [`MirrorError`] for a packet shorter than its header, one whose header
/// promises more payload than is present, or one that promises more than
/// [`MAX_PAYLOAD`].
pub fn parse_packet(datagram: &[u8]) -> Result<(MirrorHeader, &[u8]), MirrorError> {
    let header = parse_header(datagram)?;
    let promised = header.payload_size as usize;
    let present = datagram.len() - HEADER_LEN;
    if promised > present {
        return Err(MirrorError::Truncated { promised, present });
    }
    Ok((header, &datagram[HEADER_LEN..HEADER_LEN + promised]))
}

/// Reads just the header, for a caller that reads the payload separately.
///
/// A TCP reader has to do that: it reads the header first, learns how much
/// follows and then reads exactly that, because a stream does not arrive in
/// packets.
///
/// # Errors
///
/// Returns [`MirrorError::TooShort`] for fewer than [`HEADER_LEN`] bytes and
/// [`MirrorError::TooLarge`] for a payload size beyond [`MAX_PAYLOAD`].
pub fn parse_header(datagram: &[u8]) -> Result<MirrorHeader, MirrorError> {
    if datagram.len() < HEADER_LEN {
        return Err(MirrorError::TooShort {
            length: datagram.len(),
        });
    }
    let header = MirrorHeader {
        // The payload size and the timestamp are read in the host's byte order,
        // which on every machine this runs on is little endian: the protocol reads them
        // through `byteutils_get_int(packet, 0)` and `byteutils_get_long(packet, 8)`,
        // and those are a plain `*((uint32_t *)(b + offset))` rather than the `_be`
        // helpers beside them. Reading them big endian turns a
        // thirty-seven byte HEVC parameter-set packet into one that promises
        // 620756992 bytes, which is how a device's first mirror packet was refused.
        payload_size: u32::from_le_bytes(datagram[0..4].try_into().expect("four bytes")),
        kind: MirrorKind::from_header(datagram[4], datagram[5]),
        // The option is kept as the two bytes were written, because that is how
        // the protocol compares it: `packet[6] == 0x16`, `packet[6] == 0x56`
        //, not as a number.
        option: u16::from_be_bytes(datagram[6..8].try_into().expect("two bytes")),
        timestamp: u64::from_le_bytes(datagram[8..16].try_into().expect("eight bytes")),
        geometry: matches!(
            MirrorKind::from_header(datagram[4], datagram[5]),
            MirrorKind::CodecData
        )
        .then(|| Geometry::from_codec_packet(datagram))
        .flatten(),
    };
    let promised = header.payload_size as usize;
    if promised > MAX_PAYLOAD {
        return Err(MirrorError::TooLarge {
            promised,
            maximum: MAX_PAYLOAD,
        });
    }
    Ok(header)
}
