// SPDX-License-Identifier: GPL-3.0-or-later
//! The mirror stream: its keys, and the packets that carry video.
//!
//! A mirroring client sets up a stream of its own with `SETUP`, and the two
//! things that make it different from audio are that it travels over TCP and that
//! its keystream is derived rather than carried. The derivation is written out in
//! upstream (`upstream/UxPlay@3dbf7cee:lib/mirror_buffer.c`, `mirror_buffer_init_aes`):
//!
//! ```text
//! key = SHA-512("AirPlayStreamKey" + decimal(streamConnectionID) + audio key)
//! iv  = SHA-512("AirPlayStreamIV"  + decimal(streamConnectionID) + audio key)
//! ```
//!
//! both truncated to sixteen bytes, with the audio key being the one the
//! session's `SETUP` carried. `streamConnectionID` is what the client sent in the
//! `type: 110` stream entry, which this crate already keeps
//! (`server::SetupStream::stream_connection_id`).
//!
//! The same file records a consequence that is easy to miss: a re-key means a new
//! stream, so the AES-CTR keystream restarts at offset zero. Nothing here holds
//! state across streams, so that is a property of how a caller uses
//! [`StreamKeys`] rather than of the type.
//!
//! # How the payload is encrypted
//!
//! The video payload is AES-128-CTR, but not as one continuous stream: upstream
//! calls `aes_ctr_start_fresh_block` at the start of every packet
//! (`upstream/UxPlay@3dbf7cee:lib/mirror_buffer.c:104`), and OpenSSL's CTR context
//! keeps a *block offset* rather than a byte position. Decrypting a length that is
//! not a multiple of sixteen therefore leaves the context part-way into a block,
//! and "start a fresh block" throws the rest of that block's keystream away. What
//! upstream does with it instead is to decrypt the packet's tail as **one whole
//! block** and keep the bytes the packet did not use
//! (`mirror_buffer.c:111-123`), so the next packet's first bytes are XORed with
//! them ([`MirrorDecryptor`] is that state).
//!
//! Upstream also sends the codec configuration (an H.264 SPS and PPS) in a packet
//! of its own, *unencrypted*, and prepends it to the next video packet because a
//! decoder needs it before the first frame
//! (`raop_rtp_mirror.c:420-450`, [`CodecConfig`]).

use crate::crypto::sha512_concat;

/// Length of the key and IV a mirror stream uses
/// (`RAOP_AESKEY_LEN` in upstream).
pub const STREAM_KEY_LEN: usize = 16;

/// Prefix of the material a mirror stream's key is hashed from.
const KEY_PREFIX: &str = "AirPlayStreamKey";

/// Prefix of the material a mirror stream's IV is hashed from.
const IV_PREFIX: &str = "AirPlayStreamIV";

/// Length of the header every mirror packet starts with
/// (`upstream/UxPlay@3dbf7cee:lib/raop_rtp_mirror.c:298-302` reads exactly 128
/// bytes before it looks at anything else).
pub const HEADER_LEN: usize = 128;

/// Largest payload this crate reads.
///
/// A bound exists so that a client cannot make a receiver allocate without limit,
/// but it has to sit above what a real frame is. Upstream does not bound this at
/// all: it `malloc`s exactly the size the header promised
/// (`upstream/UxPlay@3dbf7cee:lib/raop_rtp_mirror.c:365-368`), and the
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
/// Upstream identifies the kind by `packet[4]` and `packet[5]`
/// (`raop_rtp_mirror.c:339-344`). The distinction matters because the video
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

    /// Reads the kind from the two bytes upstream reads it from.
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

/// The header of one mirror packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorHeader {
    /// Bytes the payload holds, from `packet[0..4]`.
    pub payload_size: u32,
    /// What the payload is.
    pub kind: MirrorKind,
    /// The two bytes upstream keeps as the payload's option, from `packet[6..8]`.
    pub option: u16,
    /// The client's timestamp, from `packet[8..16]`.
    ///
    /// Upstream notes that a streaming report has none
    /// (`raop_rtp_mirror.c:363`), so it is zero there and must not be read as a
    /// time.
    pub timestamp: u64,
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
/// packets (`raop_rtp_mirror.c:298-302` loops the same way).
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
        // which on every machine this runs on is little endian: upstream reads them
        // through `byteutils_get_int(packet, 0)` and `byteutils_get_long(packet, 8)`,
        // and those are a plain `*((uint32_t *)(b + offset))` rather than the `_be`
        // helpers beside them (`byteutils.c`). Reading them big endian turns a
        // thirty-seven byte HEVC parameter-set packet into one that promises
        // 620756992 bytes, which is how a device's first mirror packet was refused.
        payload_size: u32::from_le_bytes(datagram[0..4].try_into().expect("four bytes")),
        kind: MirrorKind::from_header(datagram[4], datagram[5]),
        // The option is kept as the two bytes were written, because that is how
        // upstream compares it: `packet[6] == 0x16`, `packet[6] == 0x56`
        // (`raop_rtp_mirror.c:580-586`), not as a number.
        option: u16::from_be_bytes(datagram[6..8].try_into().expect("two bytes")),
        timestamp: u64::from_le_bytes(datagram[8..16].try_into().expect("eight bytes")),
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

/// The key and IV of one mirror stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamKeys {
    /// AES-128-CTR key of the stream.
    pub key: [u8; STREAM_KEY_LEN],
    /// AES-128-CTR initial counter block of the stream.
    pub iv: [u8; STREAM_KEY_LEN],
}

/// Derives the keys of the mirror stream a client identified with
/// `connection_id`, using the audio key of the session it belongs to.
///
/// The decimal form of the identifier matters: upstream formats it with `%llu`,
/// so the hash covers text, not bytes. A port that hashed the number's bytes
/// would produce a stream the client cannot read, with no error anywhere.
pub fn stream_keys(connection_id: u64, audio_key: &[u8; STREAM_KEY_LEN]) -> StreamKeys {
    let key_material = format!("{KEY_PREFIX}{connection_id}");
    let iv_material = format!("{IV_PREFIX}{connection_id}");
    let key = sha512_concat(&[key_material.as_bytes(), audio_key]);
    let iv = sha512_concat(&[iv_material.as_bytes(), audio_key]);
    StreamKeys {
        key: key[..STREAM_KEY_LEN]
            .try_into()
            .expect("sixteen of sixty-four"),
        iv: iv[..STREAM_KEY_LEN]
            .try_into()
            .expect("sixteen of sixty-four"),
    }
}

/// The Annex-B start code that replaces a length prefix
/// (`upstream/UxPlay@3dbf7cee:lib/raop_rtp_mirror.c:453-454`, `nal_start_code`).
pub const START_CODE: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// Why a decrypted payload is not a sequence of NAL units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NalError {
    /// A length prefix claims bytes the payload does not have.
    LengthOutOfRange {
        /// Offset the prefix was read at.
        offset: usize,
        /// Length it claimed.
        claimed: usize,
        /// Bytes actually left after the prefix.
        available: usize,
    },
    /// The first byte of a unit has the bit set that has to be zero.
    ForbiddenBit {
        /// Offset of the unit's first byte.
        offset: usize,
    },
}

impl std::fmt::Display for NalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LengthOutOfRange {
                offset,
                claimed,
                available,
            } => write!(
                formatter,
                "the unit at {offset} claims {claimed} bytes but {available} are left"
            ),
            Self::ForbiddenBit { offset } => {
                write!(formatter, "the unit at {offset} has its forbidden bit set")
            }
        }
    }
}

impl std::error::Error for NalError {}

/// Rewrites the length prefixes of a decrypted mirror payload into Annex-B start
/// codes, in place, and reports how many units it holds.
///
/// The AirPlay mirror protocol prefixes every NAL unit with its length, which a
/// decoder does not expect; upstream replaces each prefix with `00 00 00 01`
/// while it checks the unit
/// (`upstream/UxPlay@3dbf7cee:lib/raop_rtp_mirror.c:453-474`). Doing the same
/// here means a caller hands the payload to a decoder unchanged after this.
///
/// The checks are upstream's, and they matter: a length read out of the payload
/// is only a length if the unit it claims fits in what is left, and a unit whose
/// first byte has the forbidden bit set is not a unit at all. A payload that
/// fails either check is reported instead of being passed on, because a decoder
/// fed a wrong byte stream does not fail cleanly.
///
/// # Errors
///
/// Returns [`NalError`] for a payload that is not a sequence of units.
pub fn into_annex_b(payload: &mut [u8]) -> Result<usize, NalError> {
    let mut offset = 0;
    let mut units = 0;
    while offset < payload.len() {
        if offset + 4 > payload.len() {
            return Err(NalError::LengthOutOfRange {
                offset,
                claimed: 0,
                available: payload.len() - offset,
            });
        }
        let claimed =
            u32::from_be_bytes(payload[offset..offset + 4].try_into().expect("four")) as usize;
        let available = payload.len() - offset - 4;
        if claimed > available {
            return Err(NalError::LengthOutOfRange {
                offset,
                claimed,
                available,
            });
        }
        payload[offset..offset + 4].copy_from_slice(&START_CODE);
        offset += 4;
        units += 1;
        // The first bit of an H.264 unit has to be zero. Upstream reads the byte
        // even for a unit of length zero, so this does too.
        let first = payload.get(offset).copied().unwrap_or_default();
        if first & 0x80 != 0 {
            return Err(NalError::ForbiddenBit { offset });
        }
        offset += claimed;
    }
    Ok(units)
}
/// The keystream of one mirror stream.
///
/// This is upstream's `mirror_buffer` state: the key and IV, where in the stream the
/// counter has come to, and the bytes of a partly used keystream block that the
/// previous packet left behind. The rule it follows is written out in
/// `mirror_buffer_decrypt` (`upstream/UxPlay@3dbf7cee:lib/mirror_buffer.c:94-124`) and
/// is not what a plain CTR stream would do, so it is repeated here in the order the C
/// code performs it:
///
/// 1. the first `carry` bytes of the packet are XORed with the **end** of the previous
///    packet's tail block, which that packet did not use
///    (`output[i] = input[i] ^ og[16 - carry + i]`);
/// 2. the counter is moved to a block boundary (`aes_ctr_start_fresh_block`, which is
///    the block after the tail block), and the whole blocks after the carry —
///    `((len - carry) / 16) * 16` bytes — are decrypted from there;
/// 3. the remaining `rest = (len - carry) % 16` bytes are decrypted as one whole block
///    (zero padded), of which the packet keeps the first `rest`; the other
///    `16 - rest` keystream bytes are the carry for the next packet.
///
/// So a packet's first bytes are keystream the previous packet left behind, and its
/// body is the stream's own blocks from the counter, which is what makes this
/// different from one continuous keystream: two packets of the same length read the
/// same blocks. The counter advances by the blocks a packet used, its tail's
/// included, because the next packet starts one block past the carry's block.
///
/// The rule is pinned against upstream's own code in `tests/upstream_oracle.rs`,
/// which reads where upstream's decryptor takes its keystream bytes from, packet by
/// packet.
#[derive(Clone)]
pub struct MirrorDecryptor {
    /// The key schedule, built once.
    ///
    /// `Aes128::new` expands the key, and that costs more than encrypting the block that
    /// follows it. Rebuilding it for every packet was paying that price a few dozen times
    /// a second for nothing: a stream's key does not change until it is re-keyed.
    cipher: aes::Aes128,
    /// The initial counter block, which is what a block's counter is derived from.
    ///
    /// A mirror packet's keystream is a function of its position in the stream, so nothing
    /// about the previous packet other than the bytes it carried is kept.
    iv: [u8; STREAM_KEY_LEN],
    /// The block of the stream the next packet's own bytes start on.
    ///
    /// A block number and not a byte offset, because that is what the rule is about: a
    /// packet reads whole blocks, so this moves by the packet's length rounded up to a
    /// block. Its bytes past the first `carried` ones are read from this block's first
    /// byte — the counter restarted at a boundary, it did not carry on from where the
    /// previous packet's bytes stopped.
    read_block: u64,
    /// Where in the stream this receiver has come, in bytes of packet data.
    ///
    /// Kept apart from `read_at` because the two are not the same quantity: a packet of
    /// 1265 bytes leaves this at 1265 and `read_at` at 1280. Both were needed to make a
    /// real session's packets decrypt, and measuring them is what took so long — every
    /// earlier version of this crate used one number where there are two.
    position: u64,
    /// The keystream of the block a packet's tail sat in, of which the packet used the
    /// front: what is behind that is the next packet's first bytes.
    ///
    /// This has to be kept rather than generated again, because it is not anywhere in the
    /// stream: it is the rest of a block that has already been read past. A locator looking
    /// for those bytes in the stream finds nothing, which is exactly how this was found.
    carry: [u8; 16],
    /// How far into that block the bytes it left begin.
    ///
    /// The bytes are read from here rather than from the front of the buffer, because the
    /// packet that left them used the front of the block itself.
    carry_at: usize,
    /// How many of those bytes the next packet starts with, upstream's
    /// `nextDecryptCount`.
    carried: usize,
}

impl std::fmt::Debug for MirrorDecryptor {
    /// Reports the position in the stream and nothing derived from the keys, so a
    /// session log can record where decryption is without recording secrets.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MirrorDecryptor")
            .field("position", &self.position)
            .field("carried", &self.carried)
            .finish_non_exhaustive()
    }
}

impl MirrorDecryptor {
    /// Starts a stream at its first packet.
    ///
    /// # Errors
    ///
    /// Returns [`crate::crypto::CryptoError`] when the keys have the wrong shape.
    pub fn new(keys: &StreamKeys) -> Result<Self, crate::crypto::CryptoError> {
        // The shape check is what `Aes128CtrState` does for the rest of this crate;
        // the arrays here are already sixteen bytes, so it cannot fail.
        let _ = crate::crypto::Aes128CtrState::new(&keys.key, &keys.iv)?;
        Ok(Self {
            cipher: {
                use aes::cipher::KeyInit;
                aes::Aes128::new(keys.key[..].into())
            },
            iv: keys.iv,
            position: 0,
            read_block: 0,
            carry: [0; 16],
            carry_at: 0,
            carried: 0,
        })
    }

    /// Starts a new stream, as a re-key does.
    ///
    /// Upstream clears its carry buffer here (`mirror_buffer_init_aes`,
    /// `mirror_buffer.c:66-70`): a re-key means a new stream, and bytes held back
    /// from the previous one are the wrong keystream for the first packet of this
    /// one.
    ///
    /// # Errors
    ///
    /// Returns [`crate::crypto::CryptoError`] when the keys have the wrong shape.
    pub fn rekey(&mut self, keys: &StreamKeys) -> Result<(), crate::crypto::CryptoError> {
        *self = Self::new(keys)?;
        Ok(())
    }

    /// How many keystream bytes the previous packet left for the next one,
    /// upstream's `nextDecryptCount`.
    pub fn carried(&self) -> usize {
        self.carried
    }

    /// Where in the stream the next packet's first byte belongs, in bytes of packet data.
    ///
    /// This is the position the stream has come to and not the block the cipher is on: the
    /// two differ by the part of a block a packet's tail did not fill, and both are needed
    /// — see [`Self::read_block`].
    pub fn position(&self) -> u64 {
        self.position
    }

    /// The block of the stream the next packet's bytes are read from.
    ///
    /// A block boundary, because the counter restarts on one at every packet: a packet's
    /// bytes past the first `carried` ones come from the start of this block and not from
    /// where the previous packet's bytes stopped.
    pub fn read_block(&self) -> u64 {
        self.read_block
    }

    /// The keystream of `blocks` blocks starting at block `first` of the stream.
    ///
    /// Upstream reaches this through OpenSSL's CTR context, whose counter block is
    /// incremented per block. Generating the blocks here keeps the position
    /// explicit: which block a packet starts on is the whole of the rule
    /// (`mirror_buffer.c:94-124`), and it must not depend on any state a cipher
    /// implementation keeps for itself.
    ///
    /// It is public because it is also the clearest way to check this crate against
    /// upstream's own context, block for block, in the differential test.
    #[must_use]
    pub fn keystream(&self, first: u64, blocks: usize) -> Vec<u8> {
        use aes::cipher::BlockEncrypt;
        let cipher = &self.cipher;
        let mut out = Vec::with_capacity(blocks * 16);
        for index in 0..blocks as u64 {
            let mut counter = self.iv;
            // The counter is the IV plus the block index, big-endian, the way OpenSSL's CTR
            // mode counts, and the carry is propagated through the whole 128-bit counter.
            //
            // Stopping at the first byte that does not overflow drops the carry that is
            // still pending. With an IV ending in `4f`, block 177 adds `b1`: the last byte
            // becomes `00` and one must carry into the byte before it. Dropping that leaves
            // the counter a byte short and the stream 256 blocks out, which only shows up
            // from block 177 onwards — a 62 kB packet is 3875 blocks and shows it at once,
            // while every shorter test vector passes.
            let mut carry = first + index;
            for byte in counter.iter_mut().rev() {
                if carry == 0 {
                    break;
                }
                let (next, overflow) = byte.overflowing_add((carry & 0xff) as u8);
                *byte = next;
                carry = (carry >> 8) + u64::from(overflow);
            }
            let mut block = aes::Block::clone_from_slice(&counter);
            cipher.encrypt_block(&mut block);
            out.extend_from_slice(&block);
        }
        out
    }

    /// Decrypts one payload into `output`, which has to be as long as `input`.
    ///
    /// # Errors
    ///
    /// Returns [`MirrorError::Carry`] when the state holds more keystream bytes
    /// than the packet has, which no packet sequence from a client produces: it
    /// means the caller skipped or mis-split a packet, and continuing would
    /// decrypt the rest of the stream at the wrong offset. Returns
    /// [`MirrorError::OutputLength`] for an output buffer of a different length.
    pub fn decrypt(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), MirrorError> {
        if output.len() != input.len() {
            return Err(MirrorError::OutputLength {
                length: input.len(),
                output: output.len(),
            });
        }
        let length = input.len();

        // A packet shorter than the bytes being carried takes what it needs of them and
        // loses the rest: upstream's carry buffer is one block that the next packet
        // overwrites whole (`mirror_buffer.c:115-117`), so nothing of a carry outlives the
        // packet after it, whatever the two lengths are. A client does not send that, and
        // the oracle's own readers show what it does when one arrives, so this reproduces
        // it rather than refusing — the lengths are what a receiver has to survive.

        // A packet is read in two parts, and the line between them is what every earlier
        // version of this crate got wrong.
        //
        // The cipher reads whole blocks. A packet whose length is not a multiple of the
        // block fills part of its last block, and the counter comes out of that block at
        // its end (`mirror_buffer.c:115-117`) — so the bytes the packet did not use are
        // still in the cipher, and are not anywhere in the stream to be read again: they
        // are the rest of a block that has already been read past. The next packet starts
        // with them, because `aes_ctr_start_fresh_block` cannot skip them — the counter is
        // already past them — and the loop at `:96-98` takes them from the block the
        // previous packet left.
        //
        // The rest of the packet is read from the block the cipher moved on to, starting at
        // that block's first byte: the counter restarted at a block boundary, it did not
        // continue from where the previous packet's bytes stopped.
        // The carried bytes the packet actually takes: all of them when it is long enough,
        // and only as many as it has when it is not. Either way the carry does not survive
        // this packet — upstream's buffer holds one block and the next packet fills it.
        let carried = self.carried.min(length);
        for (at, byte) in input.iter().take(carried).enumerate() {
            output[at] = byte ^ self.carry[self.carry_at + at];
        }
        if carried < length {
            let rest = length - carried;
            let used = rest % 16;
            // The whole blocks the packet fills, and — only when its last byte does not sit
            // on a block boundary — the block that byte is in, whose other half is what the
            // next packet starts with. A packet that ends on a boundary needs nothing more,
            // and asking for a block it does not use moves the counter one block too far,
            // which every packet after it then reads from.
            let tail = usize::from(used > 0);
            let fresh = self.keystream(self.read_block, rest / 16 + tail);
            for (at, byte) in input[carried..].iter().enumerate() {
                output[carried + at] = byte ^ fresh[at];
            }
            if used == 0 {
                // It ended on a block boundary, so it left nothing behind.
                self.carry_at = 0;
                self.carried = 0;
            } else {
                // What it leaves for the next one: the bytes of its last block behind the
                // ones it used.
                let start = rest / 16 * 16;
                self.carry.copy_from_slice(&fresh[start..start + 16]);
                self.carry_at = used;
                self.carried = 16 - used;
            }
        } else {
            self.carry_at = 0;
            self.carried = 0;
        }
        self.position += length as u64;
        // The blocks this packet consumed: the carry's bytes were the previous packet's,
        // so what is counted is the part it read fresh — a packet of 24 bytes after eight
        // carried ones moves the counter one block, not two.
        self.read_block += (length - carried).div_ceil(16) as u64;
        Ok(())
    }
}

/// The codec configuration a mirroring client sends before it starts video.
///
/// The packet is unencrypted and carries an H.264 sequence parameter set and a
/// picture parameter set, which a decoder needs before the first frame. Upstream
/// does not hand it on where it arrives: it keeps the two units with start codes
/// in front of them and prepends them to the **next video packet**, which carries
/// the same timestamp (`upstream/UxPlay@3dbf7cee:lib/raop_rtp_mirror.c:420-450`
/// and `:754-763`). This type is that rule, and a caller feeds it by calling
/// [`CodecConfig::codec_data`] for a codec packet and
/// [`CodecConfig::prepend_to`] for every video packet, in arrival order.
///
/// The payload of a codec packet is not a plain sequence of units: it starts with
/// six bytes of image size, then the two sizes and their sets
/// (`raop_rtp_mirror.c:560-572` describes the header, `:725-728` reads the sets).
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
    /// (`raop_rtp_mirror.c:426`).
    timestamp: u64,
    /// `00 00 00 01` + SPS + `00 00 00 01` + PPS.
    units: Vec<u8>,
}

/// The coding a mirror stream carries, re-exported so a protocol user need not also
/// reach into the renderer's types.
pub use crate::render::VideoCodec;

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
        // (`upstream/UxPlay/lib/raop_rtp_mirror.c:627-633`). A stream sends one or the
        // other and does not change, so the first answer is the answer.
        if payload.get(4..8) == Some(b"hvc1") {
            return self.hevc_data(timestamp, payload);
        }
        // The offsets are upstream's, and a device's own packet is what shows why they
        // are not the ones the format's description suggests. For an iPad's 1080p H.264
        // configuration:
        //
        //   offset 6..8    the sequence set's size, big endian      00 12 = 18
        //   offset 8..26   the sequence set itself                  (18 bytes)
        //   offset 26      a byte between the two sets              01
        //   offset 27..29  the picture set's size, big endian       00 04 = 4
        //   offset 29..33  the picture set itself                   (4 bytes)
        //
        // So the picture set's size sits at `sps_size + 9` and the set at
        // `sps_size + 11` (`raop_rtp_mirror.c:725-728`), one byte later than the
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
        // way upstream frees the buffer it was holding (`:622-625`).
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
    /// The layout is upstream's (`upstream/UxPlay/lib/raop_rtp_mirror.c:643-693`) and it is
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
    /// and `None` is returned (`raop_rtp_mirror.c:426-433`). Calling this for
    /// every video packet in arrival order is what makes the rule upstream's:
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

/// One video frame a mirroring client sent, ready for a decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoFrame {
    /// The frame's units, each behind a `00 00 00 01` start code: the codec
    /// configuration a client sent ahead of it, then the frame's own units.
    pub data: Vec<u8>,
    /// Units the frame holds, the prepended configuration included.
    pub units: usize,
    /// The client's timestamp, which is the wall-clock time the frame belongs to
    /// (`raop_rtp_mirror.c:393-395`).
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
/// Upstream does all of this in one loop over the TCP stream
/// (`raop_rtp_mirror.c:295-558`): it reads a header and a payload, decrypts the
/// video kinds with [`MirrorDecryptor`], prepends a pending codec configuration,
/// rewrites the length prefixes into start codes, and hands the result to a
/// decoder. This type is that loop without the socket, so the part that can be
/// wrong about the protocol is testable and a caller owns the connection.
#[derive(Debug)]
pub struct MirrorSession {
    decryptor: MirrorDecryptor,
    codec: CodecConfig,
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
    /// Payloads that were not the units they should be, which upstream passes on
    /// marked rather than treating as fatal (`raop_rtp_mirror.c:533-536`).
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
        self.decryptor.rekey(keys)
    }

    /// Frames handed out so far.
    /// What this session did with the packets that were not frames.
    pub fn census(&self) -> std::sync::Arc<PacketCensus> {
        std::sync::Arc::clone(&self.dropped)
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
    /// as [`parse_packet`] returned it.
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
                        // Upstream marks a frame whose units do not add up and passes
                        // it on rather than ending the stream (`:533-536`), so this is
                        // counted and reported instead of being fatal.                        // The bytes and the reader's objection are what a report needs,
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
                    // Upstream counts the two units it prepends, so a caller can
                    // report how many a frame holds (`raop_rtp_mirror.c:547-553`).
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

#[cfg(test)]
mod tests;

#[cfg(test)]
mod hevc_tests {
    use super::{CodecConfig, VideoCodec};

    /// A codec packet the way an HEVC mirroring client lays it out.
    fn hevc_packet(vps: &[u8], sps: &[u8], pps: &[u8]) -> Vec<u8> {
        let mut payload = vec![0u8; 0x75];
        payload[4..8].copy_from_slice(b"hvc1");
        for (marker, set) in [(0xa0u8, vps), (0xa1, sps), (0xa2, pps)] {
            payload.push(marker);
            payload.extend_from_slice(&[0x00, 0x01]);
            payload.extend_from_slice(&(set.len() as u16).to_be_bytes());
            payload.extend_from_slice(set);
        }
        payload
    }

    #[test]
    fn an_hevc_configuration_becomes_three_units_behind_start_codes() {
        let vps = [0x40u8, 0x01, 0x0c];
        let sps = [0x42u8, 0x01, 0x01];
        let pps = [0x44u8, 0x01, 0xc0];
        let payload = hevc_packet(&vps, &sps, &pps);
        let mut config = CodecConfig::new();
        config.codec_data(7, &payload).expect("a conforming packet");
        assert_eq!(config.codec(), VideoCodec::H265);
        let units = config.prepend_to(7).expect("the packet it belongs to");
        let expected: Vec<u8> = [
            &[0u8, 0, 0, 1][..],
            &vps,
            &[0, 0, 0, 1],
            &sps,
            &[0, 0, 0, 1],
            &pps,
        ]
        .concat();
        assert_eq!(units, expected);
    }

    #[test]
    fn an_h264_configuration_is_still_h264() {
        // The H.264 layout: a size at six, the set at eight. Its four-character code is
        // `avc1`, which is what keeps the two apart.
        let mut payload = vec![0u8; 6];
        payload.extend_from_slice(&[0x00, 0x02]);
        payload.extend_from_slice(&[0x67, 0x42]);
        payload.push(0x01);
        payload.extend_from_slice(&[0x00, 0x01]);
        payload.extend_from_slice(&[0x68]);
        let mut config = CodecConfig::new();
        config.codec_data(1, &payload).expect("a conforming packet");
        assert_eq!(config.codec(), VideoCodec::H264);
    }

    #[test]
    fn a_marker_out_of_place_is_refused() {
        let mut payload = hevc_packet(&[0x40], &[0x42], &[0x44]);
        payload[0x75] = 0x99;
        let mut config = CodecConfig::new();
        assert!(config.codec_data(1, &payload).is_err());
        assert!(
            !config.is_pending(),
            "a refused packet leaves nothing waiting"
        );
    }
}
