// SPDX-License-Identifier: GPL-3.0-or-later
//! A mirror stream's keys, and the AES-CTR position rule that is not a plain stream.

use super::header::MirrorError;
use crate::crypto::sha512_concat;

/// Length of the key and IV a mirror stream uses
/// (`RAOP_AESKEY_LEN` in the protocol).
pub const STREAM_KEY_LEN: usize = 16;

/// Prefix of the material a mirror stream's key is hashed from.
const KEY_PREFIX: &str = "AirPlayStreamKey";

/// Prefix of the material a mirror stream's IV is hashed from.
const IV_PREFIX: &str = "AirPlayStreamIV";

/// The key and IV of one mirror stream.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StreamKeys {
    /// AES-128-CTR key of the stream.
    pub key: [u8; STREAM_KEY_LEN],
    /// AES-128-CTR initial counter block of the stream.
    pub iv: [u8; STREAM_KEY_LEN],
}

impl std::fmt::Debug for StreamKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key and counter block are the whole secret of the stream.
        formatter
            .debug_struct("StreamKeys")
            .field("key", &"<redacted>")
            .field("iv", &"<redacted>")
            .finish()
    }
}

/// Derives the keys of the mirror stream a client identified with
/// `connection_id`, using the audio key of the session it belongs to.
///
/// The decimal form of the identifier matters: the protocol formats it with `%llu`,
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

/// The keystream of one mirror stream.
///
/// This is the state of the stream's cipher: the key and IV, where in the stream the counter has
/// come to, and the bytes of a partly used keystream block that the previous packet left
/// behind. The rule is not what a plain CTR stream would do, so it is written here in the order
/// the cipher performs it:
///
/// 1. the first `carry` bytes of the packet are XORed with the **end** of the previous packet's
///    tail block, which that packet did not use;
/// 2. the counter is moved to a block boundary (the block after the tail block), and the whole
///    blocks after the carry - `((len - carry) / 16) * 16` bytes - are decrypted from there;
/// 3. the remaining `rest = (len - carry) % 16` bytes are decrypted as one whole block (zero
///    padded), of which the packet keeps the first `rest`; the other `16 - rest` keystream
///    bytes are the carry for the next packet.
///
/// So a packet's first bytes are keystream the previous packet left behind, and its body is the
/// stream's own blocks from the counter, which is what makes this different from one continuous
/// keystream: two packets of the same length read the same blocks. The counter advances by the
/// blocks a packet used, its tail included, because the next packet starts one block past the
/// carry's block.
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
    /// How many of those bytes the next packet starts with, the protocol's
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
    /// The protocol clears its carry buffer here (`mirror_buffer_init_aes`,
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
    /// the protocol's `nextDecryptCount`.
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
    /// The protocol reaches this through OpenSSL's CTR context, whose counter block is
    /// incremented per block. Generating the blocks here keeps the position
    /// explicit: which block a packet starts on is the whole of the rule
    ///, and it must not depend on any state a cipher
    /// implementation keeps for itself.
    ///
    /// It is public because it is also the clearest way to check this crate against
    /// the protocol's own context, block for block, in the differential test.
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
        // loses the rest: the protocol's carry buffer is one block that the next packet
        // overwrites whole, so nothing of a carry outlives the
        // packet after it, whatever the two lengths are. A client does not send that, and
        // the oracle's own readers show what it does when one arrives, so this reproduces
        // it rather than refusing — the lengths are what a receiver has to survive.

        // A packet is read in two parts, and the line between them is what every earlier
        // version of this crate got wrong.
        //
        // The cipher reads whole blocks. A packet whose length is not a multiple of the
        // block fills part of its last block, and the counter comes out of that block at
        // its end — so the bytes the packet did not use are
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
        // this packet — the protocol's buffer holds one block and the next packet fills it.
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
