// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

/// A mirror packet with `payload` after the header upstream reads.
fn packet(first: u8, second: u8, option: u16, timestamp: u64, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len());
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.push(first);
    bytes.push(second);
    bytes.extend_from_slice(&option.to_be_bytes());
    bytes.extend_from_slice(&timestamp.to_le_bytes());
    bytes.resize(HEADER_LEN, 0);
    bytes.extend_from_slice(payload);
    bytes
}

/// A payload of length-prefixed units, as the client sends them.
fn units(units: &[&[u8]]) -> Vec<u8> {
    let mut payload = Vec::new();
    for unit in units {
        payload.extend_from_slice(&(unit.len() as u32).to_be_bytes());
        payload.extend_from_slice(unit);
    }
    payload
}

/// A codec payload the way upstream reads one: two bytes, the source width and
/// height as big-endian sixteen-bit values, then a sixteen-bit size and the
/// sequence parameter set, then a sixteen-bit size and the picture parameter
/// set (`raop_rtp_mirror.c:725-728`; the header around them is what
/// `:560-572` describes).
/// A codec packet in the layout a client sends, which is the layout the reader
/// above expects: six bytes of header, the sequence set's size and the set, one
/// byte between the sets, then the picture set's size and the set.
///
/// The byte between the sets is not decoration. A builder that left it out is how
/// the reader kept the offsets of the format's own description instead of the
/// wire's: the two agreed with each other and disagreed with every client, which
/// is what `reads_the_codec_packet_a_device_actually_sent` exists to catch.
fn codec_payload(sps: &[u8], pps: &[u8]) -> Vec<u8> {
    let mut payload = vec![0u8; 6];
    payload[2..4].copy_from_slice(&1920u16.to_be_bytes());
    payload[4..6].copy_from_slice(&1080u16.to_be_bytes());
    payload.extend_from_slice(&(sps.len() as u16).to_be_bytes());
    payload.extend_from_slice(sps);
    payload.push(0x01);
    payload.extend_from_slice(&(pps.len() as u16).to_be_bytes());
    payload.extend_from_slice(pps);
    payload
}

#[test]
fn keeps_the_codec_configuration_for_the_next_video_packet() {
    let sps = [0x67, 0x42, 0x00, 0x1e];
    let pps = [0x68, 0xce];
    let mut config = CodecConfig::new();
    assert!(!config.is_pending());
    config
        .codec_data(0x1122, &codec_payload(&sps, &pps))
        .expect("codec data");
    assert!(config.is_pending());

    // Upstream prepends the two units with start codes in front of them, and
    // only to a packet with the codec packet's own timestamp.
    let units = config.prepend_to(0x1122).expect("prepended");
    assert_eq!(
        units,
        [
            0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x01, 0x68, 0xce
        ]
    );
    assert!(!config.is_pending(), "it is prepended once");
    assert!(config.prepend_to(0x1122).is_none(), "not twice");
}

#[test]
fn reads_the_codec_packet_a_device_actually_sent() {
    // The bytes are from a real session: an iPad mirroring a 1080p screen sent
    // this as the first mirror packet (captured 2026-10-06, `kind=CodecData`,
    // 37 bytes, option 0x1601). It is an AVCDecoderConfigurationRecord —
    // `01` version, `64` profile, `00` compatibility, `28` level, `ff` a length
    // prefix of four, `e1` one SPS — and the sizes inside it are what upstream
    // reads (`raop_rtp_mirror.c:725-728`).
    //
    // A device test vector is worth more than a built one here: the port's own
    // builder writes the same layout, so a test built from it would pass even if
    // both were wrong about where the client puts the lengths.
    let packet = [
        0x01, 0x64, 0x00, 0x28, 0xff, 0xe1, 0x00, 0x12, 0x27, 0x64, 0x00, 0x28, 0xac, 0x13, 0x14,
        0x50, 0x18, 0x80, 0x89, 0xe2, 0x25, 0x9b, 0x80, 0x86, 0x80, 0x81, 0x01, 0x00, 0x04, 0x28,
        0xee, 0x3c, 0xb0, 0x02, 0x00, 0x00, 0x00,
    ];
    // The timestamp is the one that packet carried, so the configuration is
    // matched to the frame it belongs to the way a session matches it.
    const TIMESTAMP: u64 = 22_900_758_101_784;
    let mut config = CodecConfig::new();
    config
        .codec_data(TIMESTAMP, &packet)
        .expect("its configuration");

    // The record's own length fields decide where its sets end: `00 12` puts
    // eighteen bytes of sequence set after the length, and the `e2` that follows
    // marks four bytes of picture set. The four bytes after those are part of the
    // record — this client's SPS is 0x27-led and the RFC 6184 sequence a real one
    // ends with is not here — and a decoder is given the two sets the record
    // sizes rather than the trailing bytes.
    let units = config.prepend_to(TIMESTAMP).expect("prepended");
    let mut expected = Vec::new();
    expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    expected.extend_from_slice(&packet[8..26]);
    expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    expected.extend_from_slice(&[0x28, 0xee, 0x3c, 0xb0]);
    assert_eq!(units, expected, "each set behind its own start code");
    assert_eq!(packet[6..8], [0x00, 0x12], "eighteen bytes of sequence set");
    assert_eq!(units.len(), 4 + 18 + 4 + 4);
}

#[test]
fn refuses_a_stream_payload_beyond_what_a_frame_can_be() {
    // The bound is a guard against a client making a receiver allocate without
    // limit, not a judgement about frames: a 1080p screen that has just changed
    // arrives as one 76298-byte packet, which a real session sent and this crate
    // refused when the bound was 32768. So the test parses a packet of exactly
    // that size rather than asserting the constant is large enough, which would
    // be a statement about the constant and not about what it does.
    const REAL_FRAME: usize = 76_298;
    let mut frame = vec![0u8; HEADER_LEN + REAL_FRAME];
    frame[0..4].copy_from_slice(&(REAL_FRAME as u32).to_le_bytes());
    frame[4] = 0x00;
    frame[5] = 0x10;
    let (header, payload) = parse_packet(&frame).expect("a frame a device sent");
    assert_eq!(header.payload_size as usize, REAL_FRAME);
    assert_eq!(payload.len(), REAL_FRAME);
    assert_eq!(header.kind, MirrorKind::Video { idr: true });

    let mut huge = vec![0u8; HEADER_LEN];
    huge[0..4].copy_from_slice(&(MAX_PAYLOAD as u32 + 1).to_le_bytes());
    assert_eq!(
        parse_header(&huge),
        Err(MirrorError::TooLarge {
            promised: MAX_PAYLOAD + 1,
            maximum: MAX_PAYLOAD
        })
    );
}
#[test]
fn drops_a_configuration_whose_timestamp_does_not_match() {
    // A video packet with another timestamp means the configuration belongs
    // to a stream that is no longer arriving (raop_rtp_mirror.c:426-433), and
    // a decoder fed it would see parameter sets for the wrong picture.
    let mut config = CodecConfig::new();
    config
        .codec_data(0x1122, &codec_payload(&[0x67, 0x01], &[0x68, 0x02]))
        .expect("codec data");
    assert!(config.prepend_to(0x3344).is_none(), "discarded");
    assert!(!config.is_pending(), "and not kept for the next packet");
    assert!(config.prepend_to(0x1122).is_none());
}

#[test]
fn a_later_configuration_replaces_one_that_was_never_used() {
    let mut config = CodecConfig::new();
    config
        .codec_data(1, &codec_payload(&[0x67, 0xaa], &[0x68, 0xbb]))
        .expect("first");
    config
        .codec_data(2, &codec_payload(&[0x67, 0xcc], &[0x68, 0xdd]))
        .expect("second");
    assert_eq!(
        config.prepend_to(2).expect("prepended"),
        [
            0x00, 0x00, 0x00, 0x01, 0x67, 0xcc, 0x00, 0x00, 0x00, 0x01, 0x68, 0xdd
        ]
    );
}

#[test]
fn refuses_a_codec_payload_that_does_not_hold_two_parameter_sets() {
    let mut config = CodecConfig::new();
    assert_eq!(
        config.codec_data(1, &[0, 0, 0, 0, 0]),
        Err(CodecDataError::TooShort { length: 5 })
    );
    // The sizes claim more than the payload has: a 25-byte sequence parameter
    // set whose size field sits past the end of a 30-byte payload.
    let mut payload = vec![0u8; 30];
    payload[6..8].copy_from_slice(&25u16.to_be_bytes());
    assert_eq!(
        config.codec_data(1, &payload),
        Err(CodecDataError::SizeOutOfRange {
            sps: 25,
            pps: 0,
            length: 30
        })
    );
    assert!(!config.is_pending(), "nothing was kept");

    // A length that would overflow the offset arithmetic is refused before
    // anything is read with it.
    let mut huge = vec![0u8; 10];
    huge[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(matches!(
        config.codec_data(1, &huge),
        Err(CodecDataError::SizeOutOfRange { sps: 65535, .. })
    ));
}

/// The keystream a stream generates from its IV, computed here rather than by
/// the type under test: block `index` is the AES-128 encryption of `IV + index`,
/// and the keystream is those blocks one after another.
fn keystream(keys: &StreamKeys, blocks: usize) -> Vec<u8> {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let cipher = aes::Aes128::new(keys.key[..].into());
    let mut counter = keys.iv;
    let mut out = Vec::with_capacity(blocks * 16);
    for _ in 0..blocks {
        let mut block = aes::Block::clone_from_slice(&counter);
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(&block);
        for byte in counter.iter_mut().rev() {
            let (next, wrapped) = byte.overflowing_add(1);
            *byte = next;
            if !wrapped {
                break;
            }
        }
    }
    out
}

/// One payload of `length` patterned bytes, so a wrong offset shows up in every
/// byte instead of only where the pattern happens to change.
fn patterned(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index as u8).wrapping_mul(7) ^ 0x3c)
        .collect()
}

/// The client's side of the wire, written from the rule `mirror_buffer_decrypt`
/// follows (`upstream/UxPlay@3dbf7cee:lib/mirror_buffer.c:94-124`) rather than from
/// this crate: the counter restarts on the block after the blocks used so far, the
/// bytes carried from the previous packet go in front, and a packet that does not
/// end on a block boundary puts its tail, zero padded, into one whole block whose
/// unused bytes it carries.
///
/// A port and a client that both read the rule correctly agree on the keystream
/// every byte sits at. The differential test in `tests/upstream_oracle.rs` checks
/// the same port against upstream's own code; this is what checks whole packet
/// sequences, which the oracle's vectors are not.
struct Encoder<'a> {
    stream: &'a [u8],
    /// Whole blocks the packets so far occupied, plus one for a tail that did not
    /// fill its block: where the next packet's fresh counter starts.
    blocks: usize,
    /// Where in `stream` the bytes being carried came from, so the test can check
    /// the receiver read the same ones.
    carry_at: usize,
    carried: usize,
}

impl<'a> Encoder<'a> {
    fn new(stream: &'a [u8]) -> Self {
        Self {
            stream,
            blocks: 0,
            carry_at: 0,
            carried: 0,
        }
    }

    /// Encrypts `plaintext` the way a client would, and returns the ciphertext,
    /// the keystream offset each byte of it sits at, how many bytes are left for
    /// the next packet, and the block the next packet will start its counter on.
    fn encrypt(&mut self, plaintext: &[u8]) -> (Vec<u8>, Vec<usize>, usize, usize) {
        let carried = self.carried;
        let fresh_at = self.blocks * 16;
        let whole = (plaintext.len() - carried) / 16 * 16;
        let rest = plaintext.len() - carried - whole;
        let mut ciphertext = plaintext.to_vec();
        let mut offsets = Vec::with_capacity(plaintext.len());
        for index in 0..carried {
            offsets.push(self.carry_at + index);
        }
        for index in carried..plaintext.len() {
            offsets.push(fresh_at + index - carried);
        }
        for (index, offset) in offsets.iter().enumerate() {
            ciphertext[index] ^= self.stream[*offset];
        }
        // The counter advances by the block the tail sits in and the whole blocks
        // after the carry: the carry's bytes were the previous packet's, so they
        // are not part of this packet's blocks.
        self.blocks += (plaintext.len() - carried) / 16;
        if rest > 0 {
            let tail = fresh_at + whole;
            self.carry_at = tail + rest;
            self.carried = 16 - rest;
            self.blocks += 1;
        } else {
            self.carried = 0;
        }
        (ciphertext, offsets, self.carried, self.blocks)
    }
}

#[test]
fn the_keystream_generator_matches_the_crates_own_cipher() {
    // `MirrorDecryptor` generates its blocks from the IV itself, because where
    // the counter sits is the whole of the mirror rule. This says that generator
    // produces the same bytes as the CTR cipher the rest of the crate uses.
    let keys = stream_keys(11, &[0x44; STREAM_KEY_LEN]);
    let reference = keystream(&keys, 4);
    let mut cipher = [0u8; 64];
    crate::crypto::Aes128CtrState::new(&keys.key, &keys.iv)
        .expect("state")
        .apply(&mut cipher);
    let decryptor = MirrorDecryptor::new(&keys).expect("decryptor");
    assert_eq!(reference, cipher.to_vec(), "the reference over a buffer");
    assert_eq!(
        decryptor.keystream(0, 4),
        cipher.to_vec(),
        "the decryptor's generator"
    );
    // And a block further into the stream is that block, not a shifted one.
    assert_eq!(
        decryptor.keystream(2, 2),
        cipher[32..64].to_vec(),
        "blocks two and three"
    );
}

#[test]
fn the_counter_carries_into_the_byte_before_it() {
    // The counter is the IV plus the block index as a 128-bit big-endian number, and the
    // carry goes through every byte of it. A generator that stops at the first byte that
    // does not overflow reads 256 blocks away from where it should, which is what this
    // pins: `4f` at the end of the IV, block `b1`, is `100` in the last byte and needs
    // the byte before it to take the one.
    //
    // The keys are the mirror stream's own, and the blocks are the ones a real session
    // reaches: this went wrong at block 177 and every vector before it was shorter.
    let keys = stream_keys(2_765_102_747_429_192_913, &[0x5a; STREAM_KEY_LEN]);
    let generator = keystream(&keys, 700);
    let decryptor = MirrorDecryptor::new(&keys).expect("decryptor");

    assert_eq!(
        keys.iv[STREAM_KEY_LEN - 1],
        0x4f,
        "the carry this pins starts at this byte"
    );
    for block in [176usize, 177, 178, 255, 256, 257, 432, 433] {
        assert_eq!(
            decryptor.keystream(block as u64, 1),
            generator[block * 16..block * 16 + 16],
            "block {block} is that block of the stream and not one 256 further on"
        );
    }
    // And the block the wrong carry would have produced is a different one, so a
    // generator that drops it cannot pass by accident.
    assert_ne!(
        decryptor.keystream(177, 1),
        decryptor.keystream(433, 1),
        "block 177 is not block 433"
    );
}

#[test]
fn decrypts_what_a_client_encrypts_with_the_same_rule() {
    // Packet lengths that can really appear on the wire: every one is at least as
    // long as the bytes the previous packet left behind. The handoff's fixed
    // vector comes first, then a length that is never block aligned, a whole
    // number of blocks, and small packets.
    let lengths = [40usize, 24, 33, 47, 1, 64, 5, 128];
    let keys = stream_keys(7, &[0x31; STREAM_KEY_LEN]);
    // The vector's total length is 339 bytes, and 64 blocks cover it.
    let stream = keystream(&keys, 64);
    // The reference keystream is checked against the crate's own cipher over a
    // whole buffer, so a mistake in it cannot make this test agree with a mistake
    // in the implementation.
    let mut zeros = vec![0u8; 512];
    crate::crypto::Aes128CtrState::new(&keys.key, &keys.iv)
        .expect("state")
        .apply(&mut zeros);
    assert_eq!(zeros, stream[..512], "the reference keystream");

    let mut encoder = Encoder::new(&stream);
    let mut decryptor = MirrorDecryptor::new(&keys).expect("decryptor");
    let mut carried = 0usize;
    for length in lengths {
        // A shorter packet than the bytes being carried is not something a client
        // sends; the receiver refuses it, and that has its own test.
        if length < carried {
            continue;
        }
        let plaintext = patterned(length);
        let (ciphertext, offsets, left, next_block) = encoder.encrypt(&plaintext);
        assert_ne!(ciphertext, plaintext, "a packet of {length} is encrypted");
        let mut out = vec![0u8; length];
        decryptor
            .decrypt(&ciphertext, &mut out)
            .unwrap_or_else(|error| panic!("packet of {length}: {error}"));
        assert_eq!(
            out, plaintext,
            "a packet of {length} did not come back the way it was sent"
        );
        // The receiver has to have read the keystream the client wrote with, byte
        // for byte: this is the whole of the rule, and the offsets come from the
        // client's side rather than from the port.
        for (index, byte) in out.iter().enumerate() {
            assert_eq!(
                *byte,
                ciphertext[index] ^ stream[offsets[index]],
                "packet of {length}, byte {index} read keystream offset {}",
                offsets[index]
            );
        }
        assert_eq!(
            decryptor.carried(),
            left,
            "the bytes a packet of {length} leaves for the next one"
        );
        // Where the client's counter will be is where the receiver's has to be:
        // both sides have to agree about the block a packet starts on.
        assert_eq!(
            decryptor.read_block(),
            next_block as u64,
            "where the packet after {length} starts reading"
        );
        carried = left;
    }
}

#[test]
fn carries_the_tail_block_into_the_next_packet() {
    // Upstream's fixed vector, byte by byte: a 40-byte packet uses two whole
    // blocks and eight bytes of a third, and the other eight bytes of that third
    // block are what the next packet's head is XORed with
    // (`mirror_buffer.c:96-100`, `:111-123`). A rule stated without this check loses
    // those eight bytes, which is what this test reports.
    let keys = stream_keys(1, &[0x11; STREAM_KEY_LEN]);
    let stream = keystream(&keys, 6);
    let mut encoder = Encoder::new(&stream);
    let mut decryptor = MirrorDecryptor::new(&keys).expect("decryptor");

    let first = patterned(40);
    let (ciphertext, offsets, left, _) = encoder.encrypt(&first);
    let mut out = vec![0u8; 40];
    decryptor.decrypt(&ciphertext, &mut out).expect("first");
    assert_eq!(out, first);
    assert_eq!(decryptor.carried(), 8, "40 bytes leaves the block's last 8");
    assert_eq!(left, 8);
    for (index, byte) in out.iter().enumerate() {
        assert_eq!(*byte, ciphertext[index] ^ stream[index], "byte {index}");
        assert_eq!(offsets[index], index, "the encoder's own offset {index}");
    }

    let second = patterned(24);
    let (ciphertext, offsets, left, _) = encoder.encrypt(&second);
    let mut out = vec![0u8; 24];
    decryptor.decrypt(&ciphertext, &mut out).expect("second");
    assert_eq!(out, second);
    assert_eq!(decryptor.carried(), 0, "24 bytes ends on a block boundary");
    assert_eq!(left, 0);
    // The second packet reads block 2's last eight bytes for its head and block 2
    // from its start for the body: the counter restarted, it did not continue.
    assert_eq!(&offsets[..8], &[40, 41, 42, 43, 44, 45, 46, 47]);
    for (index, byte) in out.iter().enumerate() {
        assert_eq!(
            *byte,
            ciphertext[index] ^ stream[offsets[index]],
            "byte {index}"
        );
    }
}

#[test]
fn restarts_the_counter_at_every_packet() {
    // Two 24-byte packets. The first uses block 0 and the first half of block 1,
    // carrying the rest of block 1. The second's fresh block is block 2, so its
    // head is the carry from block 1 and its body is block 2 — a continuous stream
    // would have put the whole second packet at bytes 24..48 instead.
    let keys = stream_keys(3, &[0x77; STREAM_KEY_LEN]);
    let stream = keystream(&keys, 4);
    let mut encoder = Encoder::new(&stream);
    let mut decryptor = MirrorDecryptor::new(&keys).expect("decryptor");

    let first = patterned(24);
    let (ciphertext, offsets, _, _) = encoder.encrypt(&first);
    let mut out = vec![0u8; 24];
    decryptor.decrypt(&ciphertext, &mut out).expect("first");
    assert_eq!(out, first);
    assert_eq!(decryptor.carried(), 8);
    for (index, byte) in out.iter().enumerate() {
        assert_eq!(*byte, ciphertext[index] ^ stream[index], "byte {index}");
        assert_eq!(offsets[index], index, "the encoder's own offset {index}");
    }

    let second = patterned(24);
    let (ciphertext, offsets, _, _) = encoder.encrypt(&second);
    let mut out = vec![0u8; 24];
    decryptor.decrypt(&ciphertext, &mut out).expect("second");
    assert_eq!(out, second);
    assert_eq!(&offsets[..8], &[24, 25, 26, 27, 28, 29, 30, 31]);
    assert_eq!(offsets[8], 32, "the body starts at the fresh block");
    for (index, byte) in out.iter().enumerate() {
        assert_eq!(
            *byte,
            ciphertext[index] ^ stream[offsets[index]],
            "byte {index}"
        );
    }
}

#[test]
fn a_rekey_drops_the_carry_and_starts_the_keystream_over() {
    let keys = stream_keys(5, &[0x22; STREAM_KEY_LEN]);
    let other = stream_keys(6, &[0x22; STREAM_KEY_LEN]);
    let mut decryptor = MirrorDecryptor::new(&keys).expect("decryptor");
    let mut out = vec![0u8; 40];
    decryptor.decrypt(&patterned(40), &mut out).expect("first");
    assert_eq!(decryptor.carried(), 8);
    decryptor.rekey(&other).expect("rekey");
    assert_eq!(decryptor.carried(), 0, "the old stream's bytes are gone");

    // The first packet of the new stream is decrypted from the beginning of its
    // own keystream, and its head is not the old stream's carry.
    let stream = keystream(&other, 3);
    let mut encoder = Encoder::new(&stream);
    let packet = patterned(33);
    let (ciphertext, offsets, _, _) = encoder.encrypt(&packet);
    let mut out = vec![0u8; 33];
    decryptor
        .decrypt(&ciphertext, &mut out)
        .expect("new stream");
    assert_eq!(out, packet);
    for (index, byte) in out.iter().enumerate() {
        assert_eq!(*byte, ciphertext[index] ^ stream[index], "byte {index}");
        assert_eq!(offsets[index], index, "the new stream starts at its IV");
    }
}

#[test]
fn a_session_turns_video_packets_into_frames_and_keeps_the_codec_data() {
    // The client's side of a whole little stream: a codec packet, then two video
    // packets of the kind a client sends, one of them an IDR.
    let keys = stream_keys(21, &[0x66; STREAM_KEY_LEN]);
    let timestamp = 0x0000_1234_5678_9abc;
    let sps = [0x67, 0x42, 0x00, 0x1e];
    let pps = [0x68, 0xce];
    let mut session = MirrorSession::new(&keys).expect("session");

    // The codec packet is not a frame; it is kept for the next one.
    let codec = packet(0x01, 0x00, 0x16, timestamp, &codec_payload(&sps, &pps));
    let (header, payload) = parse_packet(&codec).expect("codec packet");
    assert_eq!(
        session.receive(&header, payload).expect("codec"),
        None,
        "a codec packet is not a frame"
    );
    assert_eq!(session.frames(), 0);

    // One video packet carrying one unit, encrypted by the client.
    let unit = [0x65, 0x11, 0x22, 0x33];
    let body = units(&[&unit]);
    let mut stream = keystream(&keys, 4);
    let ciphertext: Vec<u8> = body
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ stream[index])
        .collect();
    stream.clear();
    let video = packet(0x00, 0x10, 0x00, timestamp, &ciphertext);
    let (header, payload) = parse_packet(&video).expect("video packet");
    let frame = session
        .receive(&header, payload)
        .expect("video")
        .expect("a frame");
    assert_eq!(frame.timestamp, timestamp);
    assert!(frame.idr, "0x00 0x10 is an IDR packet");
    assert_eq!(
        frame.data,
        [
            0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x01, 0x68, 0xce,
            0x00, 0x00, 0x00, 0x01, 0x65, 0x11, 0x22, 0x33
        ],
        "the codec data is prepended and the prefix is a start code"
    );
    assert_eq!(frame.units, 3, "SPS, PPS and the slice");
    assert_eq!(session.frames(), 1);

    // A keep-alive is not a frame and does not disturb the stream.
    let keep_alive = packet(0x02, 0x00, 0x1e, 0, &[]);
    let (header, payload) = parse_packet(&keep_alive).expect("keep-alive");
    assert_eq!(session.receive(&header, payload).expect("keep-alive"), None);
    assert_eq!(session.frames(), 1);
}

#[test]
fn a_session_drops_a_codec_configuration_that_no_longer_matches() {
    // A codec packet, then a video packet with another timestamp: the
    // configuration belongs to a stream that stopped, so it must not be
    // prepended to this frame.
    let keys = stream_keys(22, &[0x67; STREAM_KEY_LEN]);
    let mut session = MirrorSession::new(&keys).expect("session");
    let codec = packet(0x01, 0x00, 0x16, 7, &codec_payload(&[0x67, 1], &[0x68, 2]));
    let (header, payload) = parse_packet(&codec).expect("codec");
    session.receive(&header, payload).expect("codec");

    let mut stream = keystream(&keys, 2);
    let body = units(&[&[0x41, 0xaa]]);
    let ciphertext: Vec<u8> = body
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ stream[index])
        .collect();
    stream.clear();
    let video = packet(0x00, 0x00, 0x00, 99, &ciphertext);
    let (header, payload) = parse_packet(&video).expect("video");
    let frame = session
        .receive(&header, payload)
        .expect("video")
        .expect("a frame");
    assert_eq!(
        frame.data,
        [0x00, 0x00, 0x00, 0x01, 0x41, 0xaa],
        "only the frame's own unit"
    );
    assert_eq!(frame.units, 1);
    assert!(!frame.idr);
}

#[test]
fn a_session_reports_a_frame_whose_units_do_not_hold_together() {
    // The length prefix claims more than the payload has, which upstream treats
    // as an invalid frame rather than as a broken connection
    // (`raop_rtp_mirror.c:458-474`).
    let keys = stream_keys(23, &[0x68; STREAM_KEY_LEN]);
    let mut session = MirrorSession::new(&keys).expect("session");
    let body = [0x00, 0x00, 0x00, 0x40, 0x65, 0x01];
    let stream = keystream(&keys, 2);
    let ciphertext: Vec<u8> = body
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ stream[index])
        .collect();
    let video = packet(0x00, 0x00, 0x00, 3, &ciphertext);
    let (header, payload) = parse_packet(&video).expect("video");
    assert_eq!(
        session.receive(&header, payload),
        Err(FrameError::NotUnits(NalError::LengthOutOfRange {
            offset: 0,
            claimed: 64,
            available: 2
        }))
    );
    assert_eq!(
        session.frames(),
        0,
        "a frame that could not be read is not one"
    );
}

#[test]
fn a_rekey_restarts_the_keystream_and_drops_the_codec_data() {
    let keys = stream_keys(24, &[0x69; STREAM_KEY_LEN]);
    let other = stream_keys(25, &[0x69; STREAM_KEY_LEN]);
    let mut session = MirrorSession::new(&keys).expect("session");
    let codec = packet(0x01, 0x00, 0x16, 5, &codec_payload(&[0x67, 1], &[0x68, 2]));
    let (header, payload) = parse_packet(&codec).expect("codec");
    session.receive(&header, payload).expect("codec");
    session.rekey(&other).expect("rekey");

    // The first packet of the new stream reads its own keystream from the start,
    // and the configuration from the old stream is gone.
    let stream = keystream(&other, 2);
    let body = units(&[&[0x41, 0xbb]]);
    let ciphertext: Vec<u8> = body
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ stream[index])
        .collect();
    let video = packet(0x00, 0x00, 0x00, 5, &ciphertext);
    let (header, payload) = parse_packet(&video).expect("video");
    let frame = session
        .receive(&header, payload)
        .expect("video")
        .expect("a frame");
    assert_eq!(frame.data, [0x00, 0x00, 0x00, 0x01, 0x41, 0xbb]);
    assert_eq!(frame.units, 1);
}

#[test]
fn a_session_reports_a_packet_that_is_off_its_stream() {
    // A four-byte packet cannot be the first one: the stream's first packet has
    // to be long enough to leave a block behind, and the session says so rather
    // than decrypting at a guessed offset.
    let keys = stream_keys(26, &[0x6a; STREAM_KEY_LEN]);
    let mut session = MirrorSession::new(&keys).expect("session");
    let short = packet(0x00, 0x00, 0x00, 9, &[0u8; 3]);
    let (header, payload) = parse_packet(&short).expect("short");
    // Three bytes is a legal packet length for the stream itself; what it cannot
    // be is a packet whose units hold together, so this is the unit check that
    // reports it.
    let outcome = session.receive(&header, payload);
    assert!(
        matches!(outcome, Err(FrameError::NotUnits(_))),
        "a three-byte video payload is not a frame: {outcome:?}"
    );
    assert_eq!(session.frames(), 0);

    // A packet shorter than the bytes being carried is not refused: upstream takes
    // what it needs of them and loses the rest, because its carry buffer is one block
    // that the next packet overwrites whole (`mirror_buffer.c:115-117`). The oracle's
    // own readers do exactly that for a pair of one-byte packets, so this reproduces
    // it. What the session does report is the payload, which cannot be units.
    let mut carried = MirrorSession::new(&keys).expect("session");
    let stream = keystream(&keys, 3);
    let body = units(&[&[0x41; 20]]);
    let ciphertext: Vec<u8> = body
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ stream[index])
        .collect();
    let video = packet(0x00, 0x00, 0x00, 8, &ciphertext);
    let (header, payload) = parse_packet(&video).expect("video");
    assert!(carried.receive(&header, payload).expect("video").is_some());
    let short = packet(0x00, 0x00, 0x00, 9, &[0u8; 3]);
    let (header, payload) = parse_packet(&short).expect("short");
    assert!(
        matches!(
            carried.receive(&header, payload),
            Err(FrameError::NotUnits(_))
        ),
        "a three-byte payload is not a frame however the carry went"
    );
}

#[test]
fn rewrites_length_prefixes_into_start_codes() {
    // An IDR slice and a non-IDR slice, the two shapes a stream carries.
    let mut payload = units(&[&[0x65, 0xaa, 0xbb], &[0x41, 0xcc]]);
    assert_eq!(into_annex_b(&mut payload).expect("two units"), 2);
    assert_eq!(
        payload,
        [
            0x00, 0x00, 0x00, 0x01, 0x65, 0xaa, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x41, 0xcc
        ]
    );
    // An empty payload holds no units and is not an error.
    assert_eq!(into_annex_b(&mut []).expect("empty"), 0);
}

#[test]
fn refuses_a_length_that_does_not_fit() {
    // The prefix claims eight bytes but two follow.
    let mut payload = vec![0, 0, 0, 8, 0x65, 0xaa];
    assert_eq!(
        into_annex_b(&mut payload),
        Err(NalError::LengthOutOfRange {
            offset: 0,
            claimed: 8,
            available: 2
        })
    );
    // A payload that ends inside a prefix is refused too, rather than being
    // read as a length.
    let mut short = vec![0, 0, 0x65, 0xaa];
    assert!(matches!(
        into_annex_b(&mut short),
        Err(NalError::LengthOutOfRange { offset: 0, .. })
    ));
}

#[test]
fn refuses_a_unit_whose_forbidden_bit_is_set() {
    // Upstream checks the bit before it looks at anything else in the unit
    // (raop_rtp_mirror.c:470-474).
    let mut payload = units(&[&[0x85, 0x00]]);
    assert_eq!(
        into_annex_b(&mut payload),
        Err(NalError::ForbiddenBit { offset: 4 })
    );
}

#[test]
fn reads_the_header_upstream_reads() {
    let bytes = packet(0x00, 0x10, 0x0000, 0x1122_3344_5566_7788, &[1, 2, 3, 4]);
    let (header, payload) = parse_packet(&bytes).expect("packet");
    assert_eq!(header.payload_size, 4);
    assert_eq!(header.kind, MirrorKind::Video { idr: true });
    assert_eq!(header.option, 0);
    assert_eq!(header.timestamp, 0x1122_3344_5566_7788);
    assert_eq!(payload, [1, 2, 3, 4]);
}

#[test]
fn tells_encrypted_video_from_what_must_stay_clear() {
    // The pairs upstream lists, and which of them a receiver decrypts.
    for (first, second, kind, encrypted) in [
        (0x00, 0x00, MirrorKind::Video { idr: false }, true),
        (0x00, 0x10, MirrorKind::Video { idr: true }, true),
        (0x01, 0x00, MirrorKind::CodecData, false),
        (0x02, 0x00, MirrorKind::KeepAlive, false),
        (0x05, 0x00, MirrorKind::StreamingReport, false),
        (
            0x07,
            0x03,
            MirrorKind::Unknown {
                first: 0x07,
                second: 0x03,
            },
            false,
        ),
    ] {
        let bytes = packet(first, second, 0, 0, &[0; 8]);
        let (header, _) = parse_packet(&bytes).expect("packet");
        assert_eq!(header.kind, kind, "{first:#04x} {second:#04x}");
        assert_eq!(header.kind.is_encrypted(), encrypted, "{kind:?}");
    }
}

#[test]
fn refuses_what_it_cannot_read() {
    assert_eq!(
        parse_packet(&[0; 127]),
        Err(MirrorError::TooShort { length: 127 })
    );
    // The header promises more than the packet carries.
    let mut bytes = packet(0x00, 0x00, 0, 0, &[0; 4]);
    bytes.truncate(HEADER_LEN + 2);
    assert_eq!(
        parse_packet(&bytes),
        Err(MirrorError::Truncated {
            promised: 4,
            present: 2
        })
    );
    // And one that promises more than a receiver reads, before allocating.
    let mut huge = vec![0u8; HEADER_LEN];
    huge[0..4].copy_from_slice(&(MAX_PAYLOAD as u32 + 1).to_le_bytes());
    assert_eq!(
        parse_packet(&huge),
        Err(MirrorError::TooLarge {
            promised: MAX_PAYLOAD + 1,
            maximum: MAX_PAYLOAD
        })
    );
}

#[test]
fn parses_the_construction_upstream_writes_out() {
    // The test rebuilds the hash itself, so a change to the prefixes, the
    // decimal formatting or the audio key's place in the hash fails here
    // rather than on a device.
    let connection_id = 2_765_102_747_429_192_913u64;
    let audio_key = [0x5a; STREAM_KEY_LEN];
    let keys = stream_keys(connection_id, &audio_key);

    let expected_key = sha512_concat(&[
        format!("AirPlayStreamKey{connection_id}").as_bytes(),
        &audio_key,
    ]);
    let expected_iv = sha512_concat(&[
        format!("AirPlayStreamIV{connection_id}").as_bytes(),
        &audio_key,
    ]);
    assert_eq!(keys.key, expected_key[..STREAM_KEY_LEN]);
    assert_eq!(keys.iv, expected_iv[..STREAM_KEY_LEN]);
    assert_ne!(keys.key, keys.iv, "the two prefixes differ");
}

#[test]
fn the_identifier_is_hashed_as_text() {
    // 123 hashed as text is not 123 hashed as bytes; the test pins the form
    // upstream uses so this cannot drift silently.
    let audio_key = [0x11; STREAM_KEY_LEN];
    let as_text = stream_keys(123, &audio_key);
    let mut as_bytes = [0u8; 8];
    as_bytes.copy_from_slice(&123u64.to_be_bytes());
    let mut material = b"AirPlayStreamKey".to_vec();
    material.extend_from_slice(&as_bytes);
    let hashed_bytes = sha512_concat(&[&material, &audio_key]);
    assert_ne!(as_text.key, hashed_bytes[..STREAM_KEY_LEN]);
}

#[test]
fn a_different_stream_or_key_gives_different_material() {
    let audio_key = [0x22; STREAM_KEY_LEN];
    let first = stream_keys(1, &audio_key);
    let other_stream = stream_keys(2, &audio_key);
    let other_key = stream_keys(1, &[0x23; STREAM_KEY_LEN]);
    assert_ne!(first.key, other_stream.key);
    assert_ne!(first.key, other_key.key);
    assert_ne!(first.iv, other_stream.iv);
    // The same inputs always give the same material: a caller may derive it
    // again after a re-key without asking the client anything.
    assert_eq!(first, stream_keys(1, &audio_key));
}
