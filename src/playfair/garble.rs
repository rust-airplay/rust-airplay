// SPDX-License-Identifier: GPL-3.0-or-later
//! The PlayFair garble tables, hash, key schedule and message decryptor.

use super::session::sap_scramble;

const SHIFT: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const K: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

/// Computes the modified MD5-like compression FairPlay uses over one 64-byte block.
///
/// The block words are read as big-endian message words, while the 16-byte
/// chaining key and output use native little-endian words as in the original
/// implementation on supported AirPlay hosts.
pub(crate) fn modified_md5(block: &[u8; 64], key: &[u8; 16]) -> [u8; 16] {
    let mut words = [0u32; 16];
    for (word, chunk) in words.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    let key_words = std::array::from_fn::<_, 4, _>(|index| {
        let base = index * 4;
        u32::from_le_bytes([key[base], key[base + 1], key[base + 2], key[base + 3]])
    });
    let mut a = key_words[0];
    let mut b = key_words[1];
    let mut c = key_words[2];
    let mut d = key_words[3];

    for i in 0..64 {
        let j = match i {
            0..=15 => i,
            16..=31 => (5 * i + 1) % 16,
            32..=47 => (3 * i + 5) % 16,
            _ => (7 * i) % 16,
        };
        let input = u32::from_be_bytes(words[j].to_le_bytes());
        let function = match i {
            0..=15 => (b & c) | (!b & d),
            16..=31 => (b & d) | (c & !d),
            32..=47 => b ^ c ^ d,
            _ => c ^ (b | !d),
        };
        let z = a
            .wrapping_add(input)
            .wrapping_add(K[i])
            .wrapping_add(function)
            .rotate_left(SHIFT[i]);
        let z = z.wrapping_add(b);
        (a, b, c, d) = (d, z, b, c);

        if i == 31 {
            for (left, right) in [(a & 15, b & 15), (c & 15, d & 15)] {
                words.swap(left as usize, right as usize);
            }
            for shift in [4, 8, 12] {
                let left = ((a >> shift) & 15) as usize;
                let right = ((b >> shift) & 15) as usize;
                words.swap(left, right);
            }
        }
    }

    let mut output = [0u8; 16];
    for (index, value) in [
        key_words[0].wrapping_add(a),
        key_words[1].wrapping_add(b),
        key_words[2].wrapping_add(c),
        key_words[3].wrapping_add(d),
    ]
    .into_iter()
    .enumerate()
    {
        output[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    output
}

fn rol8(input: u8, count: u32) -> u8 {
    input.rotate_left(count)
}

/// Computes the SAP hash used by FairPlay key derivation.
///
/// The transform intentionally follows the byte-level ordering FairPlay uses and
/// in-place reverse scramble. All additions and XORs are performed on the
/// 16-byte result after the garbling stage.
pub(crate) fn sap_hash(block: &[u8; 64]) -> [u8; 16] {
    const BUFFER0: [u8; 20] = [
        0x96, 0x5f, 0xc6, 0x53, 0xf8, 0x46, 0xcc, 0x18, 0xdf, 0xbe, 0xb2, 0xf8, 0x38, 0xd7, 0xec,
        0x22, 0x03, 0xd1, 0x20, 0x8f,
    ];
    const BUFFER2: [u8; 35] = [
        0x43, 0x54, 0x62, 0x7a, 0x18, 0xc3, 0xd6, 0xb3, 0x9a, 0x56, 0xf6, 0x1c, 0x14, 0x3f, 0x0c,
        0x1d, 0x3b, 0x36, 0x83, 0xb1, 0x39, 0x51, 0x4a, 0xaa, 0x09, 0x3e, 0xfe, 0x44, 0xaf, 0xde,
        0xc3, 0x20, 0x9d, 0x42, 0x3a,
    ];
    const BUFFER4: [u8; 21] = [
        0xed, 0x25, 0xd1, 0xbb, 0xbc, 0x27, 0x9f, 0x02, 0xa2, 0xa9, 0x11, 0x00, 0x0c, 0xb3, 0x52,
        0xc0, 0xbd, 0xe3, 0x1b, 0x49, 0xc7,
    ];
    const MIX_INDICES: [usize; 11] = [18, 22, 23, 0, 5, 19, 32, 31, 10, 21, 30];

    let mut buffer0 = BUFFER0;
    let mut buffer1 = sap_scramble(block);
    let mut buffer2 = BUFFER2;
    let mut buffer3 = [0u8; 132];
    let mut buffer4 = BUFFER4;
    super::hand_garble_generated::hand_garble_bytes(
        &mut buffer0,
        &mut buffer1,
        &mut buffer2,
        &mut buffer3,
        &mut buffer4,
    );

    let mut key = [0xe1u8; 16];
    for (index, &source) in MIX_INDICES.iter().enumerate() {
        key[index] = if index == 3 {
            0x3d
        } else {
            key[index].wrapping_add(buffer3[source * 4])
        };
    }
    for (index, &value) in buffer0.iter().enumerate() {
        key[index % 16] ^= value;
    }
    for (index, &value) in buffer2.iter().enumerate() {
        key[index % 16] ^= value;
    }
    for (index, &value) in buffer1.iter().enumerate() {
        key[index % 16] ^= value;
    }
    for _ in 0..16 {
        for index in 0..16 {
            let x = key[(index + 16 - 7) % 16];
            let y = key[index];
            let z = key[(index + 16 - 37 % 16) % 16];
            let w = key[(index + 16 - 177 % 16) % 16];
            key[index] = rol8(x, 1) ^ y ^ rol8(z, 6) ^ rol8(w, 5);
        }
    }
    key
}

fn table_s1(round: usize) -> &'static [u8] {
    let offset = ((31 * round) % 40) * 256;
    &crate::playfair_tables::TABLE_S1[offset..offset + 256]
}

fn table_s4(round: usize) -> &'static [u8] {
    let offset = ((71 * round) % 144) * 256;
    &crate::playfair_tables::TABLE_S4[offset..offset + 256]
}

fn permute_block_1(block: &mut [u8; 16]) {
    let table = crate::playfair_tables::TABLE_S3;
    block[0] = table[usize::from(block[0])];
    block[4] = table[0x400 + usize::from(block[4])];
    block[8] = table[0x800 + usize::from(block[8])];
    block[12] = table[0xc00 + usize::from(block[12])];
    let tmp = block[13];
    block[13] = table[0x100 + usize::from(block[9])];
    block[9] = table[0xd00 + usize::from(block[5])];
    block[5] = table[0x900 + usize::from(block[1])];
    block[1] = table[0x500 + usize::from(tmp)];
    let tmp = block[2];
    block[2] = table[0xa00 + usize::from(block[10])];
    block[10] = table[0x200 + usize::from(tmp)];
    let tmp = block[6];
    block[6] = table[0xe00 + usize::from(block[14])];
    block[14] = table[0x600 + usize::from(tmp)];
    let tmp = block[3];
    block[3] = table[0xf00 + usize::from(block[7])];
    block[7] = table[0x300 + usize::from(block[11])];
    block[11] = table[0x700 + usize::from(block[15])];
    block[15] = table[0xb00 + usize::from(tmp)];
}

fn permute_block_2(block: &mut [u8; 16], round: usize) {
    let table = |index: usize| table_s4(round * 16 + index);
    block[0] = table(0)[usize::from(block[0])];
    block[4] = table(4)[usize::from(block[4])];
    block[8] = table(8)[usize::from(block[8])];
    block[12] = table(12)[usize::from(block[12])];
    let tmp = block[13];
    block[13] = table(13)[usize::from(block[9])];
    block[9] = table(9)[usize::from(block[5])];
    block[5] = table(5)[usize::from(block[1])];
    block[1] = table(1)[usize::from(tmp)];
    let tmp = block[2];
    block[2] = table(2)[usize::from(block[10])];
    block[10] = table(10)[usize::from(tmp)];
    let tmp = block[6];
    block[6] = table(6)[usize::from(block[14])];
    block[14] = table(14)[usize::from(tmp)];
    let tmp = block[3];
    block[3] = table(3)[usize::from(block[7])];
    block[7] = table(7)[usize::from(block[11])];
    block[11] = table(11)[usize::from(block[15])];
    block[15] = table(15)[usize::from(tmp)];
}

pub(crate) fn generate_key_schedule(key_material: &[u8; 16]) -> [[u32; 4]; 11] {
    let mut key_data = [0u32; 4];
    let mut bytes = [0u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = key_material[index] ^ crate::playfair_tables::T_KEY[index];
    }
    for (word, chunk) in key_data.iter_mut().zip(bytes.chunks_exact(4)) {
        *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    let index_mangle = [1u8, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c];
    let mut schedule = [[0u32; 4]; 11];
    for round in 0..11 {
        schedule[round][0] = key_data[0];
        let tables = [
            table_s1(round * 4),
            table_s1(round * 4 + 1),
            table_s1(round * 4 + 2),
            table_s1(round * 4 + 3),
        ];
        for (chunk, word) in bytes.chunks_exact_mut(4).zip(key_data) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        let old = bytes;
        bytes[0] ^= tables[0][usize::from(old[13])] ^ index_mangle[round];
        bytes[1] ^= tables[1][usize::from(old[14])];
        bytes[2] ^= tables[2][usize::from(old[15])];
        bytes[3] ^= tables[3][usize::from(old[12])];
        key_data[0] = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        schedule[round][1] = key_data[1];
        key_data[1] ^= key_data[0];
        schedule[round][2] = key_data[2];
        key_data[2] ^= key_data[1];
        schedule[round][3] = key_data[3];
        key_data[3] ^= key_data[2];
    }
    schedule
}

pub(crate) fn cycle(mut block: [u8; 16], schedule: &[[u32; 4]; 11]) -> [u8; 16] {
    for (chunk, word) in block.chunks_exact_mut(4).zip(schedule[10]) {
        let value = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) ^ word;
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    permute_block_1(&mut block);
    for round in 0..9 {
        let key = schedule[9 - round].map(u32::to_le_bytes);
        let word0 = crate::playfair_tables::TABLE_S5[usize::from(block[3] ^ key[0][3])]
            ^ crate::playfair_tables::TABLE_S6[usize::from(block[2] ^ key[0][2])]
            ^ crate::playfair_tables::TABLE_S8[usize::from(block[0] ^ key[0][0])]
            ^ crate::playfair_tables::TABLE_S7[usize::from(block[1] ^ key[0][1])];
        block[0..4].copy_from_slice(&word0.to_le_bytes());
        let word1 = crate::playfair_tables::TABLE_S5[usize::from(block[7] ^ key[1][3])]
            ^ crate::playfair_tables::TABLE_S6[usize::from(block[6] ^ key[1][2])]
            ^ crate::playfair_tables::TABLE_S7[usize::from(block[5] ^ key[1][1])]
            ^ crate::playfair_tables::TABLE_S8[usize::from(block[4] ^ key[1][0])];
        block[4..8].copy_from_slice(&word1.to_le_bytes());
        let word2 = crate::playfair_tables::TABLE_S5[usize::from(block[11] ^ key[2][3])]
            ^ crate::playfair_tables::TABLE_S6[usize::from(block[10] ^ key[2][2])]
            ^ crate::playfair_tables::TABLE_S7[usize::from(block[9] ^ key[2][1])]
            ^ crate::playfair_tables::TABLE_S8[usize::from(block[8] ^ key[2][0])];
        block[8..12].copy_from_slice(&word2.to_le_bytes());
        let word3 = crate::playfair_tables::TABLE_S5[usize::from(block[15] ^ key[3][3])]
            ^ crate::playfair_tables::TABLE_S6[usize::from(block[14] ^ key[3][2])]
            ^ crate::playfair_tables::TABLE_S7[usize::from(block[13] ^ key[3][1])]
            ^ crate::playfair_tables::TABLE_S8[usize::from(block[12] ^ key[3][0])];
        block[12..16].copy_from_slice(&word3.to_le_bytes());
        permute_block_2(&mut block, 8 - round);
    }
    for (chunk, word) in block.chunks_exact_mut(4).zip(schedule[0]) {
        let value = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) ^ word;
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    block
}

fn message_key(mode: usize, index: usize) -> u8 {
    crate::playfair_tables::MESSAGE_KEY[mode * 144 + index]
}

fn message_iv(mode: usize) -> &'static [u8] {
    &crate::playfair_tables::MESSAGE_IV[mode * 16..mode * 16 + 16]
}

/// Decrypt the eight 16-byte PlayFair message blocks for one protocol mode.
///
/// The input includes the 16-byte header followed by a 128-byte encrypted message body; byte 12 selects
/// mode 0 through 3, as `decryptMessage` does.
pub(crate) fn decrypt_message(message: &[u8; 144]) -> Option<[u8; 128]> {
    let mode = usize::from(message[12]);
    if mode > 3 {
        return None;
    }
    let mut decrypted = [0u8; 128];
    for block_index in 0..8 {
        let mut block = [0u8; 16];
        let source = if mode == 3 {
            0x80 - 0x10 * block_index
        } else {
            0x10 * (block_index + 1)
        };
        block.copy_from_slice(&message[source..source + 16]);
        for round in 0..9 {
            let base = 0x80 - 0x10 * round;
            let table = |index: usize| {
                let offset = ((97 * index) % 144) * 256;
                &crate::playfair_tables::TABLE_S2[offset..offset + 256]
            };
            block[0] = table(base)[usize::from(block[0])] ^ message_key(mode, base);
            block[4] = table(base + 4)[usize::from(block[4])] ^ message_key(mode, base + 4);
            block[8] = table(base + 8)[usize::from(block[8])] ^ message_key(mode, base + 8);
            block[12] = table(base + 12)[usize::from(block[12])] ^ message_key(mode, base + 12);
            let tmp = block[13];
            block[13] = table(base + 13)[usize::from(block[9])] ^ message_key(mode, base + 13);
            block[9] = table(base + 9)[usize::from(block[5])] ^ message_key(mode, base + 9);
            block[5] = table(base + 5)[usize::from(block[1])] ^ message_key(mode, base + 5);
            block[1] = table(base + 1)[usize::from(tmp)] ^ message_key(mode, base + 1);
            let tmp = block[2];
            block[2] = table(base + 2)[usize::from(block[10])] ^ message_key(mode, base + 2);
            block[10] = table(base + 10)[usize::from(tmp)] ^ message_key(mode, base + 10);
            let tmp = block[6];
            block[6] = table(base + 6)[usize::from(block[14])] ^ message_key(mode, base + 6);
            block[14] = table(base + 14)[usize::from(tmp)] ^ message_key(mode, base + 14);
            let tmp = block[3];
            block[3] = table(base + 3)[usize::from(block[7])] ^ message_key(mode, base + 3);
            block[7] = table(base + 7)[usize::from(block[11])] ^ message_key(mode, base + 7);
            block[11] = table(base + 11)[usize::from(block[15])] ^ message_key(mode, base + 11);
            block[15] = table(base + 15)[usize::from(tmp)] ^ message_key(mode, base + 15);
            let words = [
                crate::playfair_tables::TABLE_S9[usize::from(block[0])]
                    ^ crate::playfair_tables::TABLE_S9[0x100 + usize::from(block[1])]
                    ^ crate::playfair_tables::TABLE_S9[0x200 + usize::from(block[2])]
                    ^ crate::playfair_tables::TABLE_S9[0x300 + usize::from(block[3])],
                crate::playfair_tables::TABLE_S9[usize::from(block[4])]
                    ^ crate::playfair_tables::TABLE_S9[0x100 + usize::from(block[5])]
                    ^ crate::playfair_tables::TABLE_S9[0x200 + usize::from(block[6])]
                    ^ crate::playfair_tables::TABLE_S9[0x300 + usize::from(block[7])],
                crate::playfair_tables::TABLE_S9[usize::from(block[8])]
                    ^ crate::playfair_tables::TABLE_S9[0x100 + usize::from(block[9])]
                    ^ crate::playfair_tables::TABLE_S9[0x200 + usize::from(block[10])]
                    ^ crate::playfair_tables::TABLE_S9[0x300 + usize::from(block[11])],
                crate::playfair_tables::TABLE_S9[usize::from(block[12])]
                    ^ crate::playfair_tables::TABLE_S9[0x100 + usize::from(block[13])]
                    ^ crate::playfair_tables::TABLE_S9[0x200 + usize::from(block[14])]
                    ^ crate::playfair_tables::TABLE_S9[0x300 + usize::from(block[15])],
            ];
            for (chunk, word) in block.chunks_exact_mut(4).zip(words) {
                chunk.copy_from_slice(&word.to_le_bytes());
            }
        }
        let table =
            |index: usize| &crate::playfair_tables::TABLE_S10[index * 256..index * 256 + 256];
        block[0] = table(0)[usize::from(block[0])];
        block[4] = table(4)[usize::from(block[4])];
        block[8] = table(8)[usize::from(block[8])];
        block[12] = table(12)[usize::from(block[12])];
        let tmp = block[13];
        block[13] = table(13)[usize::from(block[9])];
        block[9] = table(9)[usize::from(block[5])];
        block[5] = table(5)[usize::from(block[1])];
        block[1] = table(1)[usize::from(tmp)];
        let tmp = block[2];
        block[2] = table(2)[usize::from(block[10])];
        block[10] = table(10)[usize::from(tmp)];
        let tmp = block[6];
        block[6] = table(6)[usize::from(block[14])];
        block[14] = table(14)[usize::from(tmp)];
        let tmp = block[3];
        block[3] = table(3)[usize::from(block[7])];
        block[7] = table(7)[usize::from(block[11])];
        block[11] = table(11)[usize::from(block[15])];
        block[15] = table(15)[usize::from(tmp)];
        let destination = if mode == 3 {
            0x70 - 0x10 * block_index
        } else {
            0x10 * block_index
        };
        let previous = if mode == 3 {
            if block_index < 7 {
                &message[0x70 - 0x10 * block_index..0x80 - 0x10 * block_index]
            } else {
                message_iv(mode)
            }
        } else if block_index > 0 {
            &message[0x10 * block_index..0x10 * (block_index + 1)]
        } else {
            message_iv(mode)
        };
        for index in 0..16 {
            decrypted[destination + index] = block[index] ^ previous[index];
        }
    }
    Some(decrypted)
}
