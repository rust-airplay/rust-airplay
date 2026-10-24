// SPDX-License-Identifier: LGPL-2.1-or-later
//! The FairPlay hand garbling transform.
//!
//! Buffers use `i128` slots to model C's integer promotions; each write is truncated to one
//! byte exactly as an `unsigned char` assignment.
//!
//! Comments inside the translated body are the protocol author's, kept verbatim so the
//! transcription stays checkable against its source. They are not this project's voice.

#![allow(clippy::all, non_snake_case, unused_mut, unused_parens)]

fn rol8(input: i128, count: i128) -> i128 {
    if count == 0 {
        return input & 0xff;
    }
    ((input << count) | (input >> (8 - count))) & 0xff
}

fn rol8x(input: i128, count: i128) -> i128 {
    if count == 0 {
        return input;
    }
    (input << count) | (input >> (8 - count))
}

fn weird_ror8(input: i128, count: i128) -> i128 {
    if count == 0 {
        return 0;
    }
    ((input >> count) & 0xff) | ((input & 0xff) << (8 - count))
}

fn weird_rol8(input: i128, count: i128) -> i128 {
    if count == 0 {
        return 0;
    }
    ((input << count) & 0xff) | ((input & 0xff) >> (8 - count))
}

fn weird_rol32(input: i128, count: i128) -> i128 {
    if count == 0 {
        return 0;
    }
    (input << count) ^ (input >> (8 - count))
}

pub(crate) fn hand_garble(
    buffer0: &mut [i128; 20],
    buffer1: &mut [i128; 210],
    buffer2: &mut [i128; 35],
    buffer3: &mut [i128; 132],
    buffer4: &mut [i128; 21],
) {
    let mut tmp: i128;
    let mut tmp2: i128;
    let mut tmp3: i128;
    let mut A: i128;
    let mut B: i128;
    let mut C: i128;
    let mut D: i128;
    let mut E: i128;
    let mut M: i128;
    let mut J: i128;
    let mut G: i128;
    let mut F: i128;
    let mut H: i128;
    let mut K: i128;
    let mut R: i128;
    let mut S: i128;
    let mut T: i128;
    let mut U: i128;
    let mut V: i128;
    let mut W: i128;
    let mut X: i128;
    let mut Y: i128;
    let mut Z: i128;
    // buffer1[((64) & 0xffff_ffffi128) as usize] = (A
    // (buffer1[((99) & 0xffff_ffffi128) as usize] / 3) = B
    // 0ABAAABB
    // Then we AND with a complex expression, and add 20 just for good measure
    buffer2[((12) & 0xffff_ffffi128) as usize] = (0x14
        + (((buffer1[((64) & 0xffff_ffffi128) as usize] & 92)
            | ((buffer1[((99) & 0xffff_ffffi128) as usize] / 3) & 35))
            & buffer4[((rol8x(buffer4[((buffer1[206] % 21) & 0xffff_ffffi128) as usize], 4) % 21)
                & 0xffff_ffffi128) as usize]))
        & 0xff;

    // This is a bit simpler: 2*B*B/25
    buffer1[((4) & 0xffff_ffffi128) as usize] = ((buffer1[((99) & 0xffff_ffffi128) as usize] / 5)
        * (buffer1[((99) & 0xffff_ffffi128) as usize] / 5)
        * 2)
        & 0xff;

    // Simpler still!
    buffer2[((34) & 0xffff_ffffi128) as usize] = (0xb8) & 0xff;

    // ...
    buffer1[((153) & 0xffff_ffffi128) as usize] = ((buffer1[((153) & 0xffff_ffffi128) as usize]
        ^ (buffer2[((buffer1[203] % 35) & 0xffff_ffffi128) as usize]
            * buffer2[((buffer1[203] % 35) & 0xffff_ffffi128) as usize]
            * buffer1[((190) & 0xffff_ffffi128) as usize]))
        & 0xff)
        & 0xff;

    // This one looks simple, but wow was it not :(
    buffer0[((3) & 0xffff_ffffi128) as usize] = ((buffer0[((3) & 0xffff_ffffi128) as usize]
        - (((buffer4[((buffer1[205] % 21) & 0xffff_ffffi128) as usize] >> 1) & 80) | 0xe6440))
        & 0xff)
        & 0xff;

    // This is always 0x93
    buffer0[((16) & 0xffff_ffffi128) as usize] = (0x93) & 0xff;

    // This is always 0x62
    buffer0[((13) & 0xffff_ffffi128) as usize] = (0x62) & 0xff;

    buffer1[((33) & 0xffff_ffffi128) as usize] = ((buffer1[((33) & 0xffff_ffffi128) as usize]
        - (buffer4[((buffer1[36] % 21) & 0xffff_ffffi128) as usize] & 0xf6))
        & 0xff)
        & 0xff;

    // This is always 7
    tmp2 = buffer2[((buffer1[67] % 35) & 0xffff_ffffi128) as usize];
    buffer2[((12) & 0xffff_ffffi128) as usize] = (0x07) & 0xff;

    // This is pretty easy!
    tmp = buffer0[((buffer1[181] % 20) & 0xffff_ffffi128) as usize];
    buffer1[((2) & 0xffff_ffffi128) as usize] =
        ((buffer1[((2) & 0xffff_ffffi128) as usize] - (3136)) & 0xff) & 0xff;

    buffer0[((19) & 0xffff_ffffi128) as usize] =
        (buffer4[((buffer1[58] % 21) & 0xffff_ffffi128) as usize]) & 0xff;

    buffer3[((0) & 0xffff_ffffi128) as usize] =
        (92 - buffer2[((buffer1[32] % 35) & 0xffff_ffffi128) as usize]) & 0xff;

    buffer3[((4) & 0xffff_ffffi128) as usize] =
        (buffer2[((buffer1[15] % 35) & 0xffff_ffffi128) as usize] + 0x9e) & 0xff;

    buffer1[((34) & 0xffff_ffffi128) as usize] = ((buffer1[((34) & 0xffff_ffffi128) as usize]
        + (buffer4[((((buffer2[((buffer1[15] % 35) & 0xffff_ffffi128) as usize] + 0x9e) & 0xff)
            % 21)
            & 0xffff_ffffi128) as usize]
            / 5))
        & 0xff)
        & 0xff;

    buffer0[((19) & 0xffff_ffffi128) as usize] = ((buffer0[((19) & 0xffff_ffffi128) as usize]
        + (0xfffffee6 - ((buffer0[((buffer3[4] % 20) & 0xffff_ffffi128) as usize] >> 1) & 102)))
        & 0xff)
        & 0xff;

    // This LOOKS like it should be a rol8x, but it just doesnt work out because if the shift amount is 0, then the output is 0 too :(
    // FIXME: Switch to weird_ror8
    buffer1[((15) & 0xffff_ffffi128) as usize] = ((3
        * (((buffer1[((72) & 0xffff_ffffi128) as usize]
            >> (buffer4[((buffer1[190] % 21) & 0xffff_ffffi128) as usize] & 7))
            ^ (buffer1[((72) & 0xffff_ffffi128) as usize]
                << (7 - (buffer4[((buffer1[190] % 21) & 0xffff_ffffi128) as usize] - 1) & 7)))
            - (3 * buffer4[((buffer1[126] % 21) & 0xffff_ffffi128) as usize])))
        ^ buffer1[((15) & 0xffff_ffffi128) as usize])
        & 0xff;

    buffer0[((15) & 0xffff_ffffi128) as usize] = ((buffer0[((15) & 0xffff_ffffi128) as usize]
        ^ (buffer2[((buffer1[181] % 35) & 0xffff_ffffi128) as usize]
            * buffer2[((buffer1[181] % 35) & 0xffff_ffffi128) as usize]
            * buffer2[((buffer1[181] % 35) & 0xffff_ffffi128) as usize]))
        & 0xff)
        & 0xff;

    buffer2[((4) & 0xffff_ffffi128) as usize] = ((buffer2[((4) & 0xffff_ffffi128) as usize]
        ^ (buffer1[((202) & 0xffff_ffffi128) as usize] / 3))
        & 0xff)
        & 0xff;

    // This could probably be quite a bit simpler.
    A = 92 - buffer0[((buffer3[0] % 20) & 0xffff_ffffi128) as usize];
    E = (A & 0xc6)
        | (!buffer1[((105) & 0xffff_ffffi128) as usize] & 0xc6)
        | (A & (!buffer1[((105) & 0xffff_ffffi128) as usize]));
    buffer2[((1) & 0xffff_ffffi128) as usize] =
        ((buffer2[((1) & 0xffff_ffffi128) as usize] + (E * E * E)) & 0xff) & 0xff;

    buffer0[((19) & 0xffff_ffffi128) as usize] = ((buffer0[((19) & 0xffff_ffffi128) as usize]
        ^ (((224 | (buffer4[((buffer1[92] % 21) & 0xffff_ffffi128) as usize] & 27))
            * buffer2[((buffer1[41] % 35) & 0xffff_ffffi128) as usize])
            / 3))
        & 0xff)
        & 0xff;

    buffer1[((140) & 0xffff_ffffi128) as usize] = ((buffer1[((140) & 0xffff_ffffi128) as usize]
        + (weird_ror8(92, buffer1[((5) & 0xffff_ffffi128) as usize] & 7)))
        & 0xff)
        & 0xff;

    // Is this as simple as it could be?
    buffer2[((12) & 0xffff_ffffi128) as usize] = ((buffer2[((12) & 0xffff_ffffi128) as usize]
        + (((((!buffer1[((4) & 0xffff_ffffi128) as usize])
            ^ buffer2[((buffer1[12] % 35) & 0xffff_ffffi128) as usize])
            | buffer1[((182) & 0xffff_ffffi128) as usize])
            & 192)
            | (((!buffer1[((4) & 0xffff_ffffi128) as usize])
                ^ buffer2[((buffer1[12] % 35) & 0xffff_ffffi128) as usize])
                & buffer1[((182) & 0xffff_ffffi128) as usize])))
        & 0xff)
        & 0xff;

    buffer1[((36) & 0xffff_ffffi128) as usize] =
        ((buffer1[((36) & 0xffff_ffffi128) as usize] + (125)) & 0xff) & 0xff;

    buffer1[((124) & 0xffff_ffffi128) as usize] = (rol8x(
        (((74 & buffer1[((138) & 0xffff_ffffi128) as usize])
            | ((74 | buffer1[((138) & 0xffff_ffffi128) as usize])
                & buffer0[((15) & 0xffff_ffffi128) as usize]))
            & buffer0[((buffer1[43] % 20) & 0xffff_ffffi128) as usize])
            | (((74 & buffer1[((138) & 0xffff_ffffi128) as usize])
                | ((74 | buffer1[((138) & 0xffff_ffffi128) as usize])
                    & buffer0[((15) & 0xffff_ffffi128) as usize])
                | buffer0[((buffer1[43] % 20) & 0xffff_ffffi128) as usize])
                & 95),
        4,
    )) & 0xff;

    buffer3[((8) & 0xffff_ffffi128) as usize] =
        ((((buffer0[((buffer3[4] % 20) & 0xffff_ffffi128) as usize] & 95)
            & ((buffer4[((buffer1[68] % 21) & 0xffff_ffffi128) as usize] & 46) << 1))
            | 16)
            ^ 92)
            & 0xff;

    A = buffer1[((177) & 0xffff_ffffi128) as usize]
        + buffer4[((buffer1[79] % 21) & 0xffff_ffffi128) as usize];
    D = (((A >> 1) | ((3 * buffer1[((148) & 0xffff_ffffi128) as usize]) / 5))
        & buffer2[((1) & 0xffff_ffffi128) as usize])
        | ((A >> 1) & ((3 * buffer1[((148) & 0xffff_ffffi128) as usize]) / 5));
    buffer3[((12) & 0xffff_ffffi128) as usize] = (0i128.wrapping_sub(34).wrapping_sub(D)) & 0xff;

    A = 8 - (buffer2[((22) & 0xffff_ffffi128) as usize] & 7); // FIXME: buffer2[((22) & 0xffff_ffffi128) as usize] = (74, so A is always 6 and B^C is just ror8(buffer1[((33) & 0xffff_ffffi128) as usize], 6)
    B = (buffer1[((33) & 0xffff_ffffi128) as usize] >> (A & 7)) & 0xff;
    C = buffer1[((33) & 0xffff_ffffi128) as usize]
        << (buffer2[((22) & 0xffff_ffffi128) as usize] & 7);
    buffer2[((16) & 0xffff_ffffi128) as usize] = ((buffer2[((16) & 0xffff_ffffi128) as usize]
        + (((buffer2[((buffer3[0] % 35) & 0xffff_ffffi128) as usize] & 159)
            | buffer0[((buffer3[4] % 20) & 0xffff_ffffi128) as usize]
            | 8)
            - ((B ^ C) | 128)))
        & 0xff)
        & 0xff;

    // This one was very easy so I just skipped ahead and did it
    buffer0[((14) & 0xffff_ffffi128) as usize] = ((buffer0[((14) & 0xffff_ffffi128) as usize]
        ^ (buffer2[((buffer3[12] % 35) & 0xffff_ffffi128) as usize]))
        & 0xff)
        & 0xff;

    // Monster goes here
    A = weird_rol8(
        buffer4[((buffer0[((buffer1[201] % 20) & 0xffff_ffffi128) as usize] % 21) & 0xffff_ffffi128)
            as usize],
        ((buffer2[((buffer1[112] % 35) & 0xffff_ffffi128) as usize] << 1) & 7),
    );
    D = (buffer0[((buffer1[208] % 20) & 0xffff_ffffi128) as usize] & 131)
        | (buffer0[((buffer1[164] % 20) & 0xffff_ffffi128) as usize] & 124);
    buffer1[((19) & 0xffff_ffffi128) as usize] = ((buffer1[((19) & 0xffff_ffffi128) as usize]
        + ((A & (D / 5)) | ((A | (D / 5)) & 37)))
        & 0xff)
        & 0xff;

    buffer2[((8) & 0xffff_ffffi128) as usize] = (weird_ror8(
        140,
        ((buffer4[((buffer1[45] % 21) & 0xffff_ffffi128) as usize] + 92)
            * (buffer4[((buffer1[45] % 21) & 0xffff_ffffi128) as usize] + 92))
            & 7,
    )) & 0xff;

    buffer1[((190) & 0xffff_ffffi128) as usize] = (56) & 0xff;

    buffer2[((8) & 0xffff_ffffi128) as usize] = ((buffer2[((8) & 0xffff_ffffi128) as usize]
        ^ (buffer3[((0) & 0xffff_ffffi128) as usize]))
        & 0xff)
        & 0xff;

    buffer1[((53) & 0xffff_ffffi128) as usize] =
        (!((buffer0[((buffer1[83] % 20) & 0xffff_ffffi128) as usize] | 204) / 5)) & 0xff;

    buffer0[((13) & 0xffff_ffffi128) as usize] = ((buffer0[((13) & 0xffff_ffffi128) as usize]
        + (buffer0[((buffer1[41] % 20) & 0xffff_ffffi128) as usize]))
        & 0xff)
        & 0xff;

    buffer0[((10) & 0xffff_ffffi128) as usize] = (((buffer2
        [((buffer3[((0) & 0xffff_ffffi128) as usize] % 35) & 0xffff_ffffi128) as usize]
        & buffer1[((2) & 0xffff_ffffi128) as usize])
        | ((buffer2[((buffer3[0] % 35) & 0xffff_ffffi128) as usize]
            | buffer1[((2) & 0xffff_ffffi128) as usize])
            & buffer3[((12) & 0xffff_ffffi128) as usize]))
        / 15)
        & 0xff;

    A = (((56 | (buffer4[((buffer1[2] % 21) & 0xffff_ffffi128) as usize] & 68))
        | buffer2[((buffer3[8] % 35) & 0xffff_ffffi128) as usize])
        & 42)
        | (((buffer4[((buffer1[2] % 21) & 0xffff_ffffi128) as usize] & 68) | 56)
            & buffer2[((buffer3[8] % 35) & 0xffff_ffffi128) as usize]);
    buffer3[((16) & 0xffff_ffffi128) as usize] = ((A * A) + 110) & 0xff;

    buffer3[((20) & 0xffff_ffffi128) as usize] =
        (202 - buffer3[((16) & 0xffff_ffffi128) as usize]) & 0xff;

    buffer3[((24) & 0xffff_ffffi128) as usize] =
        (buffer1[((151) & 0xffff_ffffi128) as usize]) & 0xff;

    buffer2[((13) & 0xffff_ffffi128) as usize] = ((buffer2[((13) & 0xffff_ffffi128) as usize]
        ^ (buffer4[((buffer3[0] % 21) & 0xffff_ffffi128) as usize]))
        & 0xff)
        & 0xff;

    B = ((buffer2[((buffer1[179] % 35) & 0xffff_ffffi128) as usize] - 38) & 177)
        | (buffer3[((12) & 0xffff_ffffi128) as usize] & 177);
    C = (buffer2[((buffer1[179] % 35) & 0xffff_ffffi128) as usize] - 38)
        & buffer3[((12) & 0xffff_ffffi128) as usize];
    buffer3[((28) & 0xffff_ffffi128) as usize] = (30 + ((B | C) * (B | C))) & 0xff;

    buffer3[((32) & 0xffff_ffffi128) as usize] =
        (buffer3[((28) & 0xffff_ffffi128) as usize] + 62) & 0xff;

    // eek
    A = ((buffer3[((20) & 0xffff_ffffi128) as usize]
        + (buffer3[((0) & 0xffff_ffffi128) as usize] & 74))
        | !buffer4[((buffer3[0] % 21) & 0xffff_ffffi128) as usize])
        & 121;
    B = ((buffer3[((20) & 0xffff_ffffi128) as usize]
        + (buffer3[((0) & 0xffff_ffffi128) as usize] & 74))
        & !buffer4[((buffer3[0] % 21) & 0xffff_ffffi128) as usize]);
    tmp3 = (A | B);
    C = ((((A | B) ^ 0xffffffa6) | buffer3[((0) & 0xffff_ffffi128) as usize]) & 4)
        | (((A | B) ^ 0xffffffa6) & buffer3[((0) & 0xffff_ffffi128) as usize]);
    buffer1[((47) & 0xffff_ffffi128) as usize] =
        ((buffer2[((buffer1[89] % 35) & 0xffff_ffffi128) as usize] + C)
            ^ buffer1[((47) & 0xffff_ffffi128) as usize])
            & 0xff;

    buffer3[((36) & 0xffff_ffffi128) as usize] = (((rol8((tmp & 179) + 68, 2)
        & buffer0[((3) & 0xffff_ffffi128) as usize])
        | (tmp2 & !buffer0[((3) & 0xffff_ffffi128) as usize]))
        - 15)
        & 0xff;

    buffer1[((123) & 0xffff_ffffi128) as usize] =
        ((buffer1[((123) & 0xffff_ffffi128) as usize] ^ (221)) & 0xff) & 0xff;

    A = ((buffer4[((buffer3[0] % 21) & 0xffff_ffffi128) as usize]) / 3)
        - buffer2[((buffer3[4] % 35) & 0xffff_ffffi128) as usize];
    C = (((buffer3[((0) & 0xffff_ffffi128) as usize] & 163) + 92) & 246)
        | (buffer3[((0) & 0xffff_ffffi128) as usize] & 92);
    E = ((C | buffer3[((24) & 0xffff_ffffi128) as usize]) & 54)
        | (C & buffer3[((24) & 0xffff_ffffi128) as usize]);
    buffer3[((40) & 0xffff_ffffi128) as usize] = (A - E) & 0xff;

    buffer3[((44) & 0xffff_ffffi128) as usize] =
        (tmp3 ^ 81 ^ (((buffer3[((0) & 0xffff_ffffi128) as usize] >> 1) & 101) + 26)) & 0xff;

    buffer3[((48) & 0xffff_ffffi128) as usize] =
        (buffer2[((buffer3[4] % 35) & 0xffff_ffffi128) as usize] & 27) & 0xff;

    buffer3[((52) & 0xffff_ffffi128) as usize] = (27) & 0xff;

    buffer3[((56) & 0xffff_ffffi128) as usize] = (199) & 0xff;

    // caffeine
    buffer3[((64) & 0xffff_ffffi128) as usize] = (buffer3[((4) & 0xffff_ffffi128) as usize]
        + (((((((buffer3[((40) & 0xffff_ffffi128) as usize]
            | buffer3[((24) & 0xffff_ffffi128) as usize])
            & 177)
            | (buffer3[((40) & 0xffff_ffffi128) as usize]
                & buffer3[((24) & 0xffff_ffffi128) as usize]))
            & (((buffer4[((buffer3[0] % 20) & 0xffff_ffffi128) as usize] & 177) | 176)
                | ((buffer4[((buffer3[0] % 21) & 0xffff_ffffi128) as usize]) & !3)))
            | ((((buffer3[((40) & 0xffff_ffffi128) as usize]
                & buffer3[((24) & 0xffff_ffffi128) as usize])
                | ((buffer3[((40) & 0xffff_ffffi128) as usize]
                    | buffer3[((24) & 0xffff_ffffi128) as usize])
                    & 177))
                & 199)
                | ((((buffer4[((buffer3[0] % 21) & 0xffff_ffffi128) as usize] & 1) + 176)
                    | (buffer4[((buffer3[0] % 21) & 0xffff_ffffi128) as usize] & !3))
                    & buffer3[((56) & 0xffff_ffffi128) as usize])))
            & (!buffer3[((52) & 0xffff_ffffi128) as usize]))
            | buffer3[((48) & 0xffff_ffffi128) as usize]))
        & 0xff;

    buffer2[((33) & 0xffff_ffffi128) as usize] = ((buffer2[((33) & 0xffff_ffffi128) as usize]
        ^ (buffer1[((26) & 0xffff_ffffi128) as usize]))
        & 0xff)
        & 0xff;

    buffer1[((106) & 0xffff_ffffi128) as usize] = ((buffer1[((106) & 0xffff_ffffi128) as usize]
        ^ (buffer3[((20) & 0xffff_ffffi128) as usize] ^ 133))
        & 0xff)
        & 0xff;

    buffer2[((30) & 0xffff_ffffi128) as usize] = (((buffer3[((64) & 0xffff_ffffi128) as usize]
        / 3)
        - (275 | (buffer3[((0) & 0xffff_ffffi128) as usize] & 247)))
        ^ buffer0[((buffer1[122] % 20) & 0xffff_ffffi128) as usize])
        & 0xff;

    buffer1[((22) & 0xffff_ffffi128) as usize] =
        ((buffer2[((buffer1[90] % 35) & 0xffff_ffffi128) as usize] & 95) | 68) & 0xff;

    A = (buffer4[((buffer3[36] % 21) & 0xffff_ffffi128) as usize] & 184)
        | (buffer2[((buffer3[44] % 35) & 0xffff_ffffi128) as usize] & !184);
    buffer2[((18) & 0xffff_ffffi128) as usize] =
        ((buffer2[((18) & 0xffff_ffffi128) as usize] + ((A * A * A) >> 1)) & 0xff) & 0xff;

    buffer2[((5) & 0xffff_ffffi128) as usize] = ((buffer2[((5) & 0xffff_ffffi128) as usize]
        - (buffer4[((buffer1[92] % 21) & 0xffff_ffffi128) as usize]))
        & 0xff)
        & 0xff;

    A = (((buffer1[((41) & 0xffff_ffffi128) as usize] & !24)
        | (buffer2[((buffer1[183] % 35) & 0xffff_ffffi128) as usize] & 24))
        & (buffer3[((16) & 0xffff_ffffi128) as usize] + 53))
        | (buffer3[((20) & 0xffff_ffffi128) as usize]
            & buffer2[((buffer3[20] % 35) & 0xffff_ffffi128) as usize]);
    B = (buffer1[((17) & 0xffff_ffffi128) as usize]
        & (!buffer3[((44) & 0xffff_ffffi128) as usize]))
        | (buffer0[((buffer1[59] % 20) & 0xffff_ffffi128) as usize]
            & buffer3[((44) & 0xffff_ffffi128) as usize]);
    buffer2[((18) & 0xffff_ffffi128) as usize] =
        ((buffer2[((18) & 0xffff_ffffi128) as usize] ^ (A * B)) & 0xff) & 0xff;

    A = weird_ror8(
        buffer1[((11) & 0xffff_ffffi128) as usize],
        buffer2[((buffer1[28] % 35) & 0xffff_ffffi128) as usize] & 7,
    ) & 7;
    B = (((buffer0[((buffer1[93] % 20) & 0xffff_ffffi128) as usize]
        & !buffer0[((14) & 0xffff_ffffi128) as usize])
        | (buffer0[((14) & 0xffff_ffffi128) as usize] & 150))
        & !28)
        | (buffer1[((7) & 0xffff_ffffi128) as usize] & 28);
    buffer2[((22) & 0xffff_ffffi128) as usize] =
        (((((B | weird_rol8(buffer2[((buffer3[0] % 35) & 0xffff_ffffi128) as usize], A))
            & buffer2[((33) & 0xffff_ffffi128) as usize])
            | (B & weird_rol8(buffer2[((buffer3[0] % 35) & 0xffff_ffffi128) as usize], A)))
            + 74)
            & 0xff)
            & 0xff;

    A = buffer4[(((buffer0[((buffer1[39] % 20) & 0xffff_ffffi128) as usize] ^ 217) % 21)
        & 0xffff_ffffi128) as usize]; // X5
    buffer0[((15) & 0xffff_ffffi128) as usize] = ((buffer0[((15) & 0xffff_ffffi128) as usize]
        - (((((buffer3[((20) & 0xffff_ffffi128) as usize]
            | buffer3[((0) & 0xffff_ffffi128) as usize])
            & 214)
            | (buffer3[((20) & 0xffff_ffffi128) as usize]
                & buffer3[((0) & 0xffff_ffffi128) as usize]))
            & A)
            | ((((buffer3[((20) & 0xffff_ffffi128) as usize]
                | buffer3[((0) & 0xffff_ffffi128) as usize])
                & 214)
                | (buffer3[((20) & 0xffff_ffffi128) as usize]
                    & buffer3[((0) & 0xffff_ffffi128) as usize])
                | A)
                & buffer3[((32) & 0xffff_ffffi128) as usize])))
        & 0xff)
        & 0xff;

    // We need to save T here, and boy is it complicated to calculate!
    B = (((buffer2[((buffer1[57] % 35) & 0xffff_ffffi128) as usize]
        & buffer0[((buffer3[64] % 20) & 0xffff_ffffi128) as usize])
        | ((buffer0[((buffer3[64] % 20) & 0xffff_ffffi128) as usize]
            | buffer2[((buffer1[57] % 35) & 0xffff_ffffi128) as usize])
            & 95)
        | (buffer3[((64) & 0xffff_ffffi128) as usize] & 45)
        | 82)
        & 32);
    C = ((buffer2[((buffer1[57] % 35) & 0xffff_ffffi128) as usize]
        & buffer0[((buffer3[64] % 20) & 0xffff_ffffi128) as usize])
        | ((buffer2[((buffer1[57] % 35) & 0xffff_ffffi128) as usize]
            | buffer0[((buffer3[64] % 20) & 0xffff_ffffi128) as usize])
            & 95))
        & ((buffer3[((64) & 0xffff_ffffi128) as usize] & 45) | 82);
    D = (((buffer3[((0) & 0xffff_ffffi128) as usize] / 3)
        - (buffer3[((64) & 0xffff_ffffi128) as usize]
            | buffer1[((22) & 0xffff_ffffi128) as usize]))
        ^ (buffer3[((28) & 0xffff_ffffi128) as usize] + 62)
        ^ (B | C));
    T = buffer0[(((D & 0xff) % 20) & 0xffff_ffffi128) as usize];

    buffer3[((68) & 0xffff_ffffi128) as usize] = ((buffer0
        [((buffer1[((99) & 0xffff_ffffi128) as usize] % 20) & 0xffff_ffffi128) as usize]
        * buffer0[((buffer1[99] % 20) & 0xffff_ffffi128) as usize]
        * buffer0[((buffer1[99] % 20) & 0xffff_ffffi128) as usize]
        * buffer0[((buffer1[99] % 20) & 0xffff_ffffi128) as usize])
        | buffer2[((buffer3[64] % 35) & 0xffff_ffffi128) as usize])
        & 0xff;

    U = buffer0[((buffer1[50] % 20) & 0xffff_ffffi128) as usize]; // this is also v100
    W = buffer2[((buffer1[138] % 35) & 0xffff_ffffi128) as usize];
    X = buffer4[((buffer1[39] % 21) & 0xffff_ffffi128) as usize];
    Y = buffer0[((buffer1[4] % 20) & 0xffff_ffffi128) as usize]; // this is also v120
    Z = buffer4[((buffer1[202] % 21) & 0xffff_ffffi128) as usize]; // also v124
    V = buffer0[((buffer1[151] % 20) & 0xffff_ffffi128) as usize];
    S = buffer2[((buffer1[14] % 35) & 0xffff_ffffi128) as usize];
    R = buffer0[((buffer1[145] % 20) & 0xffff_ffffi128) as usize];

    A = (buffer2[((buffer3[68] % 35) & 0xffff_ffffi128) as usize]
        & buffer0[((buffer1[209] % 20) & 0xffff_ffffi128) as usize])
        | ((buffer2[((buffer3[68] % 35) & 0xffff_ffffi128) as usize]
            | buffer0[((buffer1[209] % 20) & 0xffff_ffffi128) as usize])
            & 24);
    B = weird_rol8(
        buffer4[((buffer1[127] % 21) & 0xffff_ffffi128) as usize],
        buffer2[((buffer3[68] % 35) & 0xffff_ffffi128) as usize] & 7,
    );
    C = (A & buffer0[((10) & 0xffff_ffffi128) as usize])
        | (B & !buffer0[((10) & 0xffff_ffffi128) as usize]);
    D = 7
        ^ (buffer4[((buffer2[((buffer3[36] % 35) & 0xffff_ffffi128) as usize] % 21)
            & 0xffff_ffffi128) as usize]
            << 1);
    buffer3[((72) & 0xffff_ffffi128) as usize] = ((C & 71) | (D & !71)) & 0xff;

    buffer2[((2) & 0xffff_ffffi128) as usize] = ((buffer2[((2) & 0xffff_ffffi128) as usize]
        + ((((buffer0[((buffer3[20] % 20) & 0xffff_ffffi128) as usize] << 1) & 159)
            | (buffer4[((buffer1[190] % 21) & 0xffff_ffffi128) as usize] & !159))
            & ((((buffer4[((buffer3[64] % 21) & 0xffff_ffffi128) as usize] & 110)
                | (buffer0[((buffer1[25] % 20) & 0xffff_ffffi128) as usize] & !110))
                & !150)
                | (buffer1[((25) & 0xffff_ffffi128) as usize] & 150))))
        & 0xff)
        & 0xff;

    buffer2[((14) & 0xffff_ffffi128) as usize] = ((buffer2[((14) & 0xffff_ffffi128) as usize]
        - (((buffer2[((buffer3[20] % 35) & 0xffff_ffffi128) as usize]
            & (buffer3[((72) & 0xffff_ffffi128) as usize]
                ^ buffer2[((buffer1[100] % 35) & 0xffff_ffffi128) as usize]))
            & !34)
            | (buffer1[((97) & 0xffff_ffffi128) as usize] & 34)))
        & 0xff)
        & 0xff;

    buffer0[((17) & 0xffff_ffffi128) as usize] = (115) & 0xff;

    buffer1[((23) & 0xffff_ffffi128) as usize] = ((buffer1[((23) & 0xffff_ffffi128) as usize]
        ^ ((((((buffer4[((buffer1[17] % 21) & 0xffff_ffffi128) as usize]
            | buffer0[((buffer3[20] % 20) & 0xffff_ffffi128) as usize])
            & buffer3[((72) & 0xffff_ffffi128) as usize])
            | (buffer4[((buffer1[17] % 21) & 0xffff_ffffi128) as usize]
                & buffer0[((buffer3[20] % 20) & 0xffff_ffffi128) as usize]))
            & (buffer1[((50) & 0xffff_ffffi128) as usize] / 3))
            | ((((buffer4[((buffer1[17] % 21) & 0xffff_ffffi128) as usize]
                | buffer0[((buffer3[20] % 20) & 0xffff_ffffi128) as usize])
                & buffer3[((72) & 0xffff_ffffi128) as usize])
                | (buffer4[((buffer1[17] % 21) & 0xffff_ffffi128) as usize]
                    & buffer0[((buffer3[20] % 20) & 0xffff_ffffi128) as usize])
                | (buffer1[((50) & 0xffff_ffffi128) as usize] / 3))
                & 246))
            << 1))
        & 0xff)
        & 0xff;

    buffer0[((13) & 0xffff_ffffi128) as usize] = ((((((buffer0
        [((buffer3[((40) & 0xffff_ffffi128) as usize] % 20) & 0xffff_ffffi128) as usize]
        | buffer1[((10) & 0xffff_ffffi128) as usize])
        & 82)
        | (buffer0[((buffer3[40] % 20) & 0xffff_ffffi128) as usize]
            & buffer1[((10) & 0xffff_ffffi128) as usize]))
        & 209)
        | ((buffer0[((buffer1[39] % 20) & 0xffff_ffffi128) as usize] << 1) & 46))
        >> 1)
        & 0xff;

    buffer2[((33) & 0xffff_ffffi128) as usize] = ((buffer2[((33) & 0xffff_ffffi128) as usize]
        - (buffer1[((113) & 0xffff_ffffi128) as usize] & 9))
        & 0xff)
        & 0xff;

    buffer2[((28) & 0xffff_ffffi128) as usize] = ((buffer2[((28) & 0xffff_ffffi128) as usize]
        - ((((2 | (buffer1[((110) & 0xffff_ffffi128) as usize] & 222)) >> 1) & !223)
            | (buffer3[((20) & 0xffff_ffffi128) as usize] & 223)))
        & 0xff)
        & 0xff;

    J = weird_rol8((V | Z), (U & 7)); // OK
    A = (buffer2[((16) & 0xffff_ffffi128) as usize] & T)
        | (W & (!buffer2[((16) & 0xffff_ffffi128) as usize]));
    B = (buffer1[((33) & 0xffff_ffffi128) as usize] & 17) | (X & !17);
    E = ((Y | ((A + B) / 5)) & 147) | (Y & ((A + B) / 5)); // OK
    M = (buffer3[((40) & 0xffff_ffffi128) as usize]
        & buffer4[((((buffer3[8] + J + E) & 0xff) % 21) & 0xffff_ffffi128) as usize])
        | ((buffer3[((40) & 0xffff_ffffi128) as usize]
            | buffer4[((((buffer3[8] + J + E) & 0xff) % 21) & 0xffff_ffffi128) as usize])
            & buffer2[((23) & 0xffff_ffffi128) as usize]);

    buffer0[((15) & 0xffff_ffffi128) as usize] =
        ((((buffer4[((buffer3[20] % 21) & 0xffff_ffffi128) as usize] - 48)
            & (!buffer1[((184) & 0xffff_ffffi128) as usize]))
            | ((buffer4[((buffer3[20] % 21) & 0xffff_ffffi128) as usize] - 48) & 189)
            | (189 & !buffer1[((184) & 0xffff_ffffi128) as usize]))
            & (M * M * M))
            & 0xff;

    buffer2[((22) & 0xffff_ffffi128) as usize] = ((buffer2[((22) & 0xffff_ffffi128) as usize]
        + (buffer1[((183) & 0xffff_ffffi128) as usize]))
        & 0xff)
        & 0xff;

    buffer3[((76) & 0xffff_ffffi128) as usize] = ((3 * buffer4
        [((buffer1[((1) & 0xffff_ffffi128) as usize] % 21) & 0xffff_ffffi128) as usize])
        ^ buffer3[((0) & 0xffff_ffffi128) as usize])
        & 0xff;

    A = buffer2[((((buffer3[8] + (J + E)) & 0xff) % 35) & 0xffff_ffffi128) as usize];
    F = (((buffer4[((buffer1[178] % 21) & 0xffff_ffffi128) as usize] & A)
        | ((buffer4[((buffer1[178] % 21) & 0xffff_ffffi128) as usize] | A) & 209))
        * buffer0[((buffer1[13] % 20) & 0xffff_ffffi128) as usize])
        * (buffer4[((buffer1[26] % 21) & 0xffff_ffffi128) as usize] >> 1);
    G = (F + 0x733ffff9) * 198 - (((F + 0x733ffff9) * 396 + 212) & 212) + 85;
    buffer3[((80) & 0xffff_ffffi128) as usize] =
        (buffer3[((36) & 0xffff_ffffi128) as usize] + (G ^ 148) + ((G ^ 107) << 1) - 127) & 0xff;

    buffer3[((84) & 0xffff_ffffi128) as usize] =
        (((buffer2[((buffer3[64] % 35) & 0xffff_ffffi128) as usize]) & 245)
            | (buffer2[((buffer3[20] % 35) & 0xffff_ffffi128) as usize] & 10))
            & 0xff;

    A = buffer0[((buffer3[68] % 20) & 0xffff_ffffi128) as usize] | 81;
    buffer2[((18) & 0xffff_ffffi128) as usize] = ((buffer2[((18) & 0xffff_ffffi128) as usize]
        - (((A * A * A) & !buffer0[((15) & 0xffff_ffffi128) as usize])
            | ((buffer3[((80) & 0xffff_ffffi128) as usize] / 15)
                & buffer0[((15) & 0xffff_ffffi128) as usize])))
        & 0xff)
        & 0xff;

    buffer3[((88) & 0xffff_ffffi128) as usize] = (buffer3[((8) & 0xffff_ffffi128) as usize]
        + J
        + E
        - buffer0[((buffer1[160] % 20) & 0xffff_ffffi128) as usize]
        + (buffer4[((buffer0[(((buffer3[8] + J + E) & 255) % 20 & 0xffff_ffffi128) as usize] % 21)
            & 0xffff_ffffi128) as usize]
            / 3))
        & 0xff;

    B = ((R ^ buffer3[((72) & 0xffff_ffffi128) as usize]) & !198) | ((S * S) & 198);
    F = (buffer4[((buffer1[69] % 21) & 0xffff_ffffi128) as usize]
        & buffer1[((172) & 0xffff_ffffi128) as usize])
        | ((buffer4[((buffer1[69] % 21) & 0xffff_ffffi128) as usize]
            | buffer1[((172) & 0xffff_ffffi128) as usize])
            & ((buffer3[((12) & 0xffff_ffffi128) as usize] - B) + 77));
    buffer0[((16) & 0xffff_ffffi128) as usize] = (147
        - ((buffer3[((72) & 0xffff_ffffi128) as usize] & ((F & 251) | 1))
            | (((F & 250) | buffer3[((72) & 0xffff_ffffi128) as usize]) & 198)))
        & 0xff;

    C = (buffer4[((buffer1[168] % 21) & 0xffff_ffffi128) as usize]
        & buffer0[((buffer1[29] % 20) & 0xffff_ffffi128) as usize]
        & 7)
        | ((buffer4[((buffer1[168] % 21) & 0xffff_ffffi128) as usize]
            | buffer0[((buffer1[29] % 20) & 0xffff_ffffi128) as usize])
            & 6);
    F = (buffer4[((buffer1[155] % 21) & 0xffff_ffffi128) as usize]
        & buffer1[((105) & 0xffff_ffffi128) as usize])
        | ((buffer4[((buffer1[155] % 21) & 0xffff_ffffi128) as usize]
            | buffer1[((105) & 0xffff_ffffi128) as usize])
            & 141);
    buffer0[((3) & 0xffff_ffffi128) as usize] = ((buffer0[((3) & 0xffff_ffffi128) as usize]
        - (buffer4[((weird_rol32(F, C) % 21) & 0xffff_ffffi128) as usize]))
        & 0xff)
        & 0xff;

    buffer1[((5) & 0xffff_ffffi128) as usize] =
        (weird_ror8(
            buffer0[((12) & 0xffff_ffffi128) as usize],
            ((buffer0[((buffer1[61] % 20) & 0xffff_ffffi128) as usize] / 5) & 7),
        ) ^ (((!buffer2[((buffer3[84] % 35) & 0xffff_ffffi128) as usize]) & 0xffffffff) / 5))
            & 0xff;

    buffer1[((198) & 0xffff_ffffi128) as usize] = ((buffer1[((198) & 0xffff_ffffi128) as usize]
        + (buffer1[((3) & 0xffff_ffffi128) as usize]))
        & 0xff)
        & 0xff;

    A = (162 | buffer2[((buffer3[64] % 35) & 0xffff_ffffi128) as usize]);
    buffer1[((164) & 0xffff_ffffi128) as usize] =
        ((buffer1[((164) & 0xffff_ffffi128) as usize] + ((A * A) / 5)) & 0xff) & 0xff;

    G = weird_ror8(139, (buffer3[((80) & 0xffff_ffffi128) as usize] & 7));
    C = ((buffer4[((buffer3[64] % 21) & 0xffff_ffffi128) as usize]
        * buffer4[((buffer3[64] % 21) & 0xffff_ffffi128) as usize]
        * buffer4[((buffer3[64] % 21) & 0xffff_ffffi128) as usize])
        & 95)
        | (buffer0[((buffer3[40] % 20) & 0xffff_ffffi128) as usize] & !95);
    buffer3[((92) & 0xffff_ffffi128) as usize] = ((G & 12)
        | (buffer0[((buffer3[20] % 20) & 0xffff_ffffi128) as usize] & 12)
        | (G & buffer0[((buffer3[20] % 20) & 0xffff_ffffi128) as usize])
        | C)
        & 0xff;

    buffer2[((12) & 0xffff_ffffi128) as usize] = ((buffer2[((12) & 0xffff_ffffi128) as usize]
        + (((buffer1[((103) & 0xffff_ffffi128) as usize] & 32)
            | (buffer3[((92) & 0xffff_ffffi128) as usize]
                & (buffer1[((103) & 0xffff_ffffi128) as usize] | 60))
            | 16)
            / 3))
        & 0xff)
        & 0xff;

    buffer3[((96) & 0xffff_ffffi128) as usize] =
        (buffer1[((143) & 0xffff_ffffi128) as usize]) & 0xff;

    buffer3[((100) & 0xffff_ffffi128) as usize] = (27) & 0xff;

    buffer3[((104) & 0xffff_ffffi128) as usize] = ((((buffer3
        [((40) & 0xffff_ffffi128) as usize]
        & !buffer2[((8) & 0xffff_ffffi128) as usize])
        | (buffer1[((35) & 0xffff_ffffi128) as usize]
            & buffer2[((8) & 0xffff_ffffi128) as usize]))
        & buffer3[((64) & 0xffff_ffffi128) as usize])
        ^ 119)
        & 0xff;

    buffer3[((108) & 0xffff_ffffi128) as usize] = (238
        & ((((buffer3[((40) & 0xffff_ffffi128) as usize]
            & !buffer2[((8) & 0xffff_ffffi128) as usize])
            | (buffer1[((35) & 0xffff_ffffi128) as usize]
                & buffer2[((8) & 0xffff_ffffi128) as usize]))
            & buffer3[((64) & 0xffff_ffffi128) as usize])
            << 1))
        & 0xff;

    buffer3[((112) & 0xffff_ffffi128) as usize] = ((!buffer3[((64) & 0xffff_ffffi128) as usize]
        & (buffer3[((84) & 0xffff_ffffi128) as usize] / 3))
        ^ 49)
        & 0xff;

    buffer3[((116) & 0xffff_ffffi128) as usize] = (98
        & ((!buffer3[((64) & 0xffff_ffffi128) as usize]
            & (buffer3[((84) & 0xffff_ffffi128) as usize] / 3))
            << 1))
        & 0xff;

    // finale
    A = (buffer1[((35) & 0xffff_ffffi128) as usize] & buffer2[((8) & 0xffff_ffffi128) as usize])
        | (buffer3[((40) & 0xffff_ffffi128) as usize] & !buffer2[((8) & 0xffff_ffffi128) as usize]);
    B = (A & buffer3[((64) & 0xffff_ffffi128) as usize])
        | ((buffer3[((84) & 0xffff_ffffi128) as usize] / 3)
            & !buffer3[((64) & 0xffff_ffffi128) as usize]);
    buffer1[((143) & 0xffff_ffffi128) as usize] = (buffer3[((96) & 0xffff_ffffi128) as usize]
        - ((B & (86 + ((buffer1[((172) & 0xffff_ffffi128) as usize] & 64) >> 1)))
            | (((((buffer1[((172) & 0xffff_ffffi128) as usize] & 65) >> 1) ^ 86)
                | ((!buffer3[((64) & 0xffff_ffffi128) as usize]
                    & (buffer3[((84) & 0xffff_ffffi128) as usize] / 3))
                    | (((buffer3[((40) & 0xffff_ffffi128) as usize]
                        & !buffer2[((8) & 0xffff_ffffi128) as usize])
                        | (buffer1[((35) & 0xffff_ffffi128) as usize]
                            & buffer2[((8) & 0xffff_ffffi128) as usize]))
                        & buffer3[((64) & 0xffff_ffffi128) as usize])))
                & buffer3[((100) & 0xffff_ffffi128) as usize])))
        & 0xff;

    buffer2[((29) & 0xffff_ffffi128) as usize] = (162) & 0xff;

    A = ((((buffer4[((buffer3[88] % 21) & 0xffff_ffffi128) as usize]) & 160)
        | (buffer0[((buffer1[125] % 20) & 0xffff_ffffi128) as usize] & 95))
        >> 1);
    B = buffer2[((buffer1[149] % 35) & 0xffff_ffffi128) as usize]
        ^ (buffer1[((43) & 0xffff_ffffi128) as usize] * buffer1[((43) & 0xffff_ffffi128) as usize]);
    buffer0[((15) & 0xffff_ffffi128) as usize] =
        ((buffer0[((15) & 0xffff_ffffi128) as usize] + ((B & A) | ((A | B) & 115))) & 0xff) & 0xff;

    buffer3[((120) & 0xffff_ffffi128) as usize] = (buffer3[((64) & 0xffff_ffffi128) as usize]
        - buffer0[((buffer3[40] % 20) & 0xffff_ffffi128) as usize])
        & 0xff;

    buffer1[((95) & 0xffff_ffffi128) as usize] =
        (buffer4[((buffer3[20] % 21) & 0xffff_ffffi128) as usize]) & 0xff;

    A = weird_ror8(
        buffer2[((buffer3[80] % 35) & 0xffff_ffffi128) as usize],
        (buffer2[((buffer1[17] % 35) & 0xffff_ffffi128) as usize]
            * buffer2[((buffer1[17] % 35) & 0xffff_ffffi128) as usize]
            * buffer2[((buffer1[17] % 35) & 0xffff_ffffi128) as usize])
            & 7,
    );
    buffer0[((7) & 0xffff_ffffi128) as usize] =
        ((buffer0[((7) & 0xffff_ffffi128) as usize] - (A * A)) & 0xff) & 0xff;

    buffer2[((8) & 0xffff_ffffi128) as usize] = (buffer2[((8) & 0xffff_ffffi128) as usize]
        - buffer1[((184) & 0xffff_ffffi128) as usize]
        + (buffer4[((buffer1[202] % 21) & 0xffff_ffffi128) as usize]
            * buffer4[((buffer1[202] % 21) & 0xffff_ffffi128) as usize]
            * buffer4[((buffer1[202] % 21) & 0xffff_ffffi128) as usize]))
        & 0xff;

    buffer0[((16) & 0xffff_ffffi128) as usize] =
        ((buffer2[((buffer1[102] % 35) & 0xffff_ffffi128) as usize] << 1) & 132) & 0xff;

    buffer3[((124) & 0xffff_ffffi128) as usize] =
        ((buffer4[((buffer3[40] % 21) & 0xffff_ffffi128) as usize] >> 1)
            ^ buffer3[((68) & 0xffff_ffffi128) as usize])
            & 0xff;

    buffer0[((7) & 0xffff_ffffi128) as usize] = ((buffer0[((7) & 0xffff_ffffi128) as usize]
        - (buffer0[((buffer1[191] % 20) & 0xffff_ffffi128) as usize]
            - (((buffer4[((buffer1[80] % 21) & 0xffff_ffffi128) as usize] << 1) & !177)
                | (buffer4[((buffer4[((buffer3[88] % 21) & 0xffff_ffffi128) as usize] % 21)
                    & 0xffff_ffffi128) as usize]
                    & 177))))
        & 0xff)
        & 0xff;

    buffer0[((6) & 0xffff_ffffi128) as usize] =
        (buffer0[((buffer1[119] % 20) & 0xffff_ffffi128) as usize]) & 0xff;

    A = (buffer4[((buffer1[190] % 21) & 0xffff_ffffi128) as usize] & !209)
        | (buffer1[((118) & 0xffff_ffffi128) as usize] & 209);
    B = buffer0[((buffer3[120] % 20) & 0xffff_ffffi128) as usize]
        * buffer0[((buffer3[120] % 20) & 0xffff_ffffi128) as usize];
    buffer0[((12) & 0xffff_ffffi128) as usize] = ((buffer0
        [((buffer3[((84) & 0xffff_ffffi128) as usize] % 20) & 0xffff_ffffi128) as usize]
        ^ (buffer2[((buffer1[71] % 35) & 0xffff_ffffi128) as usize]
            + buffer2[((buffer1[15] % 35) & 0xffff_ffffi128) as usize]))
        & ((A & B) | ((A | B) & 27)))
        & 0xff;

    B = (buffer1[((32) & 0xffff_ffffi128) as usize]
        & buffer2[((buffer3[88] % 35) & 0xffff_ffffi128) as usize])
        | ((buffer1[((32) & 0xffff_ffffi128) as usize]
            | buffer2[((buffer3[88] % 35) & 0xffff_ffffi128) as usize])
            & 23);
    D = (((buffer4[((buffer1[57] % 21) & 0xffff_ffffi128) as usize] * 231) & 169) | (B & 86));
    F = (((buffer0[((buffer1[82] % 20) & 0xffff_ffffi128) as usize] & !29)
        | (buffer4[((buffer3[124] % 21) & 0xffff_ffffi128) as usize] & 29))
        & 190)
        | (buffer4[(((D / 5) % 21) & 0xffff_ffffi128) as usize] & !190);
    H = buffer0[((buffer3[40] % 20) & 0xffff_ffffi128) as usize]
        * buffer0[((buffer3[40] % 20) & 0xffff_ffffi128) as usize]
        * buffer0[((buffer3[40] % 20) & 0xffff_ffffi128) as usize];
    K = (H & buffer1[((82) & 0xffff_ffffi128) as usize])
        | (H & 92)
        | (buffer1[((82) & 0xffff_ffffi128) as usize] & 92);
    buffer3[((128) & 0xffff_ffffi128) as usize] = (((F & K) | ((F | K) & 192)) ^ (D / 5)) & 0xff;

    buffer2[((25) & 0xffff_ffffi128) as usize] = ((buffer2[((25) & 0xffff_ffffi128) as usize]
        ^ (((buffer0[((buffer3[120] % 20) & 0xffff_ffffi128) as usize] << 1)
            * buffer1[((5) & 0xffff_ffffi128) as usize])
            - (weird_rol8(
                buffer3[((76) & 0xffff_ffffi128) as usize],
                (buffer4[((buffer3[124] % 21) & 0xffff_ffffi128) as usize] & 7),
            ) & (buffer3[((20) & 0xffff_ffffi128) as usize] + 110))))
        & 0xff)
        & 0xff;

    //exit(0);
}

/// Apply the garbling transform to byte buffers.
///
/// The generated core uses `i128` only to make every index a native Rust
/// index; values are truncated to eight bits at every buffer write, matching
/// C's `unsigned char` semantics.
pub(crate) fn hand_garble_bytes(
    buffer0: &mut [u8; 20],
    buffer1: &mut [u8; 210],
    buffer2: &mut [u8; 35],
    buffer3: &mut [u8; 132],
    buffer4: &mut [u8; 21],
) {
    let mut a = [0i128; 20];
    let mut b = [0i128; 210];
    let mut c = [0i128; 35];
    let mut d = [0i128; 132];
    let mut e = [0i128; 21];
    for (dst, src) in a.iter_mut().zip(buffer0.iter()) {
        *dst = i128::from(*src);
    }
    for (dst, src) in b.iter_mut().zip(buffer1.iter()) {
        *dst = i128::from(*src);
    }
    for (dst, src) in c.iter_mut().zip(buffer2.iter()) {
        *dst = i128::from(*src);
    }
    for (dst, src) in d.iter_mut().zip(buffer3.iter()) {
        *dst = i128::from(*src);
    }
    for (dst, src) in e.iter_mut().zip(buffer4.iter()) {
        *dst = i128::from(*src);
    }
    hand_garble(&mut a, &mut b, &mut c, &mut d, &mut e);
    for (dst, src) in buffer0.iter_mut().zip(a) {
        *dst = src as u8;
    }
    for (dst, src) in buffer1.iter_mut().zip(b) {
        *dst = src as u8;
    }
    for (dst, src) in buffer2.iter_mut().zip(c) {
        *dst = src as u8;
    }
    for (dst, src) in buffer3.iter_mut().zip(d) {
        *dst = src as u8;
    }
    for (dst, src) in buffer4.iter_mut().zip(e) {
        *dst = src as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_the_garble_vector() {
        let mut b0 = [
            0x96, 0x5f, 0xc6, 0x53, 0xf8, 0x46, 0xcc, 0x18, 0xdf, 0xbe, 0xb2, 0xf8, 0x38, 0xd7,
            0xec, 0x22, 0x03, 0xd1, 0x20, 0x8f,
        ];
        let mut b1 =
            std::array::from_fn::<_, 210, _>(|i| (i as u8).wrapping_mul(29).wrapping_add(7));
        let mut b2 = [
            0x43, 0x54, 0x62, 0x7a, 0x18, 0xc3, 0xd6, 0xb3, 0x9a, 0x56, 0xf6, 0x1c, 0x14, 0x3f,
            0x0c, 0x1d, 0x3b, 0x36, 0x83, 0xb1, 0x39, 0x51, 0x4a, 0xaa, 0x09, 0x3e, 0xfe, 0x44,
            0xaf, 0xde, 0xc3, 0x20, 0x9d, 0x42, 0x3a,
        ];
        let mut b3 =
            std::array::from_fn::<_, 132, _>(|i| (i as u8).wrapping_mul(17).wrapping_add(3));
        let mut b4 = [
            0xed, 0x25, 0xd1, 0xbb, 0xbc, 0x27, 0x9f, 0x02, 0xa2, 0xa9, 0x11, 0x00, 0x0c, 0xb3,
            0x52, 0xc0, 0xbd, 0xe3, 0x1b, 0x49, 0xc7,
        ];
        hand_garble_bytes(&mut b0, &mut b1, &mut b2, &mut b3, &mut b4);
        assert_eq!(
            b0,
            [
                0x96, 0x5f, 0xc6, 0x64, 0xf8, 0x46, 0x00, 0xcb, 0xdf, 0xbe, 0x00, 0xf8, 0x09, 0x1e,
                0x96, 0xfb, 0x84, 0x73, 0x20, 0x5b
            ]
        );
        assert_eq!(
            b1,
            [
                0x07, 0x24, 0x01, 0x5e, 0x20, 0xd1, 0xb5, 0xd2, 0xef, 0x0c, 0x29, 0x46, 0x63, 0x80,
                0x9d, 0xa4, 0xd7, 0xf4, 0x11, 0x52, 0x4b, 0x68, 0x4e, 0xc4, 0xbf, 0xdc, 0xf9, 0x16,
                0x33, 0x50, 0x6d, 0x8a, 0xa7, 0x2e, 0xe6, 0xfe, 0x98, 0x38, 0x55, 0x72, 0x8f, 0xac,
                0xc9, 0xe6, 0x03, 0x20, 0x3d, 0xe9, 0x77, 0x94, 0xb1, 0xce, 0xeb, 0xcd, 0x25, 0x42,
                0x5f, 0x7c, 0x99, 0xb6, 0xd3, 0xf0, 0x0d, 0x2a, 0x47, 0x64, 0x81, 0x9e, 0xbb, 0xd8,
                0xf5, 0x12, 0x2f, 0x4c, 0x69, 0x86, 0xa3, 0xc0, 0xdd, 0xfa, 0x17, 0x34, 0x51, 0x6e,
                0x8b, 0xa8, 0xc5, 0xe2, 0xff, 0x1c, 0x39, 0x56, 0x73, 0x90, 0xad, 0xbc, 0xe7, 0x04,
                0x21, 0x3e, 0x5b, 0x78, 0x95, 0xb2, 0xcf, 0xec, 0xd4, 0x26, 0x43, 0x60, 0x7d, 0x9a,
                0xb7, 0xd4, 0xf1, 0x0e, 0x2b, 0x48, 0x65, 0x82, 0x9f, 0xbc, 0xd9, 0x2b, 0xa3, 0x30,
                0x4d, 0x6a, 0x87, 0xa4, 0xc1, 0xde, 0xfb, 0x18, 0x35, 0x52, 0x6f, 0x8c, 0xa9, 0xc6,
                0xe3, 0x00, 0x1d, 0xdb, 0x57, 0x74, 0x91, 0xae, 0xcb, 0xe8, 0x05, 0x22, 0x3f, 0xc8,
                0x79, 0x96, 0xb3, 0xd0, 0xed, 0x0a, 0x27, 0x44, 0x61, 0x7e, 0xe2, 0xb8, 0xd5, 0xf2,
                0x0f, 0x2c, 0x49, 0x66, 0x83, 0xa0, 0xbd, 0xda, 0xf7, 0x14, 0x31, 0x4e, 0x6b, 0x88,
                0xa5, 0xc2, 0xdf, 0xfc, 0x19, 0x36, 0x53, 0x70, 0x38, 0xaa, 0xc7, 0xe4, 0x01, 0x1e,
                0x3b, 0x58, 0xd3, 0x92, 0xaf, 0xcc, 0xe9, 0x06, 0x23, 0x40, 0x5d, 0x7a, 0x97, 0xb4
            ]
        );
        assert_eq!(
            b2,
            [
                0x43, 0x2c, 0xfe, 0x7a, 0x55, 0xb2, 0xd6, 0xb3, 0xaa, 0x56, 0xf6, 0x1c, 0xc6, 0x84,
                0xfb, 0x1d, 0x50, 0x36, 0x96, 0xb1, 0x39, 0x51, 0xbe, 0xaa, 0x09, 0xfc, 0xfe, 0x44,
                0x37, 0xa2, 0xc2, 0x20, 0x9d, 0xbb, 0xb8
            ]
        );
        assert_eq!(
            b3,
            [
                0x18, 0x14, 0x25, 0x36, 0xba, 0x58, 0x69, 0x7a, 0x4c, 0x9c, 0xad, 0xbe, 0xb2, 0xe0,
                0xf1, 0x02, 0x72, 0x24, 0x35, 0x46, 0x58, 0x68, 0x79, 0x8a, 0x22, 0xac, 0xbd, 0xce,
                0xe2, 0xf0, 0x01, 0x12, 0x20, 0x34, 0x45, 0x56, 0x74, 0x78, 0x89, 0x9a, 0xec, 0xbc,
                0xcd, 0xde, 0x2f, 0x00, 0x11, 0x22, 0x18, 0x44, 0x55, 0x66, 0x1b, 0x88, 0x99, 0xaa,
                0xc7, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x21, 0x32, 0x72, 0x54, 0x65, 0x76, 0x56, 0x98,
                0xa9, 0xba, 0x00, 0xdc, 0xed, 0xfe, 0x58, 0x20, 0x31, 0x42, 0x74, 0x64, 0x75, 0x86,
                0x5e, 0xa8, 0xb9, 0xca, 0xcc, 0xec, 0xfd, 0x0e, 0x9d, 0x30, 0x41, 0x52, 0x3a, 0x74,
                0x85, 0x96, 0x1b, 0xb8, 0xc9, 0xda, 0x07, 0xfc, 0x0d, 0x1e, 0xe0, 0x40, 0x51, 0x62,
                0x3c, 0x84, 0x95, 0xa6, 0x02, 0xc8, 0xd9, 0xea, 0x61, 0x0c, 0x1d, 0x2e, 0x45, 0x50,
                0x61, 0x72, 0x4c, 0x94, 0xa5, 0xb6
            ]
        );
        assert_eq!(
            b4,
            [
                0xed, 0x25, 0xd1, 0xbb, 0xbc, 0x27, 0x9f, 0x02, 0xa2, 0xa9, 0x11, 0x00, 0x0c, 0xb3,
                0x52, 0xc0, 0xbd, 0xe3, 0x1b, 0x49, 0xc7
            ]
        );
    }
}
