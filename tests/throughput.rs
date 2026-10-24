// SPDX-License-Identifier: GPL-3.0-or-later

// Tests report what they measured; the library itself never prints.
#![allow(clippy::print_stdout, clippy::print_stderr)]

//! What the packet path costs, so that "make it faster" is a measurement.
//!
//! The mirror stream is the only part of this crate that runs continuously at a device's
//! pace: a 1554x1080 screen arrives as about thirty packets a second, from forty bytes to
//! tens of kilobytes each. Everything the session does per packet is therefore worth
//! knowing in nanoseconds rather than in intuition.
//!
//! The test builds packets the way a client does — a header, then length-prefixed NAL units
//! — encrypted with the stream's own keystream so the session sees a stream it can read,
//! and reports how long a second of a real session takes to process. It asserts nothing
//! about speed: a threshold in a test is a number that gets raised until it passes. What it
//! prints is the number to compare after a change.
//!
//! ```powershell
//! cargo test -p airplay-core --test throughput -- --ignored --nocapture
//! ```

use std::time::Instant;

use rust_airplay::media::mirror::{
    HEADER_LEN, MirrorDecryptor, MirrorHeader, MirrorKind, MirrorSession, parse_packet, stream_keys,
};

/// A screen's worth of packets: the sizes a real session sent, which are not one size and
/// are not all small.
const SIZES: &[usize] = &[
    1_265, 1_356, 1_358, 1_237, 1_500, 1_100, 900, 700, 1_800, 2_400, 624, 1_000, 1_300, 1_420,
    1_346, 1_300, 64, 33, 47, 1_000,
];

/// A packet: a header and the payload a client would send.
fn packet(payload_size: usize, idr: bool) -> (MirrorHeader, Vec<u8>) {
    let mut datagram = vec![0u8; HEADER_LEN + payload_size];
    datagram[0..4].copy_from_slice(&(payload_size as u32).to_le_bytes());
    datagram[4] = 0x00;
    datagram[5] = if idr { 0x10 } else { 0x00 };
    datagram[8..16].copy_from_slice(&42u64.to_le_bytes());
    let (header, payload) = parse_packet(&datagram).expect("a packet this crate built");
    (header, payload.to_vec())
}

/// A payload of `size` bytes that is a sequence of length-prefixed units, which is what a
/// session accepts and converts.
fn units(size: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(size);
    let mut left = size;
    while left >= 8 {
        // A unit of what is left, leaving room for its own four-byte prefix.
        let unit = (left - 4).min(1_400);
        payload.extend_from_slice(&(unit as u32).to_be_bytes());
        payload.resize(payload.len() + unit, 0x42);
        left -= unit + 4;
    }
    payload.resize(size, 0x42);
    payload
}

/// One second of a real session, as the session would receive it.
fn one_second() -> Vec<(MirrorHeader, Vec<u8>)> {
    // A device sends about thirty a second, so the sizes are walked twice through.
    SIZES
        .iter()
        .chain(SIZES.iter())
        .take(30)
        .enumerate()
        .map(|(index, size)| packet(*size, index % 15 == 0))
        .collect()
}

#[test]
#[ignore = "measures rather than asserts; run with --ignored --nocapture"]
fn a_second_of_a_session() {
    for round in 0..3 {
        let keys = stream_keys(0x1234_5678_9abc_def0, &[0x5a; 16]);
        let mut session = MirrorSession::new(&keys).expect("a session");
        // A decryptor walked over the same lengths keeps a parallel position, so the
        // keystream each packet was encrypted with can be produced without knowing the
        // rule here: decrypting zeros gives back exactly those bytes.
        let mut parallel = MirrorDecryptor::new(&keys).expect("a decryptor");

        let second = one_second();
        let mut encrypted = Vec::with_capacity(second.len());
        for (header, payload) in &second {
            let mut keystream = vec![0u8; payload.len()];
            parallel
                .decrypt(&vec![0u8; payload.len()], &mut keystream)
                .expect("a packet of zeros");
            let ciphertext: Vec<u8> = units(payload.len())
                .iter()
                .zip(&keystream)
                .map(|(byte, key)| byte ^ key)
                .collect();
            let mut datagram = vec![0u8; HEADER_LEN + ciphertext.len()];
            datagram[0..4].copy_from_slice(&(ciphertext.len() as u32).to_le_bytes());
            datagram[4] = 0x00;
            datagram[5] = match header.kind {
                MirrorKind::Video { idr: true } => 0x10,
                _ => 0x00,
            };
            datagram[8..16].copy_from_slice(&header.timestamp.to_le_bytes());
            datagram[HEADER_LEN..].copy_from_slice(&ciphertext);
            encrypted.push(datagram);
        }

        // Where the time goes, measured apart from the whole: a number that says "make it
        // faster" without saying which part is the part is not a measurement.
        let parsing = {
            let started = Instant::now();
            let mut checksum = 0usize;
            for datagram in &encrypted {
                let (_, payload) = parse_packet(datagram).expect("a packet");
                checksum += payload.len();
            }
            let elapsed = started.elapsed();
            assert!(checksum > 0);
            elapsed
        };
        let decrypting = {
            let mut decryptor = MirrorDecryptor::new(&keys).expect("a decryptor");
            let mut output = Vec::new();
            let started = Instant::now();
            for datagram in &encrypted {
                let (_, payload) = parse_packet(datagram).expect("a packet");
                output.resize(payload.len(), 0);
                decryptor.decrypt(payload, &mut output).expect("a packet");
            }
            started.elapsed()
        };

        let started = Instant::now();
        let mut frames = 0usize;
        for datagram in &encrypted {
            let (header, payload) = parse_packet(datagram).expect("a packet");
            if session.receive(&header, payload).is_ok() {
                frames += 1;
            }
        }
        let elapsed = started.elapsed();
        println!("  header parse {parsing:?}, decrypt only {decrypting:?}, whole path {elapsed:?}");
        let bytes: usize = encrypted.iter().map(Vec::len).sum();
        let per_packet = elapsed / encrypted.len() as u32;
        println!(
            "round {round}: {} packets, {bytes} bytes, {frames} frames in {elapsed:?} \
             ({per_packet:?} a packet, {:.0} packets a second)",
            encrypted.len(),
            encrypted.len() as f64 / elapsed.as_secs_f64()
        );
    }
}
