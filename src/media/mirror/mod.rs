// SPDX-License-Identifier: GPL-3.0-or-later
//! The mirror stream: its keys, and the packets that carry video.
//!
//! A mirroring client sets up a stream of its own with `SETUP`, and the two
//! things that make it different from audio are that it travels over TCP and that
//! its keystream is derived rather than carried. The derivation is written out in
//! the protocol:
//!
//! ```text
//! key = SHA-512("AirPlayStreamKey" + decimal(streamConnectionID) + audio key)
//! iv = SHA-512("AirPlayStreamIV" + decimal(streamConnectionID) + audio key)
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
//! The video payload is AES-128-CTR, but not as one continuous stream: the protocol
//! calls `aes_ctr_start_fresh_block` at the start of every packet
//!, and OpenSSL's CTR context
//! keeps a *block offset* rather than a byte position. Decrypting a length that is
//! not a multiple of sixteen therefore leaves the context part-way into a block,
//! and "start a fresh block" throws the rest of that block's keystream away. What
//! the protocol does with it instead is to decrypt the packet's tail as **one whole
//! block** and keep the bytes the packet did not use
//!, so the next packet's first bytes are XORed with
//! them ([`MirrorDecryptor`] is that state).
//!
//! The protocol also sends the codec configuration (an H.264 SPS and PPS) in a packet
//! of its own, *unencrypted*, and prepends it to the next video packet because a
//! decoder needs it before the first frame
//!.

mod codec;
mod crypto;
mod header;
mod nal;
mod session;

pub use codec::{CodecConfig, CodecDataError, StreamInfo};
pub use crypto::{MirrorDecryptor, STREAM_KEY_LEN, StreamKeys, stream_keys};
pub use header::{
    Geometry, HEADER_LEN, MAX_PAYLOAD, MirrorError, MirrorHeader, MirrorKind, parse_header,
    parse_packet,
};
pub use nal::{NalError, START_CODE, into_annex_b};
pub use session::{
    Decrypted, FrameError, MirrorSession, PacketCensus, PacketCounts, PendingBadPacket, VideoFrame,
};

/// The coding a mirror stream carries, re-exported so a protocol user need not also
/// reach into the renderer's types.
pub use crate::render::VideoCodec;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod pause_tests {
    use super::{HEADER_LEN, MirrorSession, parse_header, stream_keys};

    fn codec_packet(option: u8) -> Vec<u8> {
        let mut packet = vec![0u8; HEADER_LEN];
        // A codec packet is the first byte pair 0x01, 0x00, and its option says whether
        // the stream stopped or resumed.
        packet[4] = 0x01;
        packet[5] = 0x00;
        packet[6] = option;
        packet
    }

    #[test]
    fn a_codec_packet_reports_pause_and_resume() {
        let keys = stream_keys(1, &[0x11; 16]);
        let mut session = MirrorSession::new(&keys).expect("a session");
        assert!(!session.paused());
        for (option, paused) in [(0x56u8, true), (0x16, false), (0x5e, true), (0x1e, false)] {
            let packet = codec_packet(option);
            let header = parse_header(&packet).expect("a header");
            let _ = session.receive(&header, &[]);
            assert_eq!(session.paused(), paused, "option {option:#04x}");
        }
    }
}

#[cfg(test)]
mod geometry_tests {
    use super::{Geometry, HEADER_LEN, parse_header};

    /// A codec packet with the geometry a device sends: whole numbers as floats.
    fn codec_packet(width: u16, height: u16) -> Vec<u8> {
        let mut packet = vec![0u8; HEADER_LEN + 4];
        packet[4] = 0x01;
        packet[5] = 0x00;
        let mut put = |offset: usize, value: u16| {
            packet[offset..offset + 4].copy_from_slice(&f32::from(value).to_le_bytes());
        };
        put(16, width);
        put(20, height);
        put(40, width);
        put(44, height);
        put(48, 0);
        put(52, 0);
        put(56, width);
        put(60, height);
        packet
    }

    #[test]
    fn a_codec_packet_announces_the_picture_it_will_send() {
        let packet = codec_packet(1554, 1080);
        let header = parse_header(&packet).expect("a header");
        let geometry = header.geometry.expect("the geometry a device sends");
        assert_eq!(geometry.width, 1554);
        assert_eq!(geometry.height, 1080);
        assert_eq!(geometry.width_source, 1554);
        assert_eq!(geometry.height_source, 1080);
    }

    #[test]
    fn a_packet_without_geometry_announces_none() {
        let mut packet = vec![0u8; HEADER_LEN];
        packet[4] = 0x00;
        let header = parse_header(&packet).expect("a header");
        assert!(header.geometry.is_none(), "a video packet has no geometry");
        // And a codec packet full of zeroes is not geometry either.
        assert!(Geometry::from_codec_packet(&packet).is_none());
    }
}

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
