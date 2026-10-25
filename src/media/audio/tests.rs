// SPDX-License-Identifier: GPL-3.0-or-later
//! Tests for the audio packet, session and reorder rules.

use super::*;
use crate::media::control::ControlError;

/// A datagram with the header the protocol documents and `payload` after it.
fn datagram(sequence: u16, timestamp: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, AUDIO_PAYLOAD_TYPE];
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    bytes.extend_from_slice(payload);
    bytes
}

fn frame(sequence: u16) -> AudioFrame {
    AudioFrame {
        sequence,
        timestamp: u32::from(sequence) * 480,
        payload: vec![sequence as u8; 4],
        kind: AudioPayloadKind::Data,
    }
}

#[test]
fn reads_the_documented_header() {
    let bytes = datagram(0x1234, 0x0000_abcd, &[1, 2, 3, 4]);
    let packet = parse_audio_packet(&bytes).expect("audio packet");
    assert_eq!(packet.sequence, 0x1234);
    assert_eq!(packet.timestamp, 0x0000_abcd);
    assert_eq!(packet.payload, [1, 2, 3, 4]);
    assert_eq!(packet.kind, AudioPayloadKind::Data);
}

#[test]
fn a_missing_packet_is_requested_once() {
    let mut window = ReorderWindow::new(8);
    assert_eq!(window.accept(frame(0)).len(), 1);
    // Sequence 2 skips 1: the window holds it and the missing one is requested.
    assert!(window.accept(frame(2)).is_empty());
    assert_eq!(window.take_resend_requests(8), [1]);
    assert!(
        window.take_resend_requests(8).is_empty(),
        "one request per gap, not one per packet"
    );
    // The answer fills the gap and releases both frames in order.
    assert_eq!(window.accept(frame(1)).len(), 2);
}

#[test]
fn refuses_what_is_not_audio() {
    assert_eq!(
        parse_audio_packet(&[0x80, 0x60, 0, 1, 0, 0, 0, 0, 0, 0, 0]),
        Err(AudioPacketError::TooShort)
    );
    let mut wrong_type = datagram(1, 0, &[0; 4]);
    wrong_type[1] = 97;
    assert_eq!(
        parse_audio_packet(&wrong_type),
        Err(AudioPacketError::UnexpectedPayloadType(97))
    );
    let mut wrong_version = datagram(1, 0, &[0; 4]);
    wrong_version[0] = 0x00;
    assert!(matches!(
        parse_audio_packet(&wrong_version),
        Err(AudioPacketError::Header(_))
    ));
}

#[test]
fn reports_the_marker_an_aac_eld_stream_starts_with() {
    let bytes = datagram(7, 0, &NO_DATA_MARKER);
    let packet = parse_audio_packet(&bytes).expect("marker packet");
    assert_eq!(packet.kind, AudioPayloadKind::NoDataMarker);
    // A payload that merely starts like the marker is audio.
    let bytes = datagram(8, 0, &[0x00, 0x68, 0x34, 0x00, 0x01]);
    assert_eq!(
        parse_audio_packet(&bytes).expect("packet").kind,
        AudioPayloadKind::Data
    );
}

#[test]
fn a_flush_discards_what_was_buffered_and_restarts_at_the_named_sequence() {
    // What a pause looks like: frames 100 and 102 arrive, 101 never does, and then the
    // client says "resume at 200". Everything held is audio nobody wants any more.
    let mut window = ReorderWindow::new(16);
    window.accept(frame(100));
    window.accept(frame(102));
    assert_eq!(window.pending(), 1);

    window.flush(200);
    assert_eq!(window.pending(), 0, "a flush leaves nothing buffered");

    // The next frame is delivered at once rather than waiting for 101, which is what
    // a client that named 200 is telling the receiver.
    let delivered = window.accept(frame(200));
    assert_eq!(
        delivered
            .iter()
            .map(|frame| frame.sequence)
            .collect::<Vec<_>>(),
        vec![200]
    );
    assert!(window.take_lost().is_empty());
}

#[test]
fn a_flush_reaching_the_session_is_applied_to_the_next_datagram() {
    let mut session = AudioSession::new([0; 16], [0; 16], 16);
    let handle = session.flush_handle();
    handle.request(1234);
    assert_eq!(session.apply_flush(), Some(1234));
    assert_eq!(session.apply_flush(), None, "one request flushes once");
}
#[test]
fn delivers_in_order_and_holds_what_arrives_early() {
    let mut window = ReorderWindow::default();
    assert_eq!(
        window.accept(frame(10)).len(),
        1,
        "the first frame sets the start"
    );
    assert!(window.accept(frame(12)).is_empty(), "12 waits for 11");
    assert_eq!(window.pending(), 1);
    let ready = window.accept(frame(11));
    assert_eq!(
        ready.iter().map(|frame| frame.sequence).collect::<Vec<_>>(),
        [11, 12]
    );
    assert!(window.take_lost().is_empty());
    assert_eq!(window.pending(), 0);
}

#[test]
fn drops_a_duplicate_rather_than_playing_it_twice() {
    let mut window = ReorderWindow::default();
    window.accept(frame(5));
    assert!(window.accept(frame(5)).is_empty(), "delivered already");
    window.accept(frame(7));
    assert!(window.accept(frame(7)).is_empty(), "waiting already");
    assert_eq!(window.pending(), 1);
}

#[test]
fn steps_over_a_gap_the_window_cannot_hold() {
    let mut window = ReorderWindow::new(4);
    window.accept(frame(20));
    // 21 is missing; 22, 23 and 24 fill the window, and 25 does not fit, so
    // the window gives up on 21 and then delivers what it was holding.
    for sequence in [22, 23, 24] {
        assert!(window.accept(frame(sequence)).is_empty());
    }
    assert_eq!(window.pending(), 3);
    let ready = window.accept(frame(25));
    assert_eq!(
        ready.iter().map(|frame| frame.sequence).collect::<Vec<_>>(),
        [22, 23, 24, 25]
    );
    assert_eq!(window.take_lost(), [21]);
    assert!(window.pending() <= window.capacity);
}

#[test]
fn counts_every_gap_it_steps_over() {
    let mut window = ReorderWindow::new(2);
    window.accept(frame(30));
    // 31, 32 and 33 never arrive; 35 is far enough ahead that the window
    // steps over all three of them to hold it.
    assert!(window.accept(frame(35)).is_empty());
    // The window keeps at most one capacity's worth of losses, so a caller
    // that never collects them cannot make this grow: the oldest is dropped.
    assert_eq!(window.take_lost(), [32, 33]);
    let ready = window.accept(frame(34));
    assert_eq!(
        ready.iter().map(|frame| frame.sequence).collect::<Vec<_>>(),
        [34, 35]
    );
}

#[test]
fn a_large_step_forward_starts_over_instead_of_walking_the_gap() {
    let mut window = ReorderWindow::new(4);
    window.accept(frame(1));
    window.accept(frame(3));
    // 51 is a hundred steps ahead: not a gap to wait out, but a new start,
    // and it is delivered as the first frame of that start.
    let ready = window.accept(frame(51));
    assert_eq!(
        ready.iter().map(|frame| frame.sequence).collect::<Vec<_>>(),
        [51]
    );
    assert!(window.take_lost().is_empty());
    assert_eq!(window.pending(), 0);
    let ready = window.accept(frame(52));
    assert_eq!(
        ready.iter().map(|frame| frame.sequence).collect::<Vec<_>>(),
        [52]
    );
}

#[test]
fn a_frame_from_the_past_is_dropped() {
    let mut window = ReorderWindow::new(4);
    window.accept(frame(1));
    window.accept(frame(3));
    // A sequence this far behind the window is what a replay looks like, and
    // a stream that really restarted says so with a new session.
    assert!(window.accept(frame(40000)).is_empty());
    assert!(window.take_lost().is_empty());
    assert_eq!(window.pending(), 1, "the held frame is untouched");
    let ready = window.accept(frame(2));
    assert_eq!(
        ready.iter().map(|frame| frame.sequence).collect::<Vec<_>>(),
        [2, 3]
    );
}

#[test]
fn keeps_working_when_the_sequence_number_wraps() {
    let mut window = ReorderWindow::default();
    window.accept(frame(65534));
    window.accept(frame(0));
    let ready = window.accept(frame(65535));
    assert_eq!(
        ready.iter().map(|frame| frame.sequence).collect::<Vec<_>>(),
        [65535, 0]
    );
    let ready = window.accept(frame(1));
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].sequence, 1);
    assert!(window.take_lost().is_empty());
}

#[test]
fn a_frame_from_before_the_start_is_not_a_new_start() {
    let mut window = ReorderWindow::default();
    window.accept(frame(100));
    // A late duplicate of an earlier packet must not rewind the window.
    assert!(window.accept(frame(99)).is_empty());
    let ready = window.accept(frame(101));
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].sequence, 101);
}

/// Encrypts with the port's own CBC primitive, so the test builds the
/// ciphertext the way a client's key does rather than trusting a fixture.
fn encrypt(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockEncryptMut, KeyIvInit};
    type Encryptor = cbc::Encryptor<aes::Aes128>;
    let mut buffer = plaintext.to_vec();
    let encrypted = Encryptor::new(key.into(), iv.into())
        .encrypt_padded_mut::<aes::cipher::block_padding::NoPadding>(
            &mut buffer,
            plaintext.len() / 16 * 16,
        )
        .expect("whole blocks");
    let mut output = encrypted.to_vec();
    output.extend_from_slice(&plaintext[plaintext.len() / 16 * 16..]);
    output
}

#[test]
fn decrypts_only_whole_blocks_and_copies_the_tail() {
    let key = [0x11; 16];
    let iv = [0x22; 16];
    // Sixteen bytes of audio and five bytes that no block covers: the protocol
    // decrypts the first part and passes the rest through unchanged
    //.
    let mut plaintext = vec![0x8c; 16];
    plaintext.extend_from_slice(b"clear");
    assert_eq!(plaintext.len(), 21);
    let encrypted = encrypt(&key, &iv, &plaintext);
    assert_ne!(&encrypted[..16], &plaintext[..16], "the block is encrypted");
    assert_eq!(&encrypted[16..], b"clear", "the tail is not");

    let decrypted = decrypt_payload(&key, &iv, &encrypted).expect("decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn every_packet_starts_from_the_same_iv() {
    let key = [0x33; 16];
    let iv = [0x44; 16];
    let first = encrypt(&key, &iv, &[0x8c; 16]);
    let second = encrypt(&key, &iv, &[0x8c; 16]);
    assert_eq!(first, second, "the client resets its cipher per packet too");
    // A payload that is entirely clear is not an error: nothing to decrypt.
    assert_eq!(
        decrypt_payload(&key, &iv, b"short").expect("decrypt"),
        b"short"
    );
}

#[test]
fn a_session_delivers_decrypted_audio_in_order() {
    let key = [0x55; 16];
    let iv = [0x66; 16];
    let mut session = AudioSession::new(key, iv, WINDOW_CAPACITY);
    let audio = encrypt(&key, &iv, &[0x8c; 16]);
    let packet = |sequence: u16, timestamp: u32| datagram(sequence, timestamp, &audio);

    // The first packet fixes the starting point, so it is delivered.
    let ready = session.receive(&packet(1, 480)).expect("first");
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].payload, vec![0x8c; 16], "delivered decrypted");
    // The third one waits for the second.
    assert!(session.receive(&packet(3, 1440)).expect("third").is_empty());
    let ready = session.receive(&packet(2, 960)).expect("second");
    assert_eq!(
        ready.iter().map(|frame| frame.sequence).collect::<Vec<_>>(),
        [2, 3]
    );
    assert!(ready.iter().all(|frame| frame.payload == vec![0x8c; 16]));
}

#[test]
fn a_session_delivers_the_start_marker_without_decrypting_it() {
    let mut session = AudioSession::new([0x77; 16], [0x88; 16], WINDOW_CAPACITY);
    let ready = session
        .receive(&datagram(1, 0, &NO_DATA_MARKER))
        .expect("marker");
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].kind, AudioPayloadKind::NoDataMarker);
    assert_eq!(ready[0].payload, NO_DATA_MARKER);
}

#[test]
fn a_resent_packet_fills_the_gap_the_window_waits_for() {
    let key = [0xbb; 16];
    let iv = [0xcc; 16];
    let mut session = AudioSession::new(key, iv, WINDOW_CAPACITY);
    let audio = encrypt(&key, &iv, &[0x8c; 16]);
    let packet = |sequence: u16, timestamp: u32| datagram(sequence, timestamp, &audio);

    // 1 arrives, 3 is held: 2 is missing.
    assert_eq!(session.receive(&packet(1, 480)).expect("first").len(), 1);
    assert!(session.receive(&packet(3, 1440)).expect("third").is_empty());
    assert!(session.take_lost().is_empty());

    // The client answers a resend request with the audio wrapped in four
    // bytes; the session must deliver it and then the frame it was holding.
    let mut wrapped = vec![0x80, 0x56 | 0x80, 0x00, 0x00];
    wrapped.extend_from_slice(&packet(2, 960));
    let ready = session.receive_control(&wrapped).expect("resent");
    assert_eq!(
        ready.iter().map(|frame| frame.sequence).collect::<Vec<_>>(),
        [2, 3]
    );
    assert!(ready.iter().all(|frame| frame.payload == vec![0x8c; 16]));
    assert!(session.take_lost().is_empty(), "nothing was lost after all");
}

#[test]
fn a_sync_packet_delivers_nothing_and_is_not_an_error() {
    let mut session = AudioSession::new([0xdd; 16], [0xee; 16], WINDOW_CAPACITY);
    let mut sync = vec![0x90, 0xd4, 0x00, 0x04];
    sync.extend_from_slice(&[0u8; 16]);
    assert!(session.receive_control(&sync).expect("sync").is_empty());
    // A control packet this session cannot read is refused, not guessed at.
    assert!(matches!(
        session.receive_control(&[0x80]),
        Err(AudioSessionError::Control(ControlError::TooShort))
    ));
}

#[test]
fn a_session_refuses_what_is_not_audio() {
    let mut session = AudioSession::new([0x99; 16], [0xaa; 16], WINDOW_CAPACITY);
    assert!(matches!(
        session.receive(&[0x80, 0x60, 0, 1]),
        Err(AudioSessionError::Packet(AudioPacketError::TooShort))
    ));
    let mut wrong_type = datagram(1, 0, &[0; 16]);
    wrong_type[1] = 97;
    assert!(matches!(
        session.receive(&wrong_type),
        Err(AudioSessionError::Packet(
            AudioPacketError::UnexpectedPayloadType(97)
        ))
    ));
}

#[test]
fn the_window_never_grows_past_its_capacity() {
    let mut window = ReorderWindow::new(8);
    window.accept(frame(0));
    for sequence in 1..2000u16 {
        window.accept(frame(sequence));
        assert!(
            window.pending() <= window.capacity,
            "held {} frames at {sequence}",
            window.pending()
        );
    }
}

#[test]
fn debug_does_not_print_the_session_key_or_frame_payload() {
    let session = AudioSession::new([0xab; 16], [0xcd; 16], 8);
    let debug = format!("{session:?}");
    assert!(!debug.contains("171"), "{debug}");
    assert!(!debug.contains("205"), "{debug}");

    let frame = AudioFrame {
        sequence: 1,
        timestamp: 2,
        payload: vec![0xef; 4],
        kind: AudioPayloadKind::Data,
    };
    let debug = format!("{frame:?}");
    assert!(!debug.contains("239"), "{debug}");
    assert!(debug.contains("<4 bytes>"), "{debug}");
}
