// SPDX-License-Identifier: GPL-3.0-or-later
//! Tests for the media sockets and the mirror connection.

#[cfg(test)]
use super::*;
use crate::media::audio::AUDIO_PAYLOAD_TYPE;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// A datagram with the audio header the protocol documents, encrypted with the
/// port's own primitive so the test speaks the client's side of the wire.
fn datagram(sequence: u16, timestamp: u32, key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    use aes::cipher::{BlockEncryptMut, KeyIvInit};
    let plaintext = [0x8c; 16];
    let mut block = plaintext;
    cbc::Encryptor::<aes::Aes128>::new(key.into(), iv.into())
        .encrypt_padded_mut::<aes::cipher::block_padding::NoPadding>(&mut block, 16)
        .expect("one block");
    let mut bytes = vec![0x80, AUDIO_PAYLOAD_TYPE];
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    bytes.extend_from_slice(&block);
    bytes
}

#[tokio::test]
async fn binds_three_distinct_ports() {
    let sockets = MediaSockets::bind("127.0.0.1:0".parse().expect("address"))
        .await
        .expect("bind");
    let ports = [
        sockets.timing_port().expect("timing"),
        sockets.control_port().expect("control"),
        sockets.data_port().expect("data"),
    ];
    assert!(ports.iter().all(|port| *port != 0));
    let mut unique = ports.to_vec();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), 3, "each socket has its own port");
}

#[tokio::test]
async fn audio_arrives_decrypted_and_in_order_over_the_data_port() {
    let key = [0x21; 16];
    let iv = [0x43; 16];
    let sockets = MediaSockets::bind("127.0.0.1:0".parse().expect("address"))
        .await
        .expect("bind");
    let mut session = session(key, iv);
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
    let data: SocketAddr = format!("127.0.0.1:{}", sockets.data_port().expect("port"))
        .parse()
        .expect("address");

    // The first packet fixes the starting point, so it arrives first; the
    // third one then waits for the second.
    client
        .send_to(&datagram(1, 480, &key, &iv), data)
        .await
        .expect("send");
    let first = sockets.receive_audio(&mut session).await.expect("receive");
    assert_eq!(first.len(), 1);
    client
        .send_to(&datagram(3, 1440, &key, &iv), data)
        .await
        .expect("send");
    let frames = sockets.receive_audio(&mut session).await.expect("receive");
    assert!(frames.is_empty(), "3 waits for 2");

    client
        .send_to(&datagram(2, 960, &key, &iv), data)
        .await
        .expect("send");
    let frames = sockets.receive_audio(&mut session).await.expect("receive");
    assert_eq!(
        frames
            .iter()
            .map(|frame| frame.sequence)
            .collect::<Vec<_>>(),
        [2, 3]
    );
    assert!(
        frames.iter().all(|frame| frame.payload == vec![0x8c; 16]),
        "delivered decrypted"
    );
}

#[tokio::test]
async fn a_resend_on_the_control_port_closes_a_gap() {
    let key = [0x65; 16];
    let iv = [0x87; 16];
    let sockets = MediaSockets::bind("127.0.0.1:0".parse().expect("address"))
        .await
        .expect("bind");
    let mut session = session(key, iv);
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
    let data: SocketAddr = format!("127.0.0.1:{}", sockets.data_port().expect("port"))
        .parse()
        .expect("address");
    let control: SocketAddr = format!("127.0.0.1:{}", sockets.control_port().expect("port"))
        .parse()
        .expect("address");

    client
        .send_to(&datagram(1, 480, &key, &iv), data)
        .await
        .expect("send");
    assert_eq!(
        sockets
            .receive_audio(&mut session)
            .await
            .expect("first")
            .len(),
        1
    );
    // 3 arrives, 2 is missing and the receiver would ask for it.
    client
        .send_to(&datagram(3, 1440, &key, &iv), data)
        .await
        .expect("send");
    assert!(
        sockets
            .receive_audio(&mut session)
            .await
            .expect("third")
            .is_empty()
    );

    // The client answers on the control port, with the audio at offset four.
    let mut wrapped = vec![0x80, 0x56 | 0x80, 0x00, 0x00];
    wrapped.extend_from_slice(&datagram(2, 960, &key, &iv));
    client.send_to(&wrapped, control).await.expect("send");
    let frames = sockets.receive_control(&mut session).await.expect("resent");
    assert_eq!(
        frames
            .iter()
            .map(|frame| frame.sequence)
            .collect::<Vec<_>>(),
        [2, 3]
    );
    assert!(session.take_lost().is_empty(), "the gap was filled");
}

/// A mirror packet with `payload` after the header.
fn mirror_packet(kind: (u8, u8), payload: &[u8]) -> Vec<u8> {
    use crate::media::mirror::HEADER_LEN;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.push(kind.0);
    bytes.push(kind.1);
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    bytes.resize(HEADER_LEN, 0);
    bytes.extend_from_slice(payload);
    bytes
}

#[tokio::test]
async fn an_explicit_port_is_the_port_that_answers() {
    // Pick a free port by asking for one, releasing it, and asking for it by number.
    // The window between the two is a race in theory and not in this test: the kernel
    // hands out the next ephemeral port rather than the one just released.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("probe");
    let port = probe.local_addr().expect("address").port();
    drop(probe);
    let sockets = MediaSockets::bind_ports(
        "127.0.0.1:0".parse().expect("address"),
        MediaPorts {
            mirror: port,
            ..MediaPorts::automatic()
        },
    )
    .await
    .expect("bind");
    assert_eq!(sockets.mirror_port().expect("port"), port);
}

#[tokio::test]
async fn a_mirror_client_connects_and_its_packets_survive_short_reads() {
    use crate::media::mirror::MirrorKind;
    let sockets = MediaSockets::bind("127.0.0.1:0".parse().expect("address"))
        .await
        .expect("bind");
    let port = sockets.mirror_port().expect("port");
    let writer = tokio::spawn(async move {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        use tokio::io::AsyncWriteExt;
        let packet = mirror_packet((0x01, 0x00), &[0x67, 0x42, 0x00, 0x1e]);
        // A TCP stream splits where it likes: the test writes the packet in
        // three pieces, so the reader has to keep asking until it has all of
        // it rather than trusting one read.
        for piece in packet.chunks(13) {
            client.write_all(piece).await.expect("write");
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    });
    let mut stream = sockets.accept_mirror().await.expect("accept");
    let (header, payload) = stream.read_packet().await.expect("read").expect("a packet");
    assert_eq!(header.kind, MirrorKind::CodecData);
    assert_eq!(header.timestamp, 0x1122_3344_5566_7788);
    assert_eq!(payload, [0x67, 0x42, 0x00, 0x1e]);
    writer.await.expect("writer");
}

#[tokio::test]
async fn a_mirror_client_that_disconnects_ends_the_stream() {
    let sockets = MediaSockets::bind("127.0.0.1:0".parse().expect("address"))
        .await
        .expect("bind");
    let port = sockets.mirror_port().expect("port");
    tokio::spawn(async move {
        let client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        drop(client);
    });
    let mut stream = sockets.accept_mirror().await.expect("accept");
    assert!(stream.read_packet().await.expect("read").is_none());
}

#[tokio::test]
async fn the_loop_hands_audio_to_the_callback_while_a_control_packet_is_pending() {
    let key = [0x0f; 16];
    let iv = [0xf0; 16];
    let sockets = MediaSockets::bind("127.0.0.1:0".parse().expect("address"))
        .await
        .expect("bind");
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
    let data: SocketAddr = format!("127.0.0.1:{}", sockets.data_port().expect("port"))
        .parse()
        .expect("address");
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let collected = std::sync::Arc::clone(&seen);

    // The loop runs until the test stops it, so it is aborted rather than
    // awaited to completion.
    let serving = {
        let mut session = session(key, iv);
        tokio::spawn(async move {
            sockets
                .serve(
                    &mut session,
                    &Received::default(),
                    move |frame| {
                        collected.lock().expect("lock").push(frame.sequence);
                    },
                    |_answer| {},
                )
                .await
        })
    };

    for sequence in [1u16, 2, 3] {
        client
            .send_to(
                &datagram(sequence, u32::from(sequence) * 480, &key, &iv),
                data,
            )
            .await
            .expect("send");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let sequences = seen.lock().expect("lock").clone();
    assert_eq!(sequences, [1, 2, 3], "every packet reached the callback");
    serving.abort();
}

#[tokio::test]
async fn the_timing_port_hands_the_datagram_to_the_caller() {
    let sockets = MediaSockets::bind("127.0.0.1:0".parse().expect("address"))
        .await
        .expect("bind");
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
    let timing: SocketAddr = format!("127.0.0.1:{}", sockets.timing_port().expect("port"))
        .parse()
        .expect("address");
    let response = [0x80, 0x53 | 0x80, 0x00, 0x07];
    client.send_to(&response, timing).await.expect("send");
    assert_eq!(
        sockets.receive_timing().await.expect("timing"),
        response.to_vec()
    );
}
