// SPDX-License-Identifier: GPL-3.0-or-later
//! The sockets one media session listens on.
//!
//! A client does not send media anywhere it likes: `SETUP` tells it which ports
//! to use, and until now this crate told it nothing, because nothing was
//! listening. This module binds the three sockets an audio session needs and
//! drives the receive path over them, so the ports a receiver advertises are the
//! ports that answer:
//!
//! - the **timing** port, where the clock exchange happens (`media::timing`),
//! - the **control** port, where resends and sync packets arrive
//!   (`media::control`),
//! - the **data** port, where the audio datagrams arrive (`media::audio`).
//!
//! Upstream opens exactly these three for an audio session
//! (`upstream/UxPlay@3dbf7cee:lib/raop_rtp.c:236-244`, which binds a control and
//! a data socket beside the timing socket of `raop_ntp.c`). The mirror stream
//! adds a TCP listener, and arrives with its own slice.
//!
//! Nothing here decides policy: the key and IV come from the `SETUP` that a
//! caller accepted, and frames go to a caller's callback, which is where a
//! renderer plugs in ([the architecture document](../../../docs/ARCHITECTURE.md)).

use std::net::SocketAddr;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use super::audio::{AudioFrame, AudioSession, WINDOW_CAPACITY};

/// Largest datagram this receiver reads.
///
/// Upstream reads into a fixed buffer too (`raop_rtp.c`), and an audio datagram
/// is far below this: the bound exists so a client cannot make a receiver
/// allocate by sending something enormous.
pub const MAX_DATAGRAM: usize = 2048;

/// The sockets one audio session listens on.
#[derive(Debug)]
pub struct MediaSockets {
    timing: UdpSocket,
    control: UdpSocket,
    data: UdpSocket,
    /// The mirror stream arrives over TCP, beside the audio sockets.
    mirror: TcpListener,
}

/// The ports a media session binds, with `0` meaning "the system picks".
///
/// Upstream's `-p n` and `-p` are this: a fixed layout is easier to firewall and easier to
/// forward, and ephemeral ports are the default because two receivers on one machine must
/// not fight over them. The mapping is upstream's (`raop.c:784-793`): its `udp[0..2]` are
/// timing, control and data, and its `tcp[0]` is the mirror listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MediaPorts {
    /// UDP timing port.
    pub timing: u16,
    /// UDP control port, where resends arrive.
    pub control: u16,
    /// UDP data port, where audio arrives.
    pub data: u16,
    /// TCP listener the mirror stream connects to.
    pub mirror: u16,
}

impl MediaPorts {
    /// Every port chosen by the system, which is the default.
    #[must_use]
    pub fn automatic() -> Self {
        Self::default()
    }

    /// Upstream's `-p` without a value: the layout an old client expects.
    ///
    /// Upstream binds UDP 7011 timing, 6001 control and 6000 data, and TCP 7100 for the
    /// mirror stream (`uxplay.cpp:1693-1694`). Its control port, 7000, is this crate's
    /// [`crate::Config::port`] rather than one of these.
    #[must_use]
    pub fn legacy() -> Self {
        Self {
            timing: 7011,
            control: 6001,
            data: 6000,
            mirror: 7100,
        }
    }
}

impl MediaSockets {
    /// Binds the three sockets on `bind`, letting the system pick the ports.
    ///
    /// # Errors
    ///
    /// Returns the underlying error when a socket cannot be bound.
    pub async fn bind(bind: SocketAddr) -> std::io::Result<Self> {
        Self::bind_ports(bind, MediaPorts::automatic()).await
    }

    /// Binds the sockets on `bind`, on the ports `ports` names, with `0` meaning "pick".
    ///
    /// # Errors
    ///
    /// Returns the underlying error when a port cannot be bound, which for a fixed port
    /// means it is in use or reserved - the reason a caller asked for one is usually the
    /// reason it is not free.
    pub async fn bind_ports(bind: SocketAddr, ports: MediaPorts) -> std::io::Result<Self> {
        let with = |port: u16| SocketAddr::new(bind.ip(), port);
        Ok(Self {
            timing: UdpSocket::bind(with(ports.timing)).await?,
            control: UdpSocket::bind(with(ports.control)).await?,
            data: UdpSocket::bind(with(ports.data)).await?,
            mirror: TcpListener::bind(with(ports.mirror)).await?,
        })
    }

    /// Port of the timing socket.
    ///
    /// # Errors
    ///
    /// Returns the underlying error when the socket has no local address.
    pub fn timing_port(&self) -> std::io::Result<u16> {
        Ok(self.timing.local_addr()?.port())
    }

    /// Port of the control socket.
    ///
    /// # Errors
    ///
    /// Returns the underlying error when the socket has no local address.
    pub fn control_port(&self) -> std::io::Result<u16> {
        Ok(self.control.local_addr()?.port())
    }

    /// Port of the data socket.
    ///
    /// # Errors
    ///
    /// Returns the underlying error when the socket has no local address.
    pub fn data_port(&self) -> std::io::Result<u16> {
        Ok(self.data.local_addr()?.port())
    }

    /// Port of the mirror listener.
    ///
    /// # Errors
    ///
    /// Returns the underlying error when the listener has no local address.
    pub fn mirror_port(&self) -> std::io::Result<u16> {
        Ok(self.mirror.local_addr()?.port())
    }

    /// Waits for a mirroring client to connect.
    ///
    /// # Errors
    ///
    /// Returns the underlying error when the listener cannot accept.
    pub async fn accept_mirror(&self) -> std::io::Result<MirrorStream> {
        let (stream, _) = self.mirror.accept().await?;
        Ok(MirrorStream { stream })
    }

    /// Receives one audio datagram and returns what became ready.
    ///
    /// # Errors
    ///
    /// Returns the underlying error when the socket cannot be read; a datagram
    /// that is not audio is not an error, it is ignored the way a receiver
    /// ignores traffic it cannot use.
    pub async fn receive_audio(
        &self,
        session: &mut AudioSession,
    ) -> std::io::Result<Vec<AudioFrame>> {
        let mut buffer = [0u8; MAX_DATAGRAM];
        let length = self.data.recv(&mut buffer).await?;
        Ok(session.receive(&buffer[..length]).unwrap_or_default())
    }

    /// Receives one control datagram and returns what became ready.
    ///
    /// # Errors
    ///
    /// Returns the underlying error when the socket cannot be read.
    pub async fn receive_control(
        &self,
        session: &mut AudioSession,
    ) -> std::io::Result<Vec<AudioFrame>> {
        let mut buffer = [0u8; MAX_DATAGRAM];
        let length = self.control.recv(&mut buffer).await?;
        Ok(session
            .receive_control(&buffer[..length])
            .unwrap_or_default())
    }

    /// Receives one timing datagram, which is an answer to a request this
    /// receiver sent.
    ///
    /// # Errors
    ///
    /// Returns the underlying error when the socket cannot be read.
    pub async fn receive_timing(&self) -> std::io::Result<Vec<u8>> {
        let mut buffer = [0u8; MAX_DATAGRAM];
        let length = self.timing.recv(&mut buffer).await?;
        Ok(buffer[..length].to_vec())
    }

    /// Sends the clock exchange's request to a client.
    ///
    /// The receiver starts this exchange, not the client: upstream sends its first
    /// request as soon as `SETUP` is answered and keeps sending them
    /// (`upstream/UxPlay@3dbf7cee:lib/raop_ntp.c:614-618`, `:839-841`). A session
    /// that waits to be asked never ticks, and a client with no clock to agree on
    /// has no reason to send its media.
    ///
    /// # Errors
    ///
    /// Returns the underlying error when the request cannot be sent.
    pub async fn send_timing_request(
        &self,
        client: SocketAddr,
        request: &[u8],
    ) -> std::io::Result<usize> {
        self.timing.send_to(request, client).await
    }
}

/// One audio session's sockets, and what has arrived on them.
///
/// The counters exist because "no sound" has two very different causes — a client
/// that never sent anything, and a receiver that threw everything away — and a
/// session that cannot tell them apart cannot be diagnosed. They are read by a
/// caller that logs, not by the receive path itself.
#[derive(Debug, Default)]
pub struct Received {
    mirror: std::sync::atomic::AtomicU64,
    mirror_bytes: std::sync::atomic::AtomicU64,
    timing: std::sync::atomic::AtomicU64,
    control: std::sync::atomic::AtomicU64,
    data: std::sync::atomic::AtomicU64,
    unusable: std::sync::atomic::AtomicU64,
    last_error: std::sync::Mutex<Option<String>>,
}

impl Received {
    /// Packets that arrived on a mirror connection.
    ///
    /// A mirror stream is a byte stream, so "nothing arrived" and "we stopped
    /// reading" look the same from the outside; this is the number that tells them
    /// apart, and it is the first thing to look at when a picture stops moving.
    pub fn mirror(&self) -> u64 {
        self.mirror.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Bytes that arrived on a mirror connection.
    pub fn mirror_bytes(&self) -> u64 {
        self.mirror_bytes.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Records one mirror packet of `bytes`.
    pub fn saw_mirror(&self, bytes: usize) {
        self.mirror
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.mirror_bytes
            .fetch_add(bytes as u64, std::sync::atomic::Ordering::Relaxed);
    }

    /// Datagrams that arrived on the timing port.
    pub fn timing(&self) -> u64 {
        self.timing.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Datagrams that arrived on the control port.
    pub fn control(&self) -> u64 {
        self.control.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Datagrams that arrived on the data port.
    pub fn data(&self) -> u64 {
        self.data.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Datagrams that arrived and could not be used.
    pub fn unusable(&self) -> u64 {
        self.unusable.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The most recent reason a datagram was thrown away.
    pub fn last_error(&self) -> Option<String> {
        self.last_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Records a datagram that could not be used, keeping the first reason.
    ///
    /// The first one is kept rather than the last: a stream that has gone wrong
    /// usually keeps saying the same thing, and the first is the one that was not
    /// caused by the stream already being wrong.
    fn reject(&self, reason: String) {
        self.unusable
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut slot = self
            .last_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(reason);
        }
    }
}

impl MediaSockets {
    /// Serves the session until a socket fails, handing every ready frame to
    /// `on_frame`.
    ///
    /// The three sockets are watched together, because a session that read them
    /// one after another would stop draining audio while it waited for a control
    /// packet. A datagram this session cannot use is counted in `received` and
    /// then ignored rather than being fatal: a client that sends something
    /// unexpected does not end the session.
    ///
    /// # Errors
    ///
    /// Returns the underlying error when a socket stops being readable. The
    /// caller decides what that means for the session; this function does not
    /// retry, because a receiver that silently reopens a socket hides the
    /// problem from whoever is watching it.
    pub async fn serve(
        &self,
        session: &mut AudioSession,
        received: &Received,
        mut on_frame: impl FnMut(AudioFrame),
        mut on_timing: impl FnMut(&[u8]),
    ) -> std::io::Result<()> {
        use std::sync::atomic::Ordering;
        use tokio::select;
        let mut audio = [0u8; MAX_DATAGRAM];
        let mut control = [0u8; MAX_DATAGRAM];
        let mut timing = [0u8; MAX_DATAGRAM];
        loop {
            select! {
                result = self.data.recv(&mut audio) => {
                    let length = result?;
                    received.data.fetch_add(1, Ordering::Relaxed);
                    match session.receive(&audio[..length]) {
                        Ok(frames) => {
                            for frame in frames {
                                on_frame(frame);
                            }
                        }
                        Err(error) => received.reject(error.to_string()),
                    }
                }
                result = self.control.recv(&mut control) => {
                    let length = result?;
                    received.control.fetch_add(1, Ordering::Relaxed);
                    match session.receive_control(&control[..length]) {
                        Ok(frames) => {
                            for frame in frames {
                                on_frame(frame);
                            }
                        }
                        Err(error) => received.reject(error.to_string()),
                    }
                }
                result = self.timing.recv(&mut timing) => {
                    // The clock exchange is a request this receiver sends and an answer
                    // the client sends back, so the socket has to be drained here as well
                    // as written to. What the answer means is the caller's: this only
                    // reports the bytes and counts them.
                    let length = result?;
                    received.timing.fetch_add(1, Ordering::Relaxed);
                    on_timing(&timing[..length]);
                }
            }
        }
    }
}

/// One mirroring client's connection.
///
/// A TCP stream does not arrive in packets, so the reader asks for exactly the
/// header and then exactly the payload the header promised
/// (`upstream/UxPlay@3dbf7cee:lib/raop_rtp_mirror.c:298-302` loops the same way),
/// which is why a short read is handled here rather than by a caller.
#[derive(Debug)]
pub struct MirrorStream {
    stream: TcpStream,
}

impl MirrorStream {
    /// Reads packets until the client closes the connection, handing every frame to
    /// `on_frame`.
    ///
    /// A packet that is not a frame — a keep-alive, a streaming report, the codec
    /// configuration — is not reported: a caller's callback is for video, and
    /// [`super::mirror::MirrorSession`] is where the rest is kept. A packet that is
    /// not a frame *and* not something the session can place is reported to the
    /// caller as an error, because a stream that has come apart is not something to
    /// keep reading blindly.
    ///
    /// # Errors
    ///
    /// Returns the underlying error when the connection fails, and a
    /// [`super::mirror::FrameError`] when a packet does not fit the stream.
    pub async fn serve(
        &mut self,
        session: &mut super::mirror::MirrorSession,
        mut on_packet: impl FnMut(&super::mirror::MirrorHeader, usize),
        mut on_frame: impl FnMut(super::mirror::VideoFrame, super::mirror::StreamInfo),
    ) -> Result<(), ServeError> {
        while let Some((header, payload)) = self.read_packet().await? {
            // Every packet, before it is interpreted: a mirror stream is a byte
            // stream, so a caller that is only told about frames cannot tell "the
            // client stopped sending" from "we stopped reading", and those are
            // different problems.
            on_packet(&header, payload.len());
            match session.receive(&header, &payload) {
                Ok(Some(frame)) => on_frame(frame, session.info()),
                Ok(None) => {}
                // A frame that cannot be read is upstream's "invalid frame", which it
                // marks and passes on rather than ending the connection
                // (`raop_rtp_mirror.c:533-536`). A packet that is off the stream is
                // not: the receiver has lost the keystream and cannot recover it by
                // reading more packets.
                Err(super::mirror::FrameError::NotUnits(_)) => {}
                Err(error) => return Err(ServeError::Frame(error)),
            }
        }
        Ok(())
    }

    /// Reads one packet, or `None` when the client closed the connection.
    ///
    /// # Errors
    ///
    /// Returns the underlying error when the connection fails, and
    /// [`crate::media::mirror::MirrorError`] when what arrived is not a packet this receiver reads.
    pub async fn read_packet(
        &mut self,
    ) -> std::io::Result<Option<(crate::media::mirror::MirrorHeader, Vec<u8>)>> {
        let mut header = [0u8; crate::media::mirror::HEADER_LEN];
        match self.stream.read_exact(&mut header).await {
            Ok(_) => {}
            // The client closing the stream is how a mirror session ends.
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error),
        }
        let header = match crate::media::mirror::parse_header(&header) {
            Ok(header) => header,
            // A header this receiver cannot read says what the bytes actually were:
            // a wrong length is read once and then everything after it is read from
            // the wrong place, so the bytes are the only thing that says whether the
            // framing was wrong or the stream simply was not a mirror stream.
            Err(error) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{error} (first 128 bytes: {})", hex_preview(&header)),
                ));
            }
        };
        let mut payload = vec![0u8; header.payload_size as usize];
        self.stream.read_exact(&mut payload).await?;
        // What the first packets are, for a device whose codec data has to be read
        // rather than assumed: a mirror stream carries either coding and the packet
        // that announces which one is the one worth seeing.
        if std::env::var("AIRPLAY_DEBUG_MIRROR").is_ok() {
            eprintln!(
                "MIRROR packet kind={:?} payload={} option=0x{:04x} ts={} bytes: {}",
                header.kind,
                payload.len(),
                header.option,
                header.timestamp,
                hex_preview(&payload)
            );
        }
        Ok(Some((header, payload)))
    }
}

/// Creates a session for a `SETUP` that carried `key` and `iv`.
pub fn session(key: [u8; 16], iv: [u8; 16]) -> AudioSession {
    AudioSession::new(key, iv, WINDOW_CAPACITY)
}

/// Why serving a mirror stream stopped.
///
/// The two cases are kept apart because they mean different things to a caller: a
/// connection that failed can be retried, while a stream this receiver has lost
/// cannot be picked up again by reading more packets.
#[derive(Debug)]
pub enum ServeError {
    /// The connection itself failed, or the client sent something that is not a
    /// packet at all.
    Connection(std::io::Error),
    /// A packet could not be placed in the stream.
    Frame(crate::media::mirror::FrameError),
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connection(error) => write!(formatter, "the mirror connection: {error}"),
            Self::Frame(error) => write!(formatter, "the mirror stream: {error}"),
        }
    }
}

impl std::error::Error for ServeError {}

impl From<std::io::Error> for ServeError {
    fn from(error: std::io::Error) -> Self {
        Self::Connection(error)
    }
}

/// The first bytes of a packet, in hex, for a header that could not be read.
///
/// A wrong length is read once and everything after it comes from the wrong
/// place, so the bytes are the only thing that says whether the framing is wrong
/// or the stream was never a mirror stream. The whole first read is shown,
/// because a mirror header is 128 bytes and its shape is what identifies it.
pub(crate) fn hex_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(128)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::audio::AUDIO_PAYLOAD_TYPE;

    /// A datagram with the audio header upstream documents, encrypted with the
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
}
