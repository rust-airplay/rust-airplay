// SPDX-License-Identifier: GPL-3.0-or-later
//! The UDP audio sockets and the mirror listener.

use std::net::SocketAddr;

use tokio::net::{TcpListener, UdpSocket};

use super::mirror::MirrorStream;
use crate::media::audio::{AudioFrame, AudioSession};

/// Largest datagram this receiver reads.
///
/// The protocol reads into a fixed buffer too, and an audio datagram
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
/// The protocol's `-p n` and `-p` are this: a fixed layout is easier to firewall and easier to
/// forward, and ephemeral ports are the default because two receivers on one machine must
/// not fight over them. The mapping is the protocol's: its `udp[0..2]` are
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

    /// The protocol's `-p` without a value: the layout an old client expects.
    ///
    /// The protocol binds UDP 7011 timing, 6001 control and 6000 data, and TCP 7100 for the
    /// mirror stream. Its control port, 7000, is this crate's
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
        let (stream, peer) = self.mirror.accept().await?;
        Ok(MirrorStream::from_accepted(stream, peer))
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

    /// Sends one control packet to a client.
    ///
    /// A resend request is the one control packet this receiver writes: it goes from
    /// the session's control socket to the port the client named in `SETUP`.
    ///
    /// # Errors
    ///
    /// Returns the underlying error when the packet cannot be sent.
    pub async fn send_control(&self, client: SocketAddr, request: &[u8]) -> std::io::Result<usize> {
        self.control.send_to(request, client).await
    }

    /// Sends the clock exchange's request to a client.
    ///
    /// The receiver starts this exchange, not the client: the protocol sends its first
    /// request as soon as `SETUP` is answered and keeps sending them
    /// A session
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
        on_frame: impl FnMut(AudioFrame),
        on_timing: impl FnMut(&[u8]),
    ) -> std::io::Result<()> {
        self.serve_from(session, received, None, on_frame, on_timing, |_| {})
            .await
    }

    /// Serves one session, ignoring datagrams that did not come from `peer`.
    ///
    /// The media sockets are bound to an interface, not to a client: on a shared network
    /// any host can send to the data port, and a receiver that decrypts whatever arrives
    /// lets that host put frames into the renderer. A session has one client, so the
    /// source address is the cheapest thing to check.
    ///
    /// # Errors
    ///
    /// Same as [`MediaSockets::serve`].
    pub async fn serve_from(
        &self,
        session: &mut AudioSession,
        received: &Received,
        peer: Option<std::net::IpAddr>,
        mut on_frame: impl FnMut(AudioFrame),
        mut on_timing: impl FnMut(&[u8]),
        mut on_resend: impl FnMut(&[u16]),
    ) -> std::io::Result<()> {
        use std::sync::atomic::Ordering;
        use tokio::select;
        let mut audio = [0u8; MAX_DATAGRAM];
        let mut control = [0u8; MAX_DATAGRAM];
        let mut timing = [0u8; MAX_DATAGRAM];
        loop {
            select! {
                result = self.data.recv_from(&mut audio) => {
                    let (length, source) = match result {
                        Ok(packet) => packet,
                        // A UDP socket reports an ICMP unreachable as a read error on
                        // Windows. That says something about the last datagram this
                        // session sent, not about the socket: treating it as fatal ends
                        // a session that is still perfectly readable.
                        Err(error) if is_transient(&error) => {
                            received.reject(error.to_string());
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    if !source_allowed(peer, source.ip()) {
                        received.reject(format!("data from {source}"));
                        continue;
                    }
                    received.data.fetch_add(1, Ordering::Relaxed);
                    match session.receive(&audio[..length]) {
                        Ok(frames) => {
                            for frame in frames {
                                on_frame(frame);
                            }
                            let missing = session.take_resend_requests(8);
                            if !missing.is_empty() {
                                on_resend(&missing);
                            }
                        }
                        Err(error) => received.reject(error.to_string()),
                    }
                }
                result = self.control.recv_from(&mut control) => {
                    let (length, source) = match result {
                        Ok(packet) => packet,
                        Err(error) if is_transient(&error) => {
                            received.reject(error.to_string());
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    if !source_allowed(peer, source.ip()) {
                        received.reject(format!("control from {source}"));
                        continue;
                    }
                    received.control.fetch_add(1, Ordering::Relaxed);
                    match session.receive_control(&control[..length]) {
                        Ok(frames) => {
                            for frame in frames {
                                on_frame(frame);
                            }
                            let missing = session.take_resend_requests(8);
                            if !missing.is_empty() {
                                on_resend(&missing);
                            }
                        }
                        Err(error) => received.reject(error.to_string()),
                    }
                }
                result = self.timing.recv_from(&mut timing) => {
                    // The clock exchange is a request this receiver sends and an answer
                    // the client sends back, so the socket has to be drained here as well
                    // as written to. What the answer means is the caller's: this only
                    // reports the bytes and counts them.
                    let (length, source) = match result {
                        Ok(packet) => packet,
                        Err(error) if is_transient(&error) => {
                            received.reject(error.to_string());
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    if !source_allowed(peer, source.ip()) {
                        received.reject(format!("timing from {source}"));
                        continue;
                    }
                    received.timing.fetch_add(1, Ordering::Relaxed);
                    on_timing(&timing[..length]);
                }
            }
        }
    }
}

/// Whether a UDP read error describes the network rather than this socket.
///
/// A receiver that sends a timing request to a client which has already gone can be
/// told about it by an ICMP unreachable; on Windows that arrives as
/// `ConnectionReset` on the next read. The socket is still usable, so a session must
/// not be torn down by a message about a datagram that was never part of the media.
fn is_transient(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
    )
}

/// Whether a datagram came from the client the session belongs to.
///
/// A session served before its peer is known accepts what arrives; once the control
/// connection has named the peer, a datagram from another host is not part of the
/// session.
fn source_allowed(peer: Option<std::net::IpAddr>, source: std::net::IpAddr) -> bool {
    peer.is_none_or(|peer| peer == source)
}
