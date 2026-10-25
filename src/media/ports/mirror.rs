// SPDX-License-Identifier: GPL-3.0-or-later
//! A mirroring client's TCP connection.

use std::net::SocketAddr;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use super::ServeError;

/// How long a mirror connection may stay silent before it is dropped.
///
/// The listener is serial: one connection that is accepted and then sends nothing would
/// keep a real client waiting for as long as it liked.
const FIRST_MIRROR_PACKET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// One mirroring client's connection.
///
/// A TCP stream does not arrive in packets, so the reader asks for exactly the
/// header and then exactly the payload the header promised
///,
/// which is why a short read is handled here rather than by a caller.
#[derive(Debug)]
pub struct MirrorStream {
    stream: TcpStream,
    peer: SocketAddr,
}

impl MirrorStream {
    pub(crate) fn from_accepted(stream: TcpStream, peer: SocketAddr) -> Self {
        Self { stream, peer }
    }

    /// Address the mirroring client connected from.
    ///
    /// The listener knows it at accept time; a receiver that has a session's control
    /// peer can refuse a mirror stream from a different host.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Reads packets until the client closes the connection, handing every frame to
    /// `on_frame`.
    ///
    /// A packet that is not a frame — a keep-alive, a streaming report, the codec
    /// configuration — is not reported: a caller's callback is for video, and
    /// [`crate::media::mirror::MirrorSession`] is where the rest is kept. A packet that is
    /// not a frame *and* not something the session can place is reported to the
    /// caller as an error, because a stream that has come apart is not something to
    /// keep reading blindly.
    ///
    /// # Errors
    ///
    /// Returns the underlying error when the connection fails, and a
    /// [`crate::media::mirror::FrameError`] when a packet does not fit the stream.
    pub async fn serve(
        &mut self,
        session: &mut crate::media::mirror::MirrorSession,
        mut on_packet: impl FnMut(&crate::media::mirror::MirrorHeader, &[u8]),
        mut on_frame: impl FnMut(crate::media::mirror::VideoFrame, crate::media::mirror::StreamInfo),
    ) -> Result<(), ServeError> {
        let mut first = true;
        loop {
            let next = if first {
                // A connection that is accepted and then says nothing holds the one
                // mirror session a receiver serves. A real client sends its codec
                // packet as soon as it connects, so a silent one is not a slow client.
                match tokio::time::timeout(FIRST_MIRROR_PACKET_TIMEOUT, self.read_packet()).await {
                    Ok(result) => result?,
                    Err(_) => {
                        return Err(ServeError::Connection(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "the mirror connection sent nothing",
                        )));
                    }
                }
            } else {
                self.read_packet().await?
            };
            first = false;
            let Some((header, payload)) = next else {
                break;
            };
            // Every packet, before it is interpreted: a mirror stream is a byte
            // stream, so a caller that is only told about frames cannot tell "the
            // client stopped sending" from "we stopped reading", and those are
            // different problems.
            on_packet(&header, &payload);
            match session.receive(&header, &payload) {
                Ok(Some(frame)) => on_frame(frame, session.info()),
                Ok(None) => {}
                // A frame that cannot be read is the protocol's "invalid frame", which it
                // marks and passes on rather than ending the connection
                //. A packet that is off the stream is
                // not: the receiver has lost the keystream and cannot recover it by
                // reading more packets.
                Err(crate::media::mirror::FrameError::NotUnits(_)) => {}
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
        // What the packets are, for a device whose codec data has to be read rather than
        // assumed: a mirror stream carries either coding and the packet that announces
        // which one is the one worth seeing. A log record rather than a print, so the
        // program embedding this crate decides whether it is shown.
        //
        // The preview is built only when the record would be emitted. `debug!` formats
        // lazily but its arguments are evaluated when the macro is reached, and turning a
        // packet into hex for every packet of a stream is a cost a session that is not
        // being diagnosed should not pay.
        if log::log_enabled!(log::Level::Debug) {
            log::debug!(
                "mirror  packet kind={:?} payload={} option=0x{:04x} ts={} bytes: {}",
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
