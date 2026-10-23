// SPDX-License-Identifier: GPL-3.0-or-later
//! One accepted control connection.
//!
//! The loop is the port of `upstream/UxPlay@3dbf7cee:lib/httpd.c:371-640`: read bytes,
//! frame them into requests, answer each one, and stop when the peer closes or
//! when the connection stops making progress.

use std::io::{ErrorKind, Result};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};

use crate::control::{ControlError, ControlOutcome, ControlSession, RouteHandler, request_length};

/// Bytes read from the socket at a time.
///
/// A request head is limited to [`crate::wire::DEFAULT_MAX_HEAD`], so a client
/// that sends one oversized head is refused after a few reads instead of
/// growing the buffer without bound.
const READ_CHUNK: usize = 8 * 1024;

/// Bytes of a rejected request that may be scanned for the protocol to echo.
const PROTOCOL_SNIFF_BYTES: usize = 512;

/// Serves one connection until the peer closes it, it becomes idle, or a
/// request cannot be framed.
pub(super) async fn serve<H: RouteHandler>(
    socket: TcpStream,
    peer: std::net::SocketAddr,
    mut handlers: H,
    idle_timeout: Duration,
    audio_delay_micros: u32,
    feedback_timeout: Option<Duration>,
) -> Result<()> {
    // Upstream leaves Nagle enabled on control connections; a control reply is
    // one small write, so the port disables it to avoid delaying each answer by
    // the TCP delayed-ack timer.
    socket.set_nodelay(true)?;
    let (mut reader, mut writer) = socket.into_split();
    // Upstream closes a session whose client stopped asking for feedback
    // (`uxplay.cpp:577-587`). The handler set records the last request; this loop is what
    // acts on it, because a socket nobody reads is not a connection worth keeping open.
    let feedback_clock = handlers.feedback_clock();
    let feedback_deadline = feedback_timeout.map(|timeout| {
        let clock = feedback_clock.clone();
        (timeout, clock)
    });
    let mut session = ControlSession::new();
    // Upstream reports the audio delay on `RECORD`, and a caller sets it with `-al`.
    session.set_audio_delay_micros(audio_delay_micros);
    // A `SETUP` on this connection needs to know where to send the clock exchange,
    // which is the address the connection came from (`raop_ntp.c:617-618`).
    session.set_peer(peer);
    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = [0u8; READ_CHUNK];
    // Upstream removes a connection that has been silent for longer than its
    // `timeout_limit` (`upstream/UxPlay@3dbf7cee:lib/httpd.c:377`, `:473-478`),
    // but only checks that age once the socket becomes readable again, so a
    // client that simply goes quiet keeps its slot. The port treats the same
    // limit as a deadline, and bytes that continue an unfinished request do not
    // refresh it, so a client cannot hold a slot by dribbling.
    let mut deadline = Instant::now() + idle_timeout;

    loop {
        match request_length(&buffer) {
            Ok(Some(length)) => {
                let outcome = session.handle_with(&buffer[..length], &mut handlers);
                buffer.drain(..length);
                deadline = Instant::now() + idle_timeout;
                match outcome {
                    Ok(ControlOutcome::Respond(response)) => {
                        // `TEARDOWN` asks for the close with a header, a failed
                        // `/pair-verify` signature only through the flag.
                        let close = response.close_after_reply
                            || response
                                .header("Connection")
                                .is_some_and(|value| value.eq_ignore_ascii_case("close"));
                        writer.write_all(&response.to_bytes()).await?;
                        writer.flush().await?;
                        if close {
                            close_connection(&mut writer).await?;
                            return Ok(());
                        }
                    }
                    // `raop.c:247-250` and `:263-266`: upstream answers a
                    // request it cannot use with nothing at all.
                    Ok(ControlOutcome::Ignored) => {}
                    Err(error) => {
                        reject(&mut writer, &buffer, &error).await?;
                        return Ok(());
                    }
                }
                // A client may write several requests in one segment, and the
                // read below is the only thing that refills the buffer, so the
                // buffer is drained of complete requests before blocking.
                continue;
            }
            Ok(None) => {}
            Err(error) => {
                reject(&mut writer, &buffer, &error).await?;
                return Ok(());
            }
        }

        let now = Instant::now();
        if now >= deadline {
            return Ok(());
        }
        // A session kept alive by `/feedback` also expires by it: a client that stops
        // asking has gone, even if its socket has not closed. Upstream checks the same
        // limit and resets the session (`uxplay.cpp:577-587`). The read below is capped
        // by whichever deadline is nearer, because a socket that stays silent would
        // otherwise keep this loop asleep past the feedback timeout.
        let mut wait = deadline - now;
        if let Some((timeout, clock)) = &feedback_deadline
            && let Some(clock) = clock
        {
            let quiet =
                now_millis().saturating_sub(clock.load(std::sync::atomic::Ordering::Relaxed));
            let limit = timeout.as_millis() as u64;
            if quiet >= limit {
                return Ok(());
            }
            wait = wait.min(Duration::from_millis((limit - quiet).max(1)));
        }
        match timeout(wait, reader.read(&mut chunk)).await {
            // Either deadline has passed; the top of the loop decides which, and whether
            // the connection is finished.
            Err(_elapsed) => continue,
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(read)) => {
                let start_of_request = buffer.is_empty();
                buffer.extend_from_slice(&chunk[..read]);
                if start_of_request {
                    deadline = Instant::now() + idle_timeout;
                }
            }
            Ok(Err(error)) => return Err(error),
        }
    }
}

/// Milliseconds since the Unix epoch, for the feedback clock.
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or(0)
}

/// Writes the rejection response for `error` and closes the connection.
///
/// A rejected request cannot be framed, so the bytes after it cannot be trusted
/// either: upstream removes the connection when its parser rejects a request
/// (`upstream/UxPlay@3dbf7cee:lib/httpd.c:574-585`), and the port answers once and then
/// closes instead of guessing where the next request starts.
async fn reject<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    buffer: &[u8],
    error: &ControlError,
) -> Result<()> {
    let response = error.to_response(protocol_of(buffer));
    writer.write_all(&response.to_bytes()).await?;
    writer.flush().await?;
    close_connection(writer).await
}

/// Half-closes the write side, which is what upstream does before it closes a
/// connection (`upstream/UxPlay@3dbf7cee:lib/httpd.c:214-254`).
async fn close_connection<W: AsyncWriteExt + Unpin>(writer: &mut W) -> Result<()> {
    match writer.shutdown().await {
        Ok(()) => Ok(()),
        // The peer may have closed first; that is not a failure of this side.
        Err(error) if error.kind() == ErrorKind::NotConnected => Ok(()),
        Err(error) => Err(error),
    }
}

/// Protocol to echo in a rejection response.
///
/// A request the port rejects may have no parsable head, so the first request
/// line is scanned for the protocol name. `RTSP/1.0` is the fallback because
/// that is the protocol of the control service a receiver advertises; upstream
/// echoes the protocol its parser recognised (`raop.c:237`).
fn protocol_of(input: &[u8]) -> &'static str {
    let window = &input[..input.len().min(PROTOCOL_SNIFF_BYTES)];
    let line = window
        .split(|byte| *byte == b'\r' || *byte == b'\n')
        .next()
        .unwrap_or(window);
    let version = line.rsplit(|byte| *byte == b' ').next().unwrap_or(line);
    if version.starts_with(b"HTTP/") {
        "HTTP/1.1"
    } else {
        "RTSP/1.0"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{DeviceIdentity, RouteHandlers};

    #[test]
    fn protocol_of_reads_the_version_of_a_request_line() {
        assert_eq!(
            protocol_of(b"GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n"),
            "RTSP/1.0"
        );
        assert_eq!(protocol_of(b"POST /reverse HTTP/1.1\r\n\r\n"), "HTTP/1.1");
        // An oversized head without a line ending still names its protocol.
        let oversized = [b"x".repeat(PROTOCOL_SNIFF_BYTES), b" HTTP/1.1".to_vec()].concat();
        assert_eq!(protocol_of(&oversized), "RTSP/1.0");
        assert_eq!(protocol_of(b""), "RTSP/1.0");
    }

    #[tokio::test]
    async fn serve_answers_and_closes_after_a_rejected_request() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            serve(
                socket,
                peer,
                RouteHandlers::new(DeviceIdentity::default()),
                Duration::from_secs(5),
                crate::control::DEFAULT_AUDIO_DELAY_MICROS,
                None,
            )
            .await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /info HTTP/1.1\r\nBad Header\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(
            response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
            "unexpected response: {}",
            String::from_utf8_lossy(&response)
        );
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_session_without_feedback_is_closed_by_its_timeout() {
        // Upstream's `-reset`: a client that stops asking for feedback has gone, even
        // though its socket has not closed. A connection whose handler records feedback
        // and then receives none must expire.
        use std::time::Instant as StdInstant;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let timeout = Duration::from_millis(50);
        let server = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            serve(
                socket,
                peer,
                RouteHandlers::new(DeviceIdentity::default()),
                Duration::from_secs(30),
                crate::control::DEFAULT_AUDIO_DELAY_MICROS,
                Some(timeout),
            )
            .await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        // A request that is not feedback does not refresh the clock.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client
            .write_all(
                b"OPTIONS * RTSP/1.0
CSeq: 1

",
            )
            .await
            .unwrap();
        let started = StdInstant::now();
        let mut buffer = [0u8; 64];
        let _ = client.read(&mut buffer).await;
        // The answer arrives, then the connection closes; reading again returns end of
        // stream once the timeout fires.
        let closed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let mut sink = [0u8; 64];
                match client.read(&mut sink).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        })
        .await;
        assert!(
            closed.is_ok(),
            "the connection outlived its feedback timeout"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "closed after {:?}",
            started.elapsed()
        );
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn serve_closes_an_idle_connection() {
        use std::time::Instant as StdInstant;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let idle_timeout = Duration::from_millis(50);
        let server = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            serve(
                socket,
                peer,
                RouteHandlers::new(DeviceIdentity::default()),
                idle_timeout,
                crate::control::DEFAULT_AUDIO_DELAY_MICROS,
                None,
            )
            .await
        });

        let _client = TcpStream::connect(addr).await.unwrap();
        let started = StdInstant::now();
        server.await.unwrap().unwrap();
        assert!(started.elapsed() >= idle_timeout);
    }
}
