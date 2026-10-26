// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded TCP control service.
//!
//! [`Server::run`] accepts control connections, frames each byte stream into
//! requests with [`crate::control::request_length`], routes every request
//! through a per-connection [`crate::control::ControlSession`] and the
//! [`RouteHandlers`] of that connection, and writes the response
//! [`crate::control::ControlResponse::to_bytes`] produces.
//!
//! # Bounds
//!
//! Every limit the service enforces is deliberate:
//!
//! * A request head is limited to [`crate::wire::DEFAULT_MAX_HEAD`] and a body to
//!   [`crate::control::MAX_CONTROL_BODY`]; both are checked before the bytes are buffered.
//! * At most [`ServerConfig::max_connections`] connections are served at once. The listener
//!   stops accepting while the limit is reached instead of rejecting a client, so further
//!   connections wait in the kernel backlog.
//! * A connection that is idle for [`ServerConfig::idle_timeout`] is closed, and bytes that
//!   continue an unfinished request do not refresh that deadline. The deadline is hard: the
//!   connection task returns when it passes, rather than waiting for the socket to become
//!   readable again.
//! * A request the service cannot frame is answered once, with
//!   [`crate::control::ControlError::to_response`], and the connection is closed, because the
//!   bytes after a rejected request cannot be trusted.
//!
//! # Connection behaviour
//!
//! `TCP_NODELAY` is enabled on accepted connections so a control reply does not wait for the
//! delayed-ack timer. A route this layer answers itself is answered without touching the
//! handler set; one that carries a session's keys or streams goes to the connection's
//! [`RouteHandlers`].

mod connection;
mod handlers;
mod pairing;

use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::control::RouteHandler;

pub use handlers::{
    AUDIO_OUTPUT_FORMATS, ClientPolicy, ClientRequest, DEFAULT_FEATURES, DEFAULT_HEIGHT,
    DEFAULT_MAX_FPS, DEFAULT_MODEL, DEFAULT_PI, DEFAULT_REFRESH_RATE, DEFAULT_SOURCE_VERSION,
    DEFAULT_VV, DEFAULT_WIDTH, DISPLAY_FEATURES, DISPLAY_UUID, DeviceIdentity, Display,
    RouteHandlers, STATUS_FLAGS, SetParameter, SetupPorts, SetupRequest, SetupStream,
};
pub use pairing::{
    MAX_PIN_FAILURES, OsRandom, PairingError, PairingState, PinMode, RandomError, RandomSource,
    SessionAuth,
};

/// Connections the protocol serves at the same time
///, which is the default of
/// [`ServerConfig::max_connections`].
pub const MAX_CONNECTIONS: usize = 12;

/// How long a connection may make no progress before it is closed, which is the
/// default of [`ServerConfig::idle_timeout`].
///
/// It matches the `timeout_limit = 60` the protocol added for dead connections
///, with one difference the module
/// documentation describes: the port applies it as a deadline, the protocol only
/// when the socket becomes readable again.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// How a [`Server`] listens and how many clients it serves.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct ServerConfig {
    /// Address to listen on.
    ///
    /// Port `0` binds an ephemeral port, which is what the protocol does before it
    /// advertises the assigned port (,
    /// `:834-837`); a receiver that is discovered over mDNS does not need a
    /// fixed one.
    pub bind: SocketAddr,
    /// Largest number of connections served at once, at least `1`.
    pub max_connections: usize,
    /// How long a connection may stop making progress before it is closed.
    pub idle_timeout: Duration,
    /// Whether a new client takes over from the current one.
    ///
    /// The protocol's `-nohold`. Off by default: a second client's connection is refused, as
    /// the protocol refuses it with `409 Conflict` when a session is already running
    /// Turned on, a new connection drops the previous one **from the same host**, which
    /// is what a person switching phones expects. A connection from another host keeps
    /// its slot: it is another client, not the session being replaced. This crate admits
    /// several connections at once by default, so the flag only adds the takeover.
    pub nohold: bool,
    /// How long a session may go without a `/feedback` request before it is closed.
    ///
    /// The protocol's `-reset`, and its default is fifteen seconds. `None`
    /// leaves a silent client connected, which is what this crate did before the option
    /// existed.
    pub feedback_timeout: Option<Duration>,
    /// Audio delay reported to a client by `RECORD`, in microseconds.
    ///
    /// This is the protocol's `-al`: the value the client sees in `Audio-Latency` and
    /// schedules its own playback against. Zero is legal and means "play as soon as
    /// it arrives"; the range is checked when it is set.
    pub audio_delay_micros: u32,
    /// Identity the handlers advertise to clients.
    pub device: DeviceIdentity,
}

impl Default for ServerConfig {
    /// Listens on every interface with an ephemeral port, serves
    /// [`MAX_CONNECTIONS`] connections and closes an idle connection after
    /// [`DEFAULT_IDLE_TIMEOUT`].
    fn default() -> Self {
        Self {
            bind: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            max_connections: MAX_CONNECTIONS,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            nohold: false,
            feedback_timeout: None,
            audio_delay_micros: crate::control::DEFAULT_AUDIO_DELAY_MICROS,
            device: DeviceIdentity::default(),
        }
    }
}

/// A bound control service that has not started accepting yet.
///
/// Binding is separate from [`Server::run`] so a caller can learn the assigned
/// port with [`Server::local_addr`] before it advertises the service.
pub struct Server {
    listener: TcpListener,
    config: ServerConfig,
    slots: Arc<Semaphore>,
}

impl Server {
    /// Binds `config`.
    ///
    /// # Errors
    ///
    /// Returns the bind failure of the address, or [`ErrorKind::InvalidInput`]
    /// when `config.max_connections` is outside the range the connection counter
    /// can hold. A configuration value must not be able to panic the service,
    /// which is what handing an oversized limit to the semaphore would do.
    pub async fn bind(config: ServerConfig) -> Result<Self> {
        if config.max_connections == 0 || config.max_connections > Semaphore::MAX_PERMITS {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "max_connections must be between 1 and the connection counter limit",
            ));
        }
        let listener = TcpListener::bind(config.bind).await?;
        let slots = Arc::new(Semaphore::new(config.max_connections));
        Ok(Self {
            listener,
            config,
            slots,
        })
    }

    /// Address the service listens on, including the assigned port.
    ///
    /// # Errors
    ///
    /// Returns the error the operating system reports for the socket.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Configuration this service was bound with.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Accepts connections until the listener fails.
    ///
    /// `new_handlers` creates the handler set for each accepted connection, so a
    /// caller can hand every client its own [`RouteHandlers`].
    ///
    /// # Errors
    ///
    /// Returns the listener error. A connection that fails while it is served is
    /// not an error of the service: the protocol logs it and keeps accepting
    ///, and so does the port.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rust_airplay::server::{DeviceIdentity, Server, ServerConfig, RouteHandlers};
    ///
    /// # async fn serve() -> std::io::Result<()> {
    /// let mut config = ServerConfig::default();
    /// config.device = DeviceIdentity::new("aa:bb:cc:dd:ee:ff", "Receiver", Vec::new());
    /// let server = Server::bind(config).await?;
    /// println!("control service on {}", server.local_addr()?);
    /// server.run(|| RouteHandlers::new(DeviceIdentity::default())).await
    /// # }
    /// ```
    pub async fn run<F, H>(self, mut new_handlers: F) -> Result<()>
    where
        F: FnMut() -> H,
        H: RouteHandler + Send + 'static,
    {
        let idle_timeout = self.config.idle_timeout;
        let audio_delay_micros = self.config.audio_delay_micros;
        let nohold = self.config.nohold;
        let feedback_timeout = self.config.feedback_timeout;
        // Every connection still being served, so `nohold` can stop the previous one
        // from the same host. A different host is a different client and keeps its slot.
        let live: Arc<std::sync::Mutex<Vec<(std::net::IpAddr, tokio::task::AbortHandle)>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        loop {
            // Taking a slot before accepting is what keeps the connection count
            // bounded: with every slot in use, the listener is not polled and a
            // new connection waits in the backlog.
            let Ok(slot) = Arc::clone(&self.slots).acquire_owned().await else {
                return Ok(());
            };
            let (socket, peer) = match self.listener.accept().await {
                Ok(accepted) => accepted,
                // A connection can fail between the backlog and `accept`, which
                // says nothing about the next one.
                Err(error) if error.kind() == ErrorKind::ConnectionAborted => continue,
                Err(error) => return Err(error),
            };
            let handlers = new_handlers();
            let peer_ip = peer.ip();
            let task = tokio::spawn(async move {
                let _slot = slot;
                if let Err(error) = connection::serve(
                    socket,
                    peer,
                    handlers,
                    idle_timeout,
                    audio_delay_micros,
                    feedback_timeout,
                )
                .await
                {
                    log::debug!("control connection ended: {error}");
                }
            });
            let mut live = live
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if nohold {
                live.retain(|(ip, handle)| {
                    if *ip == peer_ip {
                        handle.abort();
                        false
                    } else {
                        true
                    }
                });
            }
            live.retain(|(_, handle)| !handle.is_finished());
            live.push((peer_ip, task.abort_handle()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_rejects_a_useless_connection_limit() {
        let config = ServerConfig {
            max_connections: 0,
            ..ServerConfig::default()
        };
        let error = Server::bind(config).await.err().unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn bind_rejects_a_connection_limit_the_counter_cannot_hold() {
        // Handing this limit to the semaphore would panic inside `bind`.
        let config = ServerConfig {
            max_connections: usize::MAX,
            ..ServerConfig::default()
        };
        let error = Server::bind(config).await.err().unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn a_nohold_server_drops_the_previous_client() {
        // The protocol's `-nohold`: a new connection takes the session rather than being
        // refused. The first client's socket closing is what a takeover looks like from
        // its side.
        let config = ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            nohold: true,
            ..ServerConfig::default()
        };
        let server = Server::bind(config).await.unwrap();
        let address = server.local_addr().unwrap();
        let accepting = tokio::spawn(server.run(|| RouteHandlers::new(DeviceIdentity::default())));

        let mut first = tokio::net::TcpStream::connect(address).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut second = tokio::net::TcpStream::connect(address).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The first connection is gone: a read returns end of stream, or an error.
        use tokio::io::AsyncReadExt;
        let mut byte = [0u8; 1];
        assert!(
            matches!(first.read(&mut byte).await, Ok(0) | Err(_)),
            "the previous client should have been dropped"
        );
        // And the new one is still served: it can ask a question.
        use tokio::io::AsyncWriteExt;
        second
            .write_all(
                b"OPTIONS * RTSP/1.0
CSeq: 1

",
            )
            .await
            .unwrap();
        accepting.abort();
    }

    #[tokio::test]
    async fn bind_reports_the_assigned_port() {
        let config = ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            ..ServerConfig::default()
        };
        let server = Server::bind(config).await.unwrap();
        assert_ne!(server.local_addr().unwrap().port(), 0);
        assert_eq!(server.config().max_connections, MAX_CONNECTIONS);
    }
}
