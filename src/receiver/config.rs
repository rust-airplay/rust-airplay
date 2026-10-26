// SPDX-License-Identifier: GPL-3.0-or-later
//! The values a program supplies to a receiver.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::render::{AudioCodec, Renderer};
use crate::server::PinMode;

/// Told when a client is verified for the first time, so the caller can record its key.
pub type ClientCallback = Arc<dyn Fn(&[u8; 32]) + Send + Sync>;

/// What a caller tells the receiver before it starts.
///
/// Everything here is a value the caller resolved: this crate does not read the
/// environment, does not choose a path, and does not parse a command line. That keeps it
/// testable, and keeps policy — where an identity lives, which port to prefer, what to
/// print — in the program that runs it.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// ///
/// use rust_airplay::{Config, NullRenderer};
///
/// let mut config = Config::new("Living room", [0x2a; 32], Arc::new(NullRenderer::new()));
/// config.port = 7001;
/// config.audio_latency = std::time::Duration::from_millis(100);
/// assert_eq!(config.name, "Living room");
/// ```
#[non_exhaustive]
#[derive(Clone)]
pub struct Config {
    /// The name clients see in their AirPlay menu.
    pub name: String,
    /// Port the control service listens on; `0` binds an ephemeral one.
    pub port: u16,
    /// Address the control and media sockets bind to.
    ///
    /// The default serves every interface, which is what a receiver on a home network
    /// wants. `127.0.0.1` keeps a test, or a receiver that should not be reachable from
    /// the network, on one machine.
    pub bind: std::net::IpAddr,
    /// Whether the receiver announces itself over mDNS.
    ///
    /// A test, or a program that publishes the control address some other way, turns
    /// this off; the receiver still answers every request, it is only not discovered.
    pub advertise: bool,
    /// The 32 bytes every identity key derives from.
    pub seed: [u8; 32],
    /// Device identifier to announce, when the caller has one of its own.
    pub device_id: Option<String>,
    /// How a client authenticates.
    pub pin: PinMode,
    /// Digest password, when the caller configured one.
    ///
    /// The password gates `SETUP` and the routes that change what is playing or read
    /// the session's parameters; the advertisement and pairing routes are answered
    /// without it.
    pub password: Option<String>,
    /// The coding an audio stream is expected to carry, when the client does not say.
    ///
    /// A client states its coding as `ct` in the `SETUP` that names the stream
    ///, and that declaration wins. This value is what a
    /// session falls back to when the client never declares one, which is what older
    /// clients did.
    pub audio_codec: AudioCodec,
    /// Whether a `SETUP` reports its whole body to the setup callback.
    ///
    /// Off by default. The body carries the media key, so this is for a diagnostic run:
    /// a receiver that turns it on hands session material to the program.
    pub debug_setup_body: bool,
    /// What plays the media.
    pub renderer: Arc<dyn Renderer>,
    /// Clients whose keys a previous run verified.
    ///
    /// With a PIN configured the list also decides whether a client may verify without
    /// pairing again. With the PIN disabled it is a record only: the legacy `/pair-setup`
    /// is then the way a first client joins, and refusing it would leave a receiver with
    /// no way to accept one.
    pub clients: Arc<Mutex<HashSet<[u8; 32]>>>,
    /// Called when a client is verified for the first time.
    pub on_client: Option<ClientCallback>,
    /// Where to append the request trace, when the caller wants one.
    pub trace_log: Option<std::path::PathBuf>,
    /// Where to write the first video frames, for diagnosing a picture.
    pub dump_video: Option<std::path::PathBuf>,
    /// Where to write the audio payloads, for diagnosing a stream.
    pub dump_audio: Option<std::path::PathBuf>,
    /// The audio delay reported to a client by `RECORD`.
    ///
    /// The protocol's `-al`. A client schedules its own playback against the number it reads
    /// from `Audio-Latency`: too small and every packet is late, too large and the stream
    /// starts late. The default is the protocol's quarter of a second.
    pub audio_latency: std::time::Duration,
    /// Whether a new client takes over from the current one.
    ///
    /// The protocol's `-nohold`. Off by default: this crate serves several connections at
    /// once, which is more permissive than the protocol. The flag drops the previous
    /// connection from the same host; a connection from another host keeps its slot.
    pub nohold: bool,
    /// How long a session may go without `/feedback` before it is closed.
    ///
    /// The protocol's `-reset`, which defaults to fifteen seconds there. `None` leaves a silent
    /// client connected.
    pub feedback_timeout: Option<std::time::Duration>,
    /// The ports the media session binds.
    ///
    /// The protocol's `-p n` and `-p`. The default lets the system choose every port and tells
    /// the client what it got in `SETUP`, which is what a receiver discovered over mDNS
    /// does not need anything else for. A fixed layout is for a firewall or a port forward,
    /// and [`crate::media::ports::MediaPorts::legacy`] is the protocol's own.
    pub ports: crate::media::ports::MediaPorts,
    /// Which clients may start a session.
    ///
    /// The protocol's `-restrict`, `-allow` and `-block`. The policy is checked in `SETUP`,
    /// where the client has named itself and before any key is derived; a refused client
    /// is answered `403 Forbidden`.
    pub client_policy: crate::server::ClientPolicy,
    /// The feature bitmap advertised, when the caller has one of its own.
    ///
    /// `None` advertises [`crate::server::DEFAULT_FEATURES`], which is what the protocol's
    /// build starts from. A bit decides what a client believes the receiver can do: bit 42
    /// is the one that allows HEVC video, bits 4 and 5 are HLS and slideshow, and bit 27
    /// picks the pairing protocol. The protocol's `-h265` is this bitmap with bit 42 set, and
    /// `-hls` is bit 4.
    pub features: Option<u64>,
    /// The display a client is offered in `GET /info`.
    ///
    /// The protocol's `-s wxh@r`, `-fps` and `-o` together. A client reads the size, the
    /// refresh interval and the frame cap from there and sends a mirror stream that
    /// matches, so this is how a receiver asks for a smaller picture or a lower frame
    /// rate without touching the stream afterwards.
    pub display: crate::server::Display,
    /// Called with the one-time PIN a client is asked for, as it is drawn.
    ///
    /// The PIN is the one thing a receiver must show a person, and the library cannot print:
    /// a program that has to read its own log to find it is a program with the wrong
    /// interface. Called from a background thread, once per PIN.
    pub on_pin: Option<PinCallback>,
    /// What to do with artwork a client sends, given its content type.
    ///
    /// The protocol's `-ca`: the bytes are a JPEG or PNG the program may write or show. The
    /// library cannot write a file, so this is the callback that lets a program do it.
    pub on_artwork: Option<ArtworkCallback>,
    /// What to do with the metadata listing a client sends.
    ///
    /// The protocol's `-md`: the bytes are a DMAP listing, which [`crate::media::dmap::text`]
    /// turns into the lines that file holds.
    pub on_metadata: Option<MetadataCallback>,
    /// What to do with the remote-control identifiers a request carries.
    ///
    /// The protocol's `-dacp`: a program can write them where a remote control expects to find
    /// them. They authorize nothing; they name a connection.
    pub on_remote_control: Option<RemoteControlCallback>,
    /// Whether the client's streaming reports are written to the log.
    ///
    /// The protocol's `-FPSdata`. A report is a binary plist a mirroring client sends once a
    /// second; it says how the client itself thinks the stream is going, which is the one
    /// view of performance this receiver cannot measure.
    pub log_streaming_reports: bool,
    /// How a client's slider position becomes a gain.
    ///
    /// The protocol's `-taper` and `-db`. The default is the flat `-30..0` decibel mapping.
    pub volume_curve: crate::VolumeCurve,
    /// The volume a session starts at.
    ///
    /// The protocol's `-vol`. The renderer is told once, before any client connects, so a
    /// stream opens at this level rather than at full volume. A renderer that cannot take
    /// it reports the refusal and the receiver goes on.
    pub initial_volume: crate::Volume,
    /// Whether video is held back to keep the spacing it was captured at.
    ///
    /// Off by default. A mirror is judged by how quickly the picture follows the device,
    /// and pacing spends latency to buy smoothness: writing each frame as it arrives shows
    /// the newest picture at the cost of an uneven one when a burst arrives. Turn it on for
    /// a stream that arrives in bursts and a viewer who watches rather than types.
    pub pace_video: bool,
}

impl Config {
    /// A configuration a receiver can start from.
    ///
    /// The three things a receiver cannot invent are its name, the seed its identity derives
    /// from, and what plays the media; everything else has the value a normal run wants and
    /// is a public field for a caller that wants another.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use rust_airplay::{Config, NullRenderer};
    ///
    /// let config = Config::new("Living room", [0x2a; 32], Arc::new(NullRenderer::new()));
    /// assert_eq!(config.port, 7000);
    /// assert_eq!(config.display.width, 1920);
    /// ```
    #[must_use]
    pub fn new(name: impl Into<String>, seed: [u8; 32], renderer: Arc<dyn Renderer>) -> Self {
        Self {
            name: name.into(),
            port: 7000,
            bind: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            advertise: true,
            seed,
            device_id: None,
            pin: PinMode::OneTime,
            password: None,
            audio_codec: AudioCodec::AacEld,
            debug_setup_body: false,
            renderer,
            clients: Arc::new(Mutex::new(HashSet::new())),
            on_client: None,
            trace_log: None,
            dump_video: None,
            dump_audio: None,
            audio_latency: std::time::Duration::from_micros(u64::from(
                crate::control::DEFAULT_AUDIO_DELAY_MICROS,
            )),
            nohold: false,
            feedback_timeout: None,
            ports: crate::media::ports::MediaPorts::automatic(),
            client_policy: crate::server::ClientPolicy::default(),
            features: None,
            display: crate::server::Display::default(),
            on_pin: None,
            on_artwork: None,
            on_metadata: None,
            on_remote_control: None,
            log_streaming_reports: false,
            volume_curve: crate::VolumeCurve::default(),
            initial_volume: crate::Volume::FULL,
            pace_video: false,
        }
    }
}

/// Called with the four-digit PIN a client is being asked for.
pub type PinCallback = Arc<dyn Fn(&str) + Send + Sync>;

/// Called with the content type and bytes of artwork a client sends.
pub type ArtworkCallback = Arc<dyn Fn(&str, &[u8]) + Send + Sync>;

/// Called with the raw DMAP listing a client sends.
pub type MetadataCallback = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// Called with the `DACP-ID` and `Active-Remote` a request carries.
pub type RemoteControlCallback = Arc<dyn Fn(&str, &str) + Send + Sync>;
