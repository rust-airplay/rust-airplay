// SPDX-License-Identifier: GPL-3.0-or-later
//! The values a route handler exposes and the protocol constants it uses.

use crate::control::RequestTrace;
use crate::server::pairing::SessionAuth;

/// Ports a `SETUP` response may advertise.
///
/// A field the crate cannot honour is left out instead of being filled with a
/// placeholder, so a client never believes it may send media somewhere nothing listens.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SetupPorts {
    /// Port of the timing service, sent as `timingPort`.
    pub timing_port: Option<u16>,
    /// Port of the event channel, sent as `eventPort` (the protocol sends `0`,
    /// because neither audio nor mirror mode uses it).
    ///
    /// The protocol puts this key in every `SETUP` response whether or not a client
    /// asked for it, so
    /// a response that leaves it out is not the shape a client expects. `None`
    /// therefore means "not known yet" rather than "omit", and
    /// [`SetupPorts::event_port_or_zero`] is what a response uses.
    pub event_port: Option<u16>,
    /// Audio data port, sent in the `type: 96` stream entry.
    pub data_port: Option<u16>,
    /// Audio control port, sent in the `type: 96` stream entry.
    pub control_port: Option<u16>,
    /// Mirror data port, sent in the `type: 110` stream entry.
    pub mirror_data_port: Option<u16>,
}

impl SetupPorts {
    /// The event port a response carries, which the protocol always answers.
    ///
    /// It is `0` when the port does not exist, and that is not a placeholder: a
    /// client reads the key's presence, and the protocol's own value is `0` for both
    /// of the modes this receiver serves.
    pub fn event_port_or_zero(&self) -> u16 {
        self.event_port.unwrap_or(0)
    }
}

/// One stream a client asked for in `SETUP`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupStream {
    /// Stream type: `96` is audio, `110` is mirroring
    pub kind: u16,
    /// `streamConnectionID`, which the mirror stream uses to derive its own
    /// AES-CTR key.
    pub stream_connection_id: Option<u64>,
    /// `ct`, the compression type: `2` is ALAC and `8` is AAC-ELD
    ///
    /// It is what says which coding a client is sending, and the protocol takes its decoder
    /// from it rather than guessing. A port that assumes one of the two is a port that is
    /// wrong for every client that uses the other, and the assumption is invisible from the
    /// audio alone: both are compressed, and a decoder handed the wrong one reports a
    /// stream it cannot read rather than the mix-up.
    pub compression_type: Option<u16>,
    /// `spf`, samples per frame, which the protocol passes to its decoder with `ct`
    pub samples_per_frame: Option<u16>,
    /// `controlPort`, where the client receives resend requests for this stream.
    ///
    /// A receiver that has no way to ask for a lost packet can only wait for the window
    /// to give up on it; the port is the address half of that request.
    pub control_port: Option<u16>,
}

/// What one accepted `SETUP` request hands to the session layer.
///
/// The audio key is the FairPlay-decrypted `ekey`, hashed with the connection's
/// verified pairing secret when there is one
/// Nothing is derived
/// from an unverified exchange: the session material of a connection is produced
/// only after it finished `/pair-verify`.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq)]
pub struct SetupRequest {
    /// Audio key, present when the request carried `ekey` and `eiv`.
    pub audio_key: Option<[u8; 16]>,
    /// Audio IV, present together with [`SetupRequest::audio_key`].
    pub audio_iv: Option<[u8; 16]>,
    /// Streams the client asked for, in request order.
    pub streams: Vec<SetupStream>,
    /// Port the client listens on for the clock exchange, from `timingPort`.
    ///
    /// The exchange is the receiver's to start: the protocol sends its first timing
    /// request as soon as `SETUP` is answered, to this crate
    ///, and a client that never
    /// receives one has no reason to send its media. `None` is a client that did
    /// not name a port, which the protocol logs as the AirPlay 2 "Remote Control"
    /// protocol it does not serve.
    pub client_timing_port: Option<u16>,
    /// Address the client's control connection came from.
    ///
    /// The clock exchange goes to [`SetupRequest::client_timing_port`] at this
    /// address, which is the only place a receiver can learn it from
    /// `None` is a request served without a transport, as a
    /// unit test serves one.
    pub client_address: Option<std::net::SocketAddr>,
    /// The whole request, as XML, when a receiver asked for it.
    ///
    /// A `SETUP` is the one request whose body a device session is read from, and
    /// its shape differs between clients enough that the keys alone do not always
    /// explain it. This is empty unless a receiver turned it on, because a body
    /// carries session material.
    pub debug_body: Option<String>,
    /// Top-level keys the request carried, in the order it wrote them.
    ///
    /// A `SETUP` is the one request whose shape varies most between clients and
    /// firmware versions, and knowing exactly which keys arrived is the difference
    /// between reading a device session and guessing at it. It is reported, not
    /// used: nothing in a session decides anything from this.
    pub keys: Vec<String>,
    /// Client key of the verified pairing exchange, when this connection had one.
    pub client_identity: Option<[u8; 32]>,
    /// How far the pairing exchange of this connection got.
    ///
    /// A session layer that needs an access decision reads this instead of
    /// guessing from the presence of a key: `Verified` proves the peer holds its
    /// private key, nothing more.
    pub authentication: SessionAuth,
}

impl std::fmt::Debug for SetupRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A `SETUP` carries the media key and, when the caller asked for it, the body
        // the key was read from. Neither belongs in a log line, a panic message or a
        // debugger view, so the fields that are material are reported by presence and
        // size instead of by value.
        formatter
            .debug_struct("SetupRequest")
            .field("audio_key", &self.audio_key.as_ref().map(|_| "<redacted>"))
            .field("audio_iv", &self.audio_iv.as_ref().map(|_| "<redacted>"))
            .field("streams", &self.streams)
            .field("client_timing_port", &self.client_timing_port)
            .field("client_address", &self.client_address)
            .field(
                "debug_body",
                &self
                    .debug_body
                    .as_ref()
                    .map(|body| format!("<{} bytes>", body.len())),
            )
            .field("keys", &self.keys)
            .field("client_identity", &self.client_identity)
            .field("authentication", &self.authentication)
            .finish()
    }
}

/// What a client asked to change with `SET_PARAMETER`.
///
/// The protocol hands both values straight to its media layer
///; a receiver whose
/// media layer is a later stage reports them instead of pretending to act.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SetParameter {
    /// `volume: <value>`: the volume the client asked for, in decibels.
    ///
    /// A client states `-30` for silence and `0` for full volume, and `-144` for mute
    /// It is not a fraction, and a receiver that read it as one
    /// would mute every client that lowered its volume at all.
    Volume(f32),
    /// `progress: <start>/<current>/<end>`, in seconds.
    Progress {
        /// Position the track started at.
        start: u32,
        /// Position the client is at.
        current: u32,
        /// Position the track ends at.
        end: u32,
    },
}

/// Callback that is told about every request a connection served.
///
/// It borrows the trace rather than owning it, so a receiver that logs requests
/// does not copy request data around.
pub type TraceCallback = Box<dyn FnMut(&RequestTrace<'_>) + Send>;

/// Model the protocol advertises when the user does not override it
pub const DEFAULT_MODEL: &str = "AppleTV3,2";

/// Version the protocol reports as `sourceVersion` and in its `Server` header
pub const DEFAULT_SOURCE_VERSION: &str = "220.68";

/// AirPlay feature bitmap a receiver advertises by default.
///
/// **Bit 27 is the one that decides how a client connects**, and it is worth being exact
/// about. says what it is:
///
/// > bit 27 of Features determines whether the AirPlay2 client-pairing protocol will be
/// > used (1) or not (0)
///
/// AirPlay leaves it clear (`setup_legacy_pairing = false`,
///) and advertises `0x527FFEE6`, which was read back from
/// a running receiver with `dns-sd` rather than taken from a header. With the bit set a
/// client is told to use the older pairing protocol, and iOS does: it starts
/// `/pair-pin-start` and `/pair-setup-pin`, and only after that has failed or timed out
/// does it settle on the modern flow. That is the wait between tapping a receiver and
/// seeing a picture — a real device's log showed the pin flow answering `470` at the second
/// step, which is a protocol it was told to try and this crate does not complete.
///
///'s `0x5A7FFEE6` is the value before adjusts it; the running
/// receiver is what matters, and it says `0x527FFEE6`.
pub const DEFAULT_FEATURES: u64 = 0x527F_FEE6;

/// Pairing identity the protocol advertises.
pub const DEFAULT_PI: &str = "2e388006-13ba-4041-9a67-25dd4a43d536";

/// `vv` the protocol advertises.
pub const DEFAULT_VV: u32 = 2;

/// Default display width in pixels.
pub const DEFAULT_WIDTH: u64 = 1920;

/// Default display height in pixels.
pub const DEFAULT_HEIGHT: u64 = 1080;

/// Default display refresh rate in hertz
pub const DEFAULT_REFRESH_RATE: f64 = 60.0;

/// Default display frame rate the protocol advertises
pub const DEFAULT_MAX_FPS: u64 = 30;

/// `statusFlags` the protocol always sends
pub const STATUS_FLAGS: u64 = 68;

/// Hard-coded display identifier the protocol always sends
pub const DISPLAY_UUID: &str = "e0ff8a27-6738-3d56-8a16-cc53aacee925";

/// Bitmap of the single display the protocol describes
pub const DISPLAY_FEATURES: u64 = 14;

/// Audio formats up to 5.1 surround that the protocol advertises
pub const AUDIO_OUTPUT_FORMATS: u64 = 0x03FF_FFFC;

/// The identity this receiver advertises to clients.
///
/// The protocol keeps the same facts spread over its DNS-SD record, `raop_t` and
/// the `GLOBAL_MODEL`/`GLOBAL_VERSION` macros; this type collects the ones
/// `GET /info` and the protocol defaults need so a caller can describe a
/// receiver in one value.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceIdentity {
    /// Hardware address a client sees as `deviceID` and `macAddress`. The protocol
    /// formats it with `utils_hwaddr_airplay`, i.e. lower-case hex pairs
    /// separated by colons.
    pub device_id: String,
    /// Name a client shows in its device list.
    pub name: String,
    /// `model` value, [`DEFAULT_MODEL`] unless the caller overrides it.
    pub model: String,
    /// Ed25519 public key of the receiver, sent as the `pk` data value
    ///
    /// [`RouteHandlers::with_pairing`](super::RouteHandlers::with_pairing) replaces it with
    /// [`PairingState::identity_public`](crate::server::PairingState::identity_public), so that a client can never cache one
    /// identity from `/info` and be authenticated with another one from the
    /// pairing exchange (see `docs/ARCHITECTURE.md`). A caller that
    /// advertises a key here without pairing has to keep that invariant itself.
    pub public_key: Vec<u8>,
    /// `features` bitmap, [`DEFAULT_FEATURES`] unless the caller overrides it.
    pub features: u64,
    /// `sourceVersion` value, [`DEFAULT_SOURCE_VERSION`] by default.
    pub source_version: String,
    /// `pi` value, [`DEFAULT_PI`] by default.
    pub pi: String,
    /// `vv` value, [`DEFAULT_VV`] by default.
    pub vv: u32,
    /// `initialVolume` value. The protocol asks its audio callback for the current
    /// client volume.
    pub initial_volume: f64,
    /// Display width in pixels, [`DEFAULT_WIDTH`] by default.
    pub width: u64,
    /// Display height in pixels, [`DEFAULT_HEIGHT`] by default.
    pub height: u64,
    /// Display refresh rate in hertz, [`DEFAULT_REFRESH_RATE`] by default.
    pub refresh_rate: f64,
    /// Display frame rate, [`DEFAULT_MAX_FPS`] by default.
    pub max_fps: u64,
    /// Whether the display is overscanned, `false` by default.
    pub overscanned: bool,
    /// Raw `txtAirPlay` record a client asks for with
    /// `GET /info?txtAirPlay`, or `None` while service discovery has not been
    /// ported.
    pub txt_airplay: Option<Vec<u8>>,
    /// Raw `txtRAOP` record, the RAOP counterpart of [`Self::txt_airplay`].
    pub txt_raop: Option<Vec<u8>>,
}

/// Who a client says it is, read from its `SETUP` request.
///
/// The protocol hands these three values to its `report_client_request` callback and lets the
/// program decide whether the session proceeds. They are what
/// `-restrict`, `-allow` and `-block` match against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRequest {
    /// The `deviceID` the client sent, which is its hardware address.
    pub device_id: String,
    /// The `model` the client sent, when it sent one.
    pub model: String,
    /// The `name` the client sent, when it sent one.
    pub name: String,
}

/// Which clients may start a session.
///
/// This is the protocol's `-restrict`, `-allow` and `-block` together. A blocked device is
/// always refused; when `restrict` is set, only an allowed device is admitted; otherwise
/// everything that is not blocked is. A device identifier is the one a client sends as
/// `deviceID`, the same string a receiver stores when it remembers a pairing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientPolicy {
    /// Admit only the devices in [`ClientPolicy::allow`].
    pub restrict: bool,
    /// Device identifiers that are admitted when `restrict` is set.
    pub allow: Vec<String>,
    /// Device identifiers that are never admitted.
    pub block: Vec<String>,
}

impl ClientPolicy {
    /// Whether a client may start a session.
    #[must_use]
    pub fn admits(&self, client: &ClientRequest) -> bool {
        // A block wins over everything: restricting a list and then blocking a member of
        // it is a caller saying "not this one", and the narrower permission is the safer
        // reading.
        if self.block.iter().any(|id| id == &client.device_id) {
            return false;
        }
        if self.restrict {
            return self.allow.iter().any(|id| id == &client.device_id);
        }
        true
    }
}

/// The display a receiver offers a client in `GET /info`.
///
/// This is the protocol's `-s wxh@r`, `-fps` and `-o` set together: a client reads them from
/// the `displays` array and sizes and paces the mirror stream it sends. A receiver that
/// does not care takes [`Display::default`], which is the protocol's own default of 1920x1080
/// at 60 Hz, thirty frames a second, not overscanned.
#[derive(Debug, Clone, PartialEq)]
pub struct Display {
    /// Width in pixels.
    pub width: u64,
    /// Height in pixels.
    pub height: u64,
    /// Refresh rate in hertz, sent as the interval `1 / refresh_rate`.
    pub refresh_rate: f64,
    /// Highest frame rate the client should send.
    pub max_fps: u64,
    /// Whether the picture is overscanned.
    pub overscanned: bool,
}

impl Default for Display {
    fn default() -> Self {
        Self {
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            refresh_rate: DEFAULT_REFRESH_RATE,
            max_fps: DEFAULT_MAX_FPS,
            overscanned: false,
        }
    }
}

impl DeviceIdentity {
    /// Creates an identity for `device_id` and `name` that carries `public_key`
    /// and keeps every other default.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_airplay::server::DeviceIdentity;
    ///
    /// let identity =
    ///     DeviceIdentity::new("aa:bb:cc:dd:ee:ff", "Living room", vec![0x11; 32]);
    /// assert_eq!(identity.device_id, "aa:bb:cc:dd:ee:ff");
    /// assert_eq!(identity.name, "Living room");
    /// ```
    pub fn new(device_id: impl Into<String>, name: impl Into<String>, public_key: Vec<u8>) -> Self {
        Self {
            device_id: device_id.into(),
            name: name.into(),
            public_key,
            ..Self::default()
        }
    }
}

impl Default for DeviceIdentity {
    /// The protocol's defaults with a placeholder hardware address.
    ///
    /// The hardware address identifies the receiver, so a caller that serves
    /// real clients must set [`DeviceIdentity::device_id`] and
    /// [`DeviceIdentity::public_key`]; the placeholder is only meant to keep
    /// configuration and tests readable.
    fn default() -> Self {
        Self {
            device_id: "00:00:00:00:00:00".to_owned(),
            name: "rust-airplay".to_owned(),
            model: DEFAULT_MODEL.to_owned(),
            public_key: Vec::new(),
            features: DEFAULT_FEATURES,
            source_version: DEFAULT_SOURCE_VERSION.to_owned(),
            pi: DEFAULT_PI.to_owned(),
            vv: DEFAULT_VV,
            initial_volume: 0.0,
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            refresh_rate: DEFAULT_REFRESH_RATE,
            max_fps: DEFAULT_MAX_FPS,
            overscanned: false,
            txt_airplay: None,
            txt_raop: None,
        }
    }
}

/// What to do with one piece of artwork: its content type and its bytes.
pub(crate) type ArtworkHandler = Box<dyn FnMut(&str, &[u8]) + Send>;
/// What to do with one DMAP listing.
pub(crate) type MetadataHandler = Box<dyn FnMut(&[u8]) + Send>;
/// What to do with the remote-control identifiers of a request.
pub(crate) type RemoteControlHandler = Box<dyn FnMut(&str, &str) + Send>;
