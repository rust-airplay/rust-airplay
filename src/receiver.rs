// SPDX-License-Identifier: GPL-3.0-or-later
//! The receiver: what a program runs to answer clients.
//!
//! [`run`] is the whole of it. It binds the control service and the media sockets, announces
//! the receiver over mDNS, answers `SETUP` with the ports it bound, hands each session its
//! keys and plays what arrives through whatever [`Renderer`] the caller supplied.
//!
//! What it does not do is decide policy: there is no command line, no path, no environment
//! variable and no printing here. Those are [`Config`] values and `log` records, and the
//! program that runs a receiver fills them in.

use std::collections::HashSet;
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;

use crate::crypto::sha512_concat;
use crate::discovery::{Advertisement, Advertiser, Protection};
use crate::render::{AudioCodec, AudioConfig, Renderer};
use crate::server::{
    DeviceIdentity, PairingState, PinMode, RouteHandlers, Server, ServerConfig, SetupPorts,
};
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The stream type a mirroring client asks for, whose entry carries the
/// `streamConnectionID` the mirror keys are derived from
/// (`upstream/UxPlay@3dbf7cee:lib/raop_handlers.h:954-983`).
const MIRROR_STREAM_TYPE: u16 = 110;

/// The device identifier a seed derives its keys from.
///
/// Derived rather than random so that one seed is one receiver: a client that paired with
/// it once recognises it again, which is the whole point of remembering keys.
fn derived_device_id(seed: &[u8; 32]) -> String {
    let digest = sha512_concat(&[b"rust-airplay-device-id", seed]);
    let mut octets = [0u8; 6];
    octets.copy_from_slice(&digest[..6]);
    octets[0] = (octets[0] & 0xfc) | 0x02;
    octets
        .iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Lower-case hex, for the places a log names a key without carrying it anywhere.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Frames a mirror session may hold for its renderer before it starts dropping them.
///
/// The queue exists so that waiting for a picture is not waiting inside the receive
/// loop. It is bounded because a client that sends faster than a decoder decodes must
/// not be able to make a receiver allocate without limit; a frame dropped when it is
/// full is reported, because a dropped frame is one the rest of the stream may depend
/// on. Thirty-two frames is about a second of a screen, which is longer than any
/// stall a decoder produces and far below anything a receiver would notice holding.
const QUEUED_FRAMES: usize = 8;

/// One frame waiting for the video writer.
///
/// The bytes, the client's timestamp, whether it is a key frame, when it arrived, the
/// coding it is in and the geometry the session announced: everything the writer needs to
/// open a stream on the first frame and pace the rest.
type QueuedVideo = (
    Vec<u8>,
    u64,
    bool,
    u64,
    crate::render::VideoCodec,
    Option<crate::media::mirror::Geometry>,
);

/// Frames waiting for the renderer, where a full queue drops the **oldest**.
///
/// A channel would be the obvious thing and it is wrong here. `SyncSender` refuses the
/// newest frame when it is full, so the frames it already holds are the ones that stay
/// queued — the renderer works through a picture that is a second old while the client
/// keeps sending, and what grows is exactly how far behind the screen is.
///
/// Dropping the oldest bounds the lag at the queue's depth instead. The picture cost is
/// the same either way — a frame the rest of the stream depends on is gone — but the
/// receiver no longer also drifts further behind the thing it is mirroring.
#[derive(Debug)]
struct FreshestFrames {
    state: Mutex<Frames>,
    ready: Condvar,
}

#[derive(Debug, Default)]
struct Frames {
    queued: std::collections::VecDeque<QueuedVideo>,
    /// Set when no more frames will arrive, which is what wakes the writer for the last
    /// time.
    ended: bool,
    /// How many frames were dropped to keep the queue at its depth.
    dropped: u64,
    /// Bumped by a flush, so the writer knows the frames it was about to show are stale.
    generation: u64,
}

impl FreshestFrames {
    fn new() -> Self {
        Self {
            state: Mutex::new(Frames::default()),
            ready: Condvar::new(),
        }
    }

    /// Adds a frame, dropping the oldest when the queue is full.
    ///
    /// Returns how many are waiting afterwards, so a caller can report a depth without
    /// asking a second question.
    /// Drops every frame waiting and tells the writer the picture starts over.
    ///
    /// A client sends `FLUSH` when what it played is no longer what it is about to play,
    /// and the frames queued here are the old picture. The generation is what reaches the
    /// writer, because it owns the renderer's stream: dropping the queue without telling
    /// it would leave the backend showing the frames it had already taken.
    fn clear(&self) -> u64 {
        let mut state = lock(&self.state);
        state.queued.clear();
        state.generation += 1;
        let generation = state.generation;
        drop(state);
        self.ready.notify_one();
        generation
    }

    /// The generation a flush left behind, for a writer that has to notice it.
    fn generation(&self) -> u64 {
        lock(&self.state).generation
    }

    fn put(&self, frame: QueuedVideo) -> usize {
        let mut state = lock(&self.state);
        if state.ended {
            return 0;
        }
        if state.queued.len() >= QUEUED_FRAMES {
            state.queued.pop_front();
            state.dropped += 1;
        }
        state.queued.push_back(frame);
        let depth = state.queued.len();
        drop(state);
        self.ready.notify_one();
        depth
    }

    /// Takes the next frame if one is waiting, without blocking.
    #[cfg(test)]
    fn try_take(&self) -> Option<QueuedVideo> {
        lock(&self.state).queued.pop_front()
    }

    /// Takes the next frame, waiting until there is one or the queue has ended.
    fn take(&self) -> Option<QueuedVideo> {
        let mut state = lock(&self.state);
        loop {
            if let Some(frame) = state.queued.pop_front() {
                return Some(frame);
            }
            if state.ended {
                return None;
            }
            state = self
                .ready
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    /// Says that no more frames are coming, and wakes whoever is waiting.
    fn end(&self) {
        lock(&self.state).ended = true;
        self.ready.notify_all();
    }

    /// How many frames were dropped to keep the queue at its depth.
    fn dropped(&self) -> u64 {
        lock(&self.state).dropped
    }
}

/// How many audio frames a writer thread will hold before frames start being dropped.
///
/// Audio packets are small and arrive in bursts, so this is deeper than the video
/// queue: at 44.1 kHz a frame is a few milliseconds, and a second of slack is what a
/// decoder stall needs. It is still bounded, because an unbounded queue turns "the
/// pipeline has stopped" into a growing delay rather than a visible fault.
const QUEUED_AUDIO_FRAMES: usize = 256;

fn open_audio(
    renderer: &Arc<dyn crate::Renderer>,
    codec: AudioCodec,
    samples_per_frame: u16,
) -> Option<Box<dyn crate::AudioStream>> {
    let config = AudioConfig {
        codec,
        samples_per_frame,
        ..AudioConfig::default()
    };
    match renderer.open_audio(config) {
        Ok(stream) => {
            log::info!(
                "media     audio stream open, {} at {}",
                codec.name(),
                config.sample_rate
            );
            Some(stream)
        }
        Err(error) => {
            log::warn!("rust-airplay: cannot play audio: {error}");
            None
        }
    }
}

/// A future that is ready when the receiver is stopping.
///
/// A receiver ends with Ctrl+C, and its receive loops need to be told: a loop that outlived
/// the control plane would hold a sound card or a window open with nothing to play into it.
/// One that cannot install signal handling waits forever instead, which is the same receiver
/// it was before this existed.
type Stopping = tokio::sync::watch::Receiver<bool>;

/// A signal that says the receiver is stopping, and a way to watch it.
fn shutdown_signal() -> Stopping {
    let (sender, receiver) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        log::info!("\nstopping");
        let _ = sender.send(true);
    });
    receiver
}

/// Waits for the signal, or forever for a receiver that has none.
async fn stopped(mut signal: Stopping) {
    let _ = signal.changed().await;
}

/// Told when a client is verified for the first time, so the caller can record its key.
pub type ClientCallback = Arc<dyn Fn(&[u8; 32]) + Send + Sync>;

/// What a caller tells the receiver before it starts.
///
/// Everything here is a value the caller resolved: this crate does not read the
/// environment, does not choose a path, and does not parse a command line. That keeps it
/// testable, and keeps policy — where an identity lives, which port to prefer, what to
/// print — in the program that runs it.
#[derive(Clone)]
pub struct Config {
    /// The name clients see in their AirPlay menu.
    pub name: String,
    /// Port the control service listens on; `0` binds an ephemeral one.
    pub port: u16,
    /// The 32 bytes every identity key derives from.
    pub seed: [u8; 32],
    /// Device identifier to announce, when the caller has one of its own.
    pub device_id: Option<String>,
    /// How a client authenticates.
    pub pin: PinMode,
    /// Digest password, when the caller configured one.
    pub password: Option<String>,
    /// The coding an audio stream is expected to carry, when the client does not say.
    ///
    /// A client states its coding as `ct` in the `SETUP` that names the stream
    /// (`raop_handlers.h:995-1030`), and that declaration wins. This value is what a
    /// session falls back to when the client never declares one, which is what older
    /// clients did.
    pub audio_codec: AudioCodec,
    /// What plays the media.
    pub renderer: Arc<dyn Renderer>,
    /// Clients whose keys a previous run verified.
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
    /// Upstream's `-al`. A client schedules its own playback against the number it reads
    /// from `Audio-Latency`: too small and every packet is late, too large and the stream
    /// starts late. The default is upstream's quarter of a second.
    pub audio_latency: std::time::Duration,
    /// Whether a new client takes over from the current one.
    ///
    /// Upstream's `-nohold`. Off by default: this crate serves several connections at once,
    /// which is more permissive than upstream, and the flag adds the takeover a person
    /// switching phones expects.
    pub nohold: bool,
    /// How long a session may go without `/feedback` before it is closed.
    ///
    /// Upstream's `-reset`, which defaults to fifteen seconds there. `None` leaves a silent
    /// client connected.
    pub feedback_timeout: Option<std::time::Duration>,
    /// The ports the media session binds.
    ///
    /// Upstream's `-p n` and `-p`. The default lets the system choose every port and tells
    /// the client what it got in `SETUP`, which is what a receiver discovered over mDNS
    /// does not need anything else for. A fixed layout is for a firewall or a port forward,
    /// and [`crate::media::ports::MediaPorts::legacy`] is upstream's own.
    pub ports: crate::media::ports::MediaPorts,
    /// Which clients may start a session.
    ///
    /// Upstream's `-restrict`, `-allow` and `-block`. The policy is checked in `SETUP`,
    /// where the client has named itself and before any key is derived; a refused client
    /// is answered `403 Forbidden`.
    pub client_policy: crate::server::ClientPolicy,
    /// The feature bitmap advertised, when the caller has one of its own.
    ///
    /// `None` advertises [`crate::server::DEFAULT_FEATURES`], which is what upstream's
    /// build starts from. A bit decides what a client believes the receiver can do: bit 42
    /// is the one that allows HEVC video, bits 4 and 5 are HLS and slideshow, and bit 27
    /// picks the pairing protocol. Upstream's `-h265` is this bitmap with bit 42 set, and
    /// `-hls` is bit 4.
    pub features: Option<u64>,
    /// The display a client is offered in `GET /info`.
    ///
    /// Upstream's `-s wxh@r`, `-fps` and `-o` together. A client reads the size, the
    /// refresh interval and the frame cap from there and sends a mirror stream that
    /// matches, so this is how a receiver asks for a smaller picture or a lower frame
    /// rate without touching the stream afterwards.
    pub display: crate::server::Display,
    /// What to do with artwork a client sends, given its content type.
    ///
    /// Upstream's `-ca`: the bytes are a JPEG or PNG the program may write or show. The
    /// library cannot write a file, so this is the callback that lets a program do it.
    pub on_artwork: Option<ArtworkCallback>,
    /// What to do with the metadata listing a client sends.
    ///
    /// Upstream's `-md`: the bytes are a DMAP listing, which [`crate::media::dmap::text`]
    /// turns into the lines that file holds.
    pub on_metadata: Option<MetadataCallback>,
    /// What to do with the remote-control identifiers a request carries.
    ///
    /// Upstream's `-dacp`: a program can write them where a remote control expects to find
    /// them. They authorize nothing; they name a connection.
    pub on_remote_control: Option<RemoteControlCallback>,
    /// Whether the client's streaming reports are written to the log.
    ///
    /// Upstream's `-FPSdata`. A report is a binary plist a mirroring client sends once a
    /// second; it says how the client itself thinks the stream is going, which is the one
    /// view of performance this receiver cannot measure.
    pub log_streaming_reports: bool,
    /// How a client's slider position becomes a gain.
    ///
    /// Upstream's `-taper` and `-db`. The default is the flat `-30..0` decibel mapping.
    pub volume_curve: crate::VolumeCurve,
    /// The volume a session starts at.
    ///
    /// Upstream's `-vol`. The renderer is told once, before any client connects, so a
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

/// Called with the content type and bytes of artwork a client sends.
pub type ArtworkCallback = Arc<dyn Fn(&str, &[u8]) + Send + Sync>;

/// Called with the raw DMAP listing a client sends.
pub type MetadataCallback = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// Called with the `DACP-ID` and `Active-Remote` a request carries.
pub type RemoteControlCallback = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// What the two streams' first frames say about their shared clock.
///
/// A session has to put audio and video on one timeline before either can be scheduled,
/// and the question that decides how is whether the two streams' timestamps count the same
/// thing. The audio timestamp counts samples, so it is unambiguous once the rate is known;
/// the video timestamp's unit is not written down anywhere in the protocol. Rather than
/// assume one, this records the first frame of each stream with the moment it arrived and
/// reports which candidate makes the two agree: if the timestamps share a clock, the
/// difference between them and the difference between the arrivals are the same number.
#[derive(Debug, Default)]
struct ClockProbe {
    audio: Option<(u64, u128)>,
    video: Option<(u64, u128)>,
    /// The previous mirror frame, for the tick rate its deltas imply.
    video_previous: Option<(u64, u128)>,
    /// How many mirror frames have been measured, so the log stays short.
    video_measured: u32,
}

impl ClockProbe {
    /// The local time now, which is what a frame's arrival is measured against.
    fn now() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or(0)
    }

    /// Records the first audio frame, and reports the pair when the video side is known.
    fn audio(&mut self, samples: u64, rate: u32) {
        if self.audio.is_some() {
            return;
        }
        let arrival = Self::now();
        self.audio = Some((samples, arrival));
        log::info!(
            "clock     audio first frame: ts {} samples ({} s at {rate} Hz), arrived at {} ns",
            samples,
            samples as f64 / f64::from(rate.max(1)),
            arrival
        );
        self.report();
    }

    /// Measures the mirror stream's tick rate from two frames.
    ///
    /// The absolute epoch of a mirror timestamp is the start of the stream, which this
    /// receiver has no independent measure of, so comparing it with anything else is
    /// meaningless. What it does describe is how much time passed between two frames, and
    /// dividing that by the time the two frames actually arrived apart gives the rate in
    /// ticks per second. Three frames are measured and the median-ish middle one is what
    /// the log reports, because one measurement of a network arrival is not a measurement.
    fn video_tick_rate(&mut self, timestamp: u64) {
        let arrival = Self::now();
        let Some((previous, previous_arrival)) = self.video_previous.replace((timestamp, arrival))
        else {
            return;
        };
        self.video_measured += 1;
        if self.video_measured > 4 {
            return;
        }
        let ticks = timestamp.saturating_sub(previous) as f64;
        let seconds = (arrival as i64 - previous_arrival as i64) as f64 / 1e9;
        if seconds <= 0.0 || ticks <= 0.0 {
            return;
        }
        // A Q32.32 timestamp ticks 2^32 times a second, so this is also a check on the
        // unit: a delta that divides by 2^32 into one frame interval is fixed point, and
        // one that divides into nothing is some other unit.
        log::info!(
            "clock     video delta {ticks:.0} ticks in {seconds:.6} s -> {:.0} Hz, \
             {:.3} frame intervals at 2^32 ticks a second",
            ticks / seconds,
            seconds * 4_294_967_296.0 / ticks
        );
    }

    /// Records the first mirror frame.
    fn video(&mut self, timestamp: u64) {
        if self.video.is_some() {
            return;
        }
        let arrival = Self::now();
        self.video = Some((timestamp, arrival));
        log::info!("clock     video first frame: ts {timestamp}, arrived at {arrival} ns");
        self.video_previous = Some((timestamp, arrival));
        log::info!(
            "clock       candidates: /90000 = {:.6} s, /1000000 = {:.6} s, /1e9 = {:.6} s, \
             as q32.32 = {}",
            timestamp as f64 / 90_000.0,
            timestamp as f64 / 1_000_000.0,
            timestamp as f64 / 1e9,
            timestamp >> 32
        );
        self.report();
    }

    /// The candidate timebase that makes the two streams agree, with its residual.
    ///
    /// Returns `None` until both first frames have arrived. This is what a device run is
    /// asked for: the answer goes in the log, and a session that disagrees with every
    /// candidate has a timeline problem rather than a scheduling one.
    fn agreement(&self) -> Option<(&'static str, f64)> {
        let ((audio, audio_arrival), (video, video_arrival)) = (self.audio?, self.video?);
        let observed = (video_arrival as i64 - audio_arrival as i64) as f64 / 1e9;
        let audio_seconds = audio as f64 / 44_100.0;
        let mut best: Option<(&'static str, f64)> = None;
        for (name, divisor) in [
            ("90000", 90_000.0),
            ("1e6", 1_000_000.0),
            ("1e9", 1e9),
            ("27e6", 27_000_000.0),
        ] {
            let residual = (audio_seconds - video as f64 / divisor) - observed;
            if best.is_none_or(|(_, lowest)| residual.abs() < lowest.abs()) {
                best = Some((name, residual));
            }
        }
        best.filter(|(_, residual)| residual.abs() < 0.05)
    }

    /// Says which candidate timebase makes the two streams agree, once both are known.
    fn report(&self) {
        let (Some((audio, audio_arrival)), Some((video, video_arrival))) = (self.audio, self.video)
        else {
            return;
        };
        // The audio side is taken as the reference: samples over a known rate is a time.
        // The arrival difference is what a shared clock has to reproduce.
        let observed = (video_arrival as i64 - audio_arrival as i64) as f64 / 1e9;
        let audio_seconds = audio as f64 / 44_100.0;
        log::info!(
            "clock     the two first frames arrived {:.6} s apart, and their timestamps \
             differ by {:.6} s at the audio rate",
            observed,
            audio_seconds - video as f64 / 90_000.0
        );
        for (name, divisor) in [
            ("90000", 90_000.0),
            ("1e6", 1_000_000.0),
            ("1e9", 1e9),
            ("27e6", 27_000_000.0),
        ] {
            let video_seconds = video as f64 / divisor;
            let residual = (audio_seconds - video_seconds) - observed;
            log::info!(
                "clock       if the video clock is {name} Hz: residual {:+.6} s{}",
                residual,
                if residual.abs() < 0.05 {
                    "  <- agrees"
                } else {
                    ""
                }
            );
        }
        match self.agreement() {
            Some((name, residual)) => log::info!(
                "clock     the two streams share a clock: video counts {name} Hz \
                 (residual {:+.6} s)",
                residual
            ),
            None => log::info!(
                "clock     no candidate timebase makes the two agree: the streams do \
                 not share a timestamp domain"
            ),
        }
    }
}
/// A streaming report as a person can read it.
///
/// A report is a binary plist, so it is written out as XML; one that does not parse is
/// summarised as bytes, because a report a receiver cannot read is still evidence that the
/// client is sending something.
fn describe_report(payload: &[u8]) -> String {
    const PREVIEW: usize = 2_048;
    let text = match crate::plist::Plist::parse(payload).and_then(|plist| plist.encode_xml()) {
        Ok(xml) => String::from_utf8_lossy(&xml).into_owned(),
        Err(_) => {
            let shown: Vec<String> = payload
                .iter()
                .take(32)
                .map(|byte| format!("{byte:02x}"))
                .collect();
            format!("{} bytes, not a plist: {}", payload.len(), shown.join(" "))
        }
    };
    if text.chars().count() > PREVIEW {
        text.chars().take(PREVIEW).collect()
    } else {
        text
    }
}

/// The gain a client's decibels mean under `curve`.
///
/// The two scales meet here: a client states decibels (with `-144` for mute) and a renderer
/// plays at a linear gain. Keeping it in one function is what lets the conversion be tested
/// without a sound card.
fn client_gain(db: f32, curve: crate::VolumeCurve) -> f64 {
    let fraction = crate::airplay_db_to_fraction(f64::from(db));
    curve.gain(fraction)
}

/// The decibels a slider position means under `curve`.
fn airplay_volume(fraction: f64, curve: crate::VolumeCurve) -> f64 {
    curve.db_for_fraction(fraction)
}

/// The longest a frame may be held back to keep a stream at its capture spacing.
///
/// A client sends a second of mirror frames in a few tens of milliseconds, so pacing them
/// exactly means the last frame of the burst waits most of a second before it is shown.
/// That is a latency the viewer sees, and it is the one this bounds: past the budget a
/// stream plays the frame it has and re-anchors, trading a few milliseconds of unevenness
/// for not falling behind.
///
/// Forty milliseconds is a little over one frame interval, and it is what a device session
/// asked for: with the budget at a hundred and twenty, the log showed the pacer holding
/// three frames at once - about a hundred milliseconds of it - while the queue in front of
/// the writer held another sixty-five. The pacer's share was the part this crate controls,
/// and cutting it costs only the ability to absorb a burst longer than a frame.
const MAX_LEAD: std::time::Duration = std::time::Duration::from_millis(40);

/// Why a receiver could not start, or could not go on.
#[derive(Debug, Clone)]
pub struct Error {
    message: String,
}

impl Error {
    /// The message this error carries.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Self { message }
    }
}

impl From<&str> for Error {
    fn from(message: &str) -> Self {
        Self {
            message: message.to_owned(),
        }
    }
}

/// Serves clients until the process is asked to stop.
///
/// # Errors
///
/// Returns [`Error`] when a port cannot be bound, the receiver cannot be announced, or a
/// media socket cannot be opened. A session that fails later is reported and does not stop
/// the receiver: the next client is why it is still running.
pub async fn run(config: Config) -> Result<(), Error> {
    let seed = config.seed;
    let renderer = Arc::clone(&config.renderer);
    let device_id = config
        .device_id
        .clone()
        .unwrap_or_else(|| derived_device_id(&seed));

    // A client a previous session verified may start `/pair-verify` on a fresh connection;
    // one that never completed a session is not known yet, which is the honest limit of
    // remembering keys only once a session carries them.
    let known = Arc::clone(&config.clients);
    log::info!("clients   {} remembered", lock(&known).len());

    let mut state = PairingState::new(seed, config.pin).with_client_registered({
        let known = Arc::clone(&known);
        move |key| lock(&known).contains(key)
    });
    if let Some(password) = config.password.as_deref() {
        state = state.with_password(password);
    }
    let state = Arc::new(state);
    let public_key = state.identity_public();

    let identity = DeviceIdentity {
        features: config.features.unwrap_or(crate::server::DEFAULT_FEATURES),
        width: config.display.width,
        height: config.display.height,
        refresh_rate: config.display.refresh_rate,
        max_fps: config.display.max_fps,
        overscanned: config.display.overscanned,
        initial_volume: airplay_volume(config.initial_volume.fraction(), config.volume_curve),
        ..DeviceIdentity::new(&device_id, &config.name, public_key.to_vec())
    };
    let protection = match (config.pin, &config.password) {
        (PinMode::Disabled, None) => Protection::None,
        (PinMode::Disabled, Some(_)) => Protection::Password,
        _ => Protection::Pin,
    };

    // The volume is set once, before a session opens: a renderer is told what level to
    // start at rather than being corrected after the first frame. A client's `-vol` is a
    // slider position, so the curve is what turns it into a gain.
    let initial_gain = config.volume_curve.gain(config.initial_volume.fraction());
    if let Err(error) = config.renderer.set_volume(crate::Volume::new(initial_gain)) {
        log::warn!("rust-airplay: the renderer would not take the initial volume: {error}");
    }
    // Upstream validates the same range when it parses `-al` (`uxplay.cpp:1954-1966`).
    let audio_delay_micros = u32::try_from(config.audio_latency.as_micros())
        .ok()
        .filter(|micros| *micros <= crate::control::MAX_AUDIO_DELAY_MICROS)
        .ok_or_else(|| {
            Error::from(format!(
                "audio latency must be between 0 and {} seconds",
                crate::control::MAX_AUDIO_DELAY_MICROS / 1_000_000
            ))
        })?;
    let server_config = ServerConfig {
        bind: format!("0.0.0.0:{}", config.port)
            .parse()
            .map_err(|error| format!("bind address: {error}"))?,
        audio_delay_micros,
        nohold: config.nohold,
        feedback_timeout: config.feedback_timeout,
        device: identity.clone(),
        ..ServerConfig::default()
    };
    let server = Server::bind(server_config)
        .await
        .map_err(|error| format!("cannot bind port {}: {error}", config.port))?;
    let address = server
        .local_addr()
        .map_err(|error| format!("cannot read the bound address: {error}"))?;

    log::info!("receiver  {} ({device_id})", config.name);
    log::info!("control   {address}");
    log::info!("identity  {}", hex(&public_key));
    match protection {
        Protection::Pin => log::info!("pairing   PIN required, watch this console"),
        Protection::Password => log::info!("pairing   password required"),
        Protection::None => log::info!("pairing   open (legacy pairing only)"),
    }

    // A device session is easier to archive than to describe, so the trace can be
    // appended to a file as well as the console. Nothing written there is a
    // secret: the lines carry what the client sent in the clear and the status it
    // got, and never a body, a key or a signature.
    let log = match config.trace_log.as_deref() {
        Some(path) => {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
            log::info!("logging   {}", path.display());
            Some(Arc::new(Mutex::new(file)))
        }
        None => None,
    };

    let advertisement = Advertisement::new(&identity, address.port(), protection);
    // The same value answers `GET /info?txtAirPlay` and is registered below, so a
    // client that reads the record from either place sees one advertisement.
    let (txt_airplay, txt_raop) = advertisement.txt_records();
    let identity = DeviceIdentity {
        txt_airplay: Some(txt_airplay),
        txt_raop: Some(txt_raop),
        ..identity
    };
    let advertiser = Advertiser::register(&advertisement)
        .map_err(|error| format!("cannot announce the receiver: {error}"))?;
    for fullname in advertiser.fullnames() {
        log::info!("advertised {fullname}");
    }

    // The PIN only exists once a client asks for one, so it is printed when it
    // appears rather than up front.
    let pin_state = Arc::clone(&state);
    std::thread::spawn(move || {
        let mut shown: Option<String> = None;
        loop {
            let pin = pin_state.pending_pin();
            if pin != shown {
                if let Some(pin) = pin.as_deref() {
                    log::info!("*** enter PIN {pin} on the client ***");
                }
                shown = pin;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    });

    let handlers_state = Arc::clone(&state);
    log::info!("waiting for a client (Ctrl+C to stop)");
    // Every line carries the time since the receiver started serving, because
    // "the client takes ages to connect" is a question about elapsed time and a
    // log without timestamps cannot answer it.
    let started = std::time::Instant::now();
    let trace_log = log.clone();

    // The media sockets are bound before anything is advertised, so the ports
    // `SETUP` names are ports that already answer. The receive loop waits for the
    // first `SETUP` that carries a key, because until then there is nothing to
    // decrypt with.
    let media = crate::media::ports::MediaSockets::bind_ports(
        "0.0.0.0:0".parse().expect("bind address"),
        config.ports,
    )
    .await
    .map_err(|error| format!("cannot bind the media ports: {error}"))?;
    let setup_ports = SetupPorts {
        timing_port: Some(
            media
                .timing_port()
                .map_err(|error| format!("timing port: {error}"))?,
        ),
        control_port: Some(
            media
                .control_port()
                .map_err(|error| format!("control port: {error}"))?,
        ),
        data_port: Some(
            media
                .data_port()
                .map_err(|error| format!("data port: {error}"))?,
        ),
        // A mirroring client is told where to connect, so its stream arrives on a
        // port this receiver is already listening on.
        mirror_data_port: Some(
            media
                .mirror_port()
                .map_err(|error| format!("mirror port: {error}"))?,
        ),
        ..SetupPorts::default()
    };
    log::info!(
        "media     timing {} control {} data {} mirror {}",
        setup_ports.timing_port.unwrap_or_default(),
        setup_ports.control_port.unwrap_or_default(),
        setup_ports.data_port.unwrap_or_default(),
        setup_ports.mirror_data_port.unwrap_or_default()
    );
    // The three datagram sockets and the mirror listener are shared by the audio loop
    // and the mirror loop, which watch different ones of them.
    let media = Arc::new(media);
    let audio_renderer = Arc::clone(&renderer);
    let audio_codec = config.audio_codec;
    // The control plane runs until Ctrl+C, and a receive loop that outlived it would keep a
    // sound card or a window open with nothing to play into it.
    let stopping = shutdown_signal();
    let audio_stop = stopping.clone();
    let (media_key, media_ready) = tokio::sync::oneshot::channel::<([u8; 16], [u8; 16])>();
    // What the client says it is sending, as `(coding, samples per frame)`. The SETUP that
    // names an audio stream carries it (`raop_handlers.h:995-1030`), and it can arrive a
    // moment after the SETUP that carries the key, so the audio task waits for it briefly.
    let declared_audio: Arc<Mutex<Option<(AudioCodec, u16)>>> = Arc::new(Mutex::new(None));
    let media_key = Arc::new(Mutex::new(Some(media_key)));
    // The audio key of the session, kept where every control connection can see it.
    //
    // A device sends its audio key in one `SETUP` and its `type: 110` stream entry in a
    // later one without repeating the key — and those two need not be served by the same
    // control connection, because the receiver builds a handler set per connection
    // (`Server::run`'s `new_handlers`). A remembered key that lives inside one of those
    // handler sets is therefore not a key the session has: it is a key that connection
    // saw, and the connection that needs it is the one that never had it. That is why
    // this is shared rather than local.
    let session_audio_key: Arc<Mutex<Option<[u8; 16]>>> = Arc::new(Mutex::new(None));
    // Where the clock exchange goes: the timing port a client named in its `SETUP`,
    // at the address its control connection came from. The receiver starts that
    // exchange, so a session that never learns this never ticks
    // (`raop_ntp.c:614-618`).
    let (timing_target, timing_ready) = tokio::sync::oneshot::channel::<std::net::SocketAddr>();
    let timing_target = Arc::new(Mutex::new(Some(timing_target)));
    // The mirror stream is keyed by the connection identifier a client sends in its
    // `type: 110` stream entry, which arrives in a *different* `SETUP` from the audio
    // key the stream is derived from — and a device may open the mirror connection
    // before either. So the keys live in one place that is written whenever a `SETUP`
    // derives them and read whenever a connection needs them, rather than in a channel
    // that can only hand them over once: a one-shot delivery loses them entirely if
    // the first `SETUP` of a session is the one that consumes it, which is exactly what
    // a device that splits its session across two requests does.
    let (mirror_keys, mirror_ready) =
        tokio::sync::watch::channel::<Option<crate::media::mirror::StreamKeys>>(None);
    let mirror_keys = Arc::new(Mutex::new(mirror_keys));
    // Where the audio task publishes its flush handle once a session starts, so that a
    // `FLUSH` reaching any control connection can clear that session's window.
    let audio_flush: Arc<Mutex<Option<crate::media::audio::FlushHandle>>> =
        Arc::new(Mutex::new(None));
    // The video queue a `FLUSH` has to empty, published by whichever mirror session is
    // running. A receiver has one, so a single slot is enough.
    let video_flush: Arc<Mutex<Option<Arc<FreshestFrames>>>> = Arc::new(Mutex::new(None));
    // The client's clock, as the timing exchange establishes it. Written by the exchange
    // and read by anything that has to know when a client timestamp happens here.
    let clock = Arc::new(Mutex::new(crate::media::timing::RemoteClock::new()));
    // What the first frame of each stream says about the timeline they will share.
    let probe = Arc::new(Mutex::new(ClockProbe::default()));
    let audio_sockets = Arc::clone(&media);
    let audio_stop = audio_stop.clone();
    let audio_flush_task = Arc::clone(&audio_flush);
    let audio_probes = Arc::clone(&probe);
    let declared_audio_task = Arc::clone(&declared_audio);
    tokio::spawn(async move {
        tokio::select! {
            _ = stopped(audio_stop.clone()) => {}
            ready = media_ready => {
                let Ok((key, iv)) = ready else {
                    return;
                };
                // A client that names its coding gets that coding; one that never does
                // falls back to the configured default after a short wait. Upstream starts
                // audio from the same declaration (`raop_handlers.h:995-1034`), so the wait
                // is the interval between two SETUP requests rather than a guess.
                let waiting = std::time::Instant::now();
                let declared = loop {
                    if let Some(found) = declared_audio_task.lock().ok().and_then(|slot| *slot) {
                        break Some(found);
                    }
                    if waiting.elapsed() >= std::time::Duration::from_millis(500) {
                        break None;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                };
                let (codec, samples_per_frame) = declared.unwrap_or((audio_codec, 480));
                if declared.is_none() {
                    log::info!(
                        "media     no audio format declared; using {} as configured",
                        codec.name()
                    );
                }
                let stream = open_audio(&audio_renderer, codec, samples_per_frame);
                let mut session = crate::media::ports::session(key, iv);
                // Published before the first datagram, so a `FLUSH` that arrives early is
                // not lost: the slot holds the request until the session applies it.
                if let Ok(mut slot) = audio_flush_task.lock() {
                    *slot = Some(session.flush_handle());
                }
                // Audio is pushed by a thread of its own, for the same reason video is:
                // writing to a pipeline blocks when the pipeline is full, and a write that
                // blocks inside the receive loop stops everything that loop is watching —
                // the screen, the control socket and the clock exchange. A session with
                // sound in it froze while a silent one ran, and this is that.
                //
                // A queue that is full drops the frame rather than waiting. Waiting is the
                // fault being avoided, and the receive loop has to keep draining the sockets
                // whatever the pipeline is doing; dropping is counted and reported once, so
                // a pipeline that never recovers is seen rather than buffered away.
                let (feed, queued) = std::sync::mpsc::sync_channel::<crate::AudioFrame>(
                    QUEUED_AUDIO_FRAMES,
                );
                let played = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                let played_writer = std::sync::Arc::clone(&played);
                // The stream is taken out of the `Option` rather than borrowed from it: the
                // writer thread owns it for the life of the session, and a borrowed stream
                // cannot be moved into a thread.
                let playing = stream.map(|playing| {
                    std::thread::spawn(move || {
                        use std::sync::atomic::Ordering;
                        // Anchored on the first frame's arrival, then advancing by the
                        // samples each frame carries: an audio timestamp is an RTP counter
                        // from a random origin, so only its differences mean anything.
                        let mut pacer =
                            crate::media::pace::Pacer::new(crate::media::pace::Ticks::Samples(
                                crate::AudioConfig::default().sample_rate,
                            ));
                        let opened = std::time::Instant::now();
                        while let Ok(frame) = queued.recv() {
                            let arrival = opened.elapsed().as_nanos() as u64;
                            let due = pacer.due_limited(frame.timestamp, arrival, MAX_LEAD);
                            if let Some(wait) = crate::media::pace::Pacer::wait(due, arrival) {
                                std::thread::sleep(wait);
                            }
                            // What real-time playback needs and this backend does not do
                            // yet: the frame carries its timestamp and the sink is told to
                            // play as fast as it is given, so audio runs at whatever rate
                            // the pipeline manages. Named here rather than left implicit.
                            if let Err(error) = playing.push(frame) {
                                log::warn!("rust-airplay: the renderer refused a frame: {error}");
                                break;
                            }
                            played_writer.fetch_add(1, Ordering::Relaxed);
                        }
                        // A last frame already handed over is played out rather than cut
                        // off, which is what an end of stream means to a backend.
                        if let Err(error) = playing.close() {
                            log::warn!("rust-airplay: the audio stream ended badly: {error}");
                        }
                    })
                });
                // The clock exchange runs beside the audio, on its own socket: the
                // receiver is the one that starts it, and upstream keeps it going
                // for as long as the session does.
                let timing_sockets = Arc::clone(&audio_sockets);
                let timing_stop = audio_stop.clone();
                let timing_clock = Arc::clone(&clock);
                let audio_probe = audio_probes;
                let audio_rate = crate::AudioConfig::default().sample_rate;
                tokio::spawn(async move {
                    let Ok(target) = timing_ready.await else {
                        return;
                    };
                    log::info!("media     clock exchange with {target}");
                    let mut sent: u64 = 0;
                    let mut stop = timing_stop;
                    loop {
                        // `build_request` takes Unix nanoseconds and puts the NTP form
                        // of them where upstream puts the send time
                        // (`raop_ntp.c:615-616`).
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|since| since.as_nanos() as u64)
                            .unwrap_or(0);
                        let Ok(request) = crate::media::timing::build_request(now) else {
                            log::warn!("rust-airplay: cannot build a timing request");
                            return;
                        };
                        // The answer echoes these four bytes, and a reply to a request this
                        // receiver never made is not a measurement.
                        let t1 = u32::from_be_bytes([request[24], request[25], request[26], request[27]]);
                        if let Ok(mut clock) = timing_clock.lock() {
                            clock.request_sent(t1);
                        }
                        match timing_sockets.send_timing_request(target, &request).await {
                            Ok(_) => sent += 1,
                            Err(error) => {
                                log::warn!("rust-airplay: cannot send a timing request: {error}");
                                return;
                            }
                        }
                        tokio::select! {
                            _ = stop.changed() => return,
                            _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {}
                        }
                        if sent % 10 == 0 {
                            log::info!("media     {sent} timing requests sent");
                        }
                    }
                });
                let frames = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                let dropped = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                // What a device actually sends, for a decoder that is not this one to
                // identify: a stream that is received, queued and played without a sound is
                // one whose coding is the thing in doubt.
                let dump_frames = config.dump_audio.clone().map(|path| {
                    log::info!("media     writing the audio bytes to {}", path.display());
                    let file = std::fs::File::create(&path)
                        .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
                    std::sync::Arc::new(std::sync::Mutex::new(file))
                });
                // What arrived, so "the client is not sending" and "we are throwing it
                // away" cannot be confused in a log. A session that never reaches the
                // frame counter still says which sockets were written to.
                let received = std::sync::Arc::new(crate::media::ports::Received::default());
                let watching = std::sync::Arc::clone(&received);
                tokio::spawn(async move {
                    let mut last = (0u64, 0u64, 0u64, 0u64);
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        let now = (
                            watching.data(),
                            watching.control(),
                            watching.timing(),
                            watching.unusable(),
                        );
                        if now != last {
                            log::info!(
                                "media     received: data {}, control {}, timing {}, unusable {}",
                                now.0, now.1, now.2, now.3
                            );
                            if let Some(reason) = watching.last_error() {
                                log::info!("media     first datagram that did not fit: {reason}");
                            }
                            last = now;
                        }
                    }
                });
                let outcome = audio_sockets
                    .serve(&mut session, &received, |frame| {
                        use std::sync::atomic::Ordering;
                        let count = frames.fetch_add(1, Ordering::Relaxed) + 1;
                        if count == 1 {
                            log::info!(
                                "media     first audio frame: {} bytes, seq {}, ts {}",
                                frame.payload.len(),
                                frame.sequence,
                                frame.timestamp
                            );
                            if let Ok(mut probe) = audio_probe.lock() {
                                probe.audio(u64::from(frame.timestamp), audio_rate);
                            }
                        } else if count % 500 == 0 {
                            log::info!("media     {count} audio frames received");
                        }
                        if let Some(file) = dump_frames.as_ref().and_then(|dump| dump.lock().ok()) {
                            use std::io::Write;
                            let length = frame.payload.len() as u32;
                            let _ = (&*file).write_all(&length.to_le_bytes());
                            let _ = (&*file).write_all(&frame.payload);
                        }
                        let queued = crate::AudioFrame {
                            data: frame.payload,
                            timestamp: u64::from(frame.timestamp),
                        };
                        if feed.try_send(queued).is_err() {
                            let missed = dropped.fetch_add(1, Ordering::Relaxed) + 1;
                            if missed == 1 {
                                log::warn!(
                                    "rust-airplay: the audio pipeline is not keeping up; \
                                     frames are being dropped rather than stalling the session"
                                );
                            }
                        }
                    }, |answer| {
                        // One answer to one request: `t1` was the second this receiver
                        // sent, `t2` and `t3` are the client's receive and transmit
                        // times, and `t4` is now.
                        let Ok(response) = crate::media::timing::parse_response(answer) else {
                            return;
                        };
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|since| since.as_nanos() as u64)
                            .unwrap_or(0);

                        let Ok(mut clock) = clock.lock() else {
                            return;
                        };
                        let seen = clock.samples_collected();
                        if let Some(sample) = clock.response_received(
                            response.t1,
                            response.t2,
                            response.t3,
                            now,
                        ) {
                            // Logged every time the estimate is new, which is once per
                            // exchange in a quiet room and worth seeing: the offset is what
                            // a schedule is built on, and a wrong one is invisible later.
                            log::info!(
                                "media     clock epoch {:+.3} s (client to local), \
                                 residual {:+.3} ms, delay {:.3} ms, root distance {:.3} ms, \
                                 synced {}, raw t1 {} t2 {} t3 {}",
                                clock.fixed_offset_nanos().unwrap_or(0) as f64 / 1e9,
                                clock.offset_nanos() as f64 / 1e6,
                                sample.delay * 1e3,
                                clock.root_distance_nanos() as f64 / 1e6,
                                clock.is_synced(),
                                response.t1,
                                response.t2,
                                response.t3
                            );
                        } else if seen == 0 {
                            log::debug!("media     timing answer ignored: not an answer to a request");
                        }
                    })
                    .await;
                drop(feed);
                if let Some(playing) = playing {
                    let _ = playing.join();
                }
                log::info!(
                    "media     {} audio frames played of {}, {} dropped",
                    played.load(std::sync::atomic::Ordering::Relaxed),
                    frames.load(std::sync::atomic::Ordering::Relaxed),
                    dropped.load(std::sync::atomic::Ordering::Relaxed)
                );
                if let Err(error) = outcome {
                    log::warn!("rust-airplay: the media session stopped: {error}");
                }
            }
        }
    });

    // A mirroring client connects over TCP after its `SETUP`, and until it does
    // there is nothing to read from. Each connection gets a session of its own: a
    // client that reconnects starts its stream over.
    let mirror_sockets = Arc::clone(&media);
    let mirror_renderer = Arc::clone(&renderer);
    let mirror_stop = stopping.clone();
    let mirror_probe = Arc::clone(&probe);
    let pace_video = config.pace_video;
    let log_reports = config.log_streaming_reports;
    let on_artwork = config.on_artwork.clone();
    let on_metadata = config.on_metadata.clone();
    let on_remote_control = config.on_remote_control.clone();
    let video_flush_task = Arc::clone(&video_flush);
    tokio::spawn(async move {
        // The listener accepts from the moment the receiver is up, which is not the
        // moment it has keys: a device may open the mirror connection before the
        // `SETUP` that carries the `type: 110` stream entry has been answered, and a
        // connection nobody accepts is one the device abandons after a timeout. So
        // the first connection waits for the keys beside the accept rather than
        // behind it.
        log::info!(
            "media     mirror listener ready on port {}",
            mirror_sockets.mirror_port().unwrap_or_default()
        );
        // The keys a connection needs are whatever the last `SETUP` derived, so each
        // connection reads them here rather than being handed them once. A connection
        // that arrives first waits for them beside the accept, and a later `SETUP` that
        // re-keys the stream is picked up without the listener having to restart.
        let mut keys = mirror_ready;
        let mut pending = None;
        loop {
            let mut stream = match pending.take() {
                Some(stream) => stream,
                None => tokio::select! {
                    _ = stopped(mirror_stop.clone()) => return,
                    accepted = mirror_sockets.accept_mirror() => match accepted {
                        Ok(stream) => stream,
                        Err(error) => {
                            log::warn!("rust-airplay: the mirror listener stopped: {error}");
                            return;
                        }
                    },
                },
            };
            // A mirror stream cannot be read without its keys, so a connection that got
            // here first waits for the `SETUP` that derives them. The wait is beside the
            // accept rather than in front of it, so a second connection is still taken.
            // When the client's video socket lands is the client's own idea of being
            // connected, so it is timed against the same origin every trace line uses.
            log::info!(
                "media     mirror stream connected at +{} ms",
                started.elapsed().as_millis()
            );
            let current = loop {
                if let Some(current) = *keys.borrow() {
                    break current;
                }
                tokio::select! {
                    _ = stopped(mirror_stop.clone()) => return,
                    changed = keys.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                    accepted = mirror_sockets.accept_mirror(), if pending.is_none() => match accepted {
                        Ok(stream) => {
                            log::info!("media     another mirror connection is waiting for its keys");
                            pending = Some(stream);
                        }
                        Err(error) => {
                            log::warn!("rust-airplay: the mirror listener stopped: {error}");
                            return;
                        }
                    },
                }
            };
            log::info!(
                "*** mirror stream keyed, reading the connection ({} waiting)",
                usize::from(pending.is_some())
            );
            let keys = current;
            let mut session = match crate::media::mirror::MirrorSession::new(&keys) {
                Ok(session) => session,
                Err(error) => {
                    log::warn!("rust-airplay: cannot start the mirror session: {error}");
                    return;
                }
            };
            // A mirror stream carries its own codec data, so what it needs from the
            // renderer is a video stream and nothing else; the size is whatever the client
            // sends, which is not something `SETUP` says.
            // The stream is opened on the first frame rather than when the connection
            // arrives: a client sends its codec configuration before its first frame, and
            // the coding decides which parser and decoder a backend has to build.
            let opening = std::time::Instant::now();
            let mut frames: u64 = 0;
            let mut sent: u64 = 0;
            let mut refused = 0u64;
            // When the frame being pushed belongs, from the client's own timestamps.
            // A mirror stream is one key frame followed by frames that describe only
            // what changed, so decoding faster than real time loses frames the rest of
            // the stream depends on and leaves the picture partly wrong for the rest of
            // the session. The rate is the client's to state, and it is applied in the
            // thread below rather than here: writing to a pipeline and waiting for the
            // next frame are both blocking, and a receive loop is not a place a blocking
            // call can be — one that waits stops reading its socket, which stops the
            // client too, and the picture freezes with it.
            // How many frames are waiting for the renderer, kept beside the queue
            // because a channel does not say: it is the number that decides whether a
            // picture is being kept up with or dropped.
            let feed = std::sync::Arc::new(FreshestFrames::new());
            if let Ok(mut slot) = video_flush_task.lock() {
                *slot = Some(Arc::clone(&feed));
            }
            let queued = std::sync::Arc::clone(&feed);
            let opening_writer = opening;
            let writer_renderer = Arc::clone(&mirror_renderer);
            let paused_signal = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let writer_paused = std::sync::Arc::clone(&paused_signal);
            let playing = {
                std::thread::spawn(move || {
                    let mut shown: u64 = 0;
                    let mut video: Option<Box<dyn crate::VideoStream>> = None;
                    // A mirror timestamp counts 2^32 to the second, which the device run
                    // established: consecutive frames differed by 143156808 of them.
                    let mut pacer =
                        crate::media::pace::Pacer::new(crate::media::pace::Ticks::NtpFixed);
                    // A flush is the client saying the picture it is about to send is not
                    // the one on screen; the writer is where that reaches the renderer.
                    let mut flushed = queued.generation();
                    let mut paused = false;
                    while let Some((data, timestamp, idr, received, codec, geometry)) =
                        queued.take()
                    {
                        // What the pacing is actually told, for the first frames: the
                        // interval a device sends is not a frame rate this crate can
                        // assume, and a wrong one is a wait that stalls a picture
                        // instead of pacing it. Printed rather than silently clamped,
                        // because the number is the whole question.
                        if shown < 3 {
                            log::info!(
                                "media     writer frame {}: {} bytes",
                                shown + 1,
                                data.len()
                            );
                        }
                        // The frame's own timestamp says when it is due, and the pacer
                        // is anchored on the first one. This is not the guess that had to
                        // be removed once: that one derived an interval from the pipeline's
                        // throughput, while this derives it from the client's clock, which
                        // is a rate the stream actually has. A frame arriving in a burst
                        // still plays when it was captured.
                        //
                        // Waiting here cannot stall the session: this is the thread that
                        // owns the queue, and the receive loop is on another one dropping
                        // what it cannot hand over.
                        // Two delays make up what the viewer sees, and they are counted
                        // apart: how long the frame waited in the queue to be written, and
                        // how long the pacer then held it. A single number cannot say which
                        // of them to change.
                        let now = started.elapsed().as_nanos() as u64;
                        let arrival = received;
                        let residence = now.saturating_sub(received);
                        let wanted = pacer.due(timestamp, arrival);
                        let due = pacer.due_limited(timestamp, arrival, MAX_LEAD);
                        let mut waited = 0;
                        if pace_video && let Some(wait) = crate::media::pace::Pacer::wait(due, now)
                        {
                            std::thread::sleep(wait);
                            waited = wait.as_millis();
                        }
                        if shown < 40 || shown % 120 == 0 {
                            log::info!(
                                "media     pace frame {shown}: queued {:.0} ms, \
                                 pacer wanted {:.0} ms, waited {waited} ms",
                                residence as f64 / 1e6,
                                wanted.saturating_sub(arrival) as f64 / 1e6
                            );
                        }
                        // The first frame opens the stream, with the coding the client
                        // announced.
                        if video.is_none() {
                            match writer_renderer.open_video(crate::VideoConfig {
                                width: geometry.map(|geometry| u32::from(geometry.width)),
                                height: geometry.map(|geometry| u32::from(geometry.height)),
                                codec,
                            }) {
                                Ok(stream) => {
                                    log::info!(
                                        "media     video stream open in {} ms (at +{} ms), {} frames",
                                        opening_writer.elapsed().as_millis(),
                                        started.elapsed().as_millis(),
                                        codec.name()
                                    );
                                    video = Some(stream);
                                }
                                Err(error) => {
                                    log::warn!("rust-airplay: cannot show video: {error}");
                                    return 0;
                                }
                            }
                        }
                        let Some(video) = video.as_mut() else {
                            return 0;
                        };
                        // A pause is a state, not a frame: the writer owns the stream, so
                        // the flag the receive loop sets is what reaches the backend.
                        let wants_pause = writer_paused.load(std::sync::atomic::Ordering::Relaxed);
                        if wants_pause != paused {
                            paused = wants_pause;
                            let result = if paused {
                                video.pause()
                            } else {
                                video.resume()
                            };
                            if let Err(error) = result {
                                log::warn!(
                                    "rust-airplay: the video stream would not change state: {error}"
                                );
                            }
                        }
                        if queued.generation() != flushed {
                            flushed = queued.generation();
                            if let Err(error) = video.flush() {
                                log::warn!(
                                    "rust-airplay: the video stream would not flush: {error}"
                                );
                            }
                        }
                        if let Err(error) = video.push(crate::VideoFrame {
                            data,
                            timestamp,
                            keyframe: idr,
                        }) {
                            log::warn!("rust-airplay: the renderer refused a frame: {error}");
                            break;
                        }
                        shown += 1;
                    }
                    // A last frame already handed over is played out rather than cut
                    // off, which is what an end of stream means to a backend. A session
                    // that ended before its first frame never opened one.
                    let Some(video) = video else {
                        return shown;
                    };
                    match video.close() {
                        Ok(()) => shown,
                        Err(error) => {
                            log::warn!("rust-airplay: the video stream ended badly: {error}");
                            shown
                        }
                    }
                })
            };
            // Every packet a mirror connection sends, counted before it is
            // interpreted, so that a stream which stops is a stream that stopped
            // arriving rather than one this receiver cannot say anything about.
            //
            // The video dump is opened here, once, for the same reason: `AIRPLAY_DUMP_VIDEO`
            // names a file that the first frames are written to, and doing that per frame
            // would make a diagnostic cost something in every session that does not use it.
            let mut dumping = config.dump_video.clone().and_then(|path| {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .map_err(|error| {
                        log::warn!("rust-airplay: cannot write {}: {error}", path.display())
                    })
                    .ok()
            });
            let received = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let received_bytes = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let watching = std::sync::Arc::clone(&received);
            let watching_bytes = std::sync::Arc::clone(&received_bytes);
            // Frames that reached the renderer. The reporter reads a clone, so the count
            // outlives the serving loop that fills it.
            let frames_out = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let watching_frames = std::sync::Arc::clone(&frames_out);
            // The census the session keeps is the one the reporter reads: it is shared
            // rather than copied, so there is one answer to what became of the packets.
            let watching_census = session.census();
            // The recent packets live beside the census and are read the same way.
            let recent_source = std::sync::Arc::clone(&watching_census);
            let watching_recent = move || recent_source.recent();
            tokio::spawn(async move {
                let mut last = (0u64, 0u64, 0u64);
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    let now = (
                        watching.load(std::sync::atomic::Ordering::Relaxed),
                        watching_bytes.load(std::sync::atomic::Ordering::Relaxed),
                        watching_frames.load(std::sync::atomic::Ordering::Relaxed),
                    );
                    if now != last {
                        log::info!(
                            "media     mirror: {} packets, {} bytes in, {} frames out",
                            now.0,
                            now.1,
                            now.2
                        );
                        // What became of the packets that were not frames. A stream
                        // that is arriving but producing nothing says which of the
                        // kinds it turned into, which is the whole question when a
                        // picture stops.
                        let census = watching_census.read();
                        log::info!(
                            "media     mirror kinds: video {}, codec {}, reports {}, \
                             unknown {} {:?}, not units {}",
                            census.video,
                            census.codec,
                            census.reports,
                            census.unknown,
                            census.last_unknown,
                            census.not_units
                        );
                        // The first payload a reader could not take, with the bytes it
                        // was given: a payload that is not units is either a decryption
                        // gone wrong or a framing this receiver does not have, and the
                        // bytes are what says which.
                        if let Some(bad) = &census.first_bad {
                            log::info!(
                                "media     first unreadable payload: {} bytes declared, {} read: \
                                 {} (bytes: {})",
                                bad.declared,
                                bad.length,
                                bad.error,
                                bad.preview
                            );
                            // The packets either side of it. A keystream that has gone
                            // out of step is only visible across packets, and the one
                            // that broke it is the one just before the first payload
                            // that could not be read.
                            log::info!(
                                "media     packets around it (size, carry->carry, blocks->blocks, \
                                 first bytes, idr, read):"
                            );
                            for packet in watching_recent() {
                                log::info!(
                                    "media       {:>7} B  carry {}->{}  blocks {}->{}  \
                                     {:02x}{:02x}{:02x}{:02x}  idr={}  {}",
                                    packet.declared,
                                    packet.carried_before,
                                    packet.carried_after,
                                    packet.blocks_before,
                                    packet.blocks_after,
                                    packet.first[0],
                                    packet.first[1],
                                    packet.first[2],
                                    packet.first[3],
                                    packet.idr,
                                    if packet.read { "frame" } else { "NOT READ" }
                                );
                            }
                        }
                        last = now;
                    }
                }
            });
            let paused_feed = std::sync::Arc::clone(&feed);
            let mut was_paused = false;
            let outcome = stream
                .serve(
                    &mut session,
                    |header, bytes| {
                        received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        received_bytes
                            .fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
                        // Upstream's `-FPSdata` prints the client's streaming reports, which
                        // are binary plists sent once a second (`raop_rtp_mirror.c:800-824`).
                        if log_reports
                            && matches!(header.kind, crate::media::mirror::MirrorKind::StreamingReport)
                        {
                            log::info!("media     streaming report: {}", describe_report(bytes));
                        }
                        // Nothing to do here: the census is shared, so the reporter
                        // reads it as it stands. A copy per packet would be a copy of
                        // something the reporter can already see.
                    },
                    |frame, info| {
                    frames += 1;
                    // A paused client is not a quiet one: the picture on screen is the one
                    // it stopped on, and the frames queued behind it are from a stream
                    // that is not advancing. Upstream calls its renderer's pause here
                    // (`raop_rtp_mirror.c:580-586`); dropping the queue is what this
                    // crate can do without asking a backend to freeze a window.
                    if info.paused != was_paused {
                        was_paused = info.paused;
                        paused_signal.store(info.paused, std::sync::atomic::Ordering::Relaxed);
                        paused_feed.clear();
                        log::info!(
                            "media     the client {} video",
                            if info.paused { "paused" } else { "resumed" }
                        );
                    }
                    frames_out.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if frames == 1 {
                        log::info!(
                            "media     first video frame at +{} ms: {} bytes, {} units, idr={}, ts={}",
                            started.elapsed().as_millis(),
                            frame.data.len(),
                            frame.units,
                            frame.idr,
                            frame.timestamp
                        );
                        if let Ok(mut probe) = mirror_probe.lock() {
                            probe.video(frame.timestamp);
                        }
                    } else if frames <= 5 {
                        // The rate is what turns a timestamp into a play time, and it is
                        // measured rather than assumed.
                        if let Ok(mut probe) = mirror_probe.lock() {
                            probe.video_tick_rate(frame.timestamp);
                        }
                    } else if frames % 200 == 0 {
                        log::info!("media     {frames} video frames received");
                    }
                    // The bytes handed to a decoder are what a picture is diagnosed
                    // from, and nothing else can say whether a stream is malformed or
                    // merely hard to follow: `AIRPLAY_DUMP_VIDEO=<path>` writes the first
                    // frames as an Annex-B stream a second decoder can read.
                    //
                    // The file is opened once, below, and only when the variable is set:
                    // this runs for every frame of every session, and reading an
                    // environment variable and opening a file per frame is a cost the
                    // receive loop pays for a feature that is off in any session nobody is
                    // diagnosing.
                    if let Some(file) = dumping.as_mut() {
                        if frames <= 30 {
                            use std::io::Write;
                            let _ = file.write_all(&frame.data);
                        }
                    }
                    // A full queue means the picture is behind what a client sent. The
                    // oldest frame goes rather than the newest, so the lag stays at the
                    // queue's depth instead of growing: what the renderer gets is always
                    // the most recent frames there are. It is said once, because either
                    // way a dropped frame is one the rest of the stream may depend on.
                    sent += 1;
                    let received = started.elapsed().as_nanos() as u64;
                    let depth = feed.put((
                        frame.data,
                        frame.timestamp,
                        frame.idr,
                        received,
                        info.codec,
                        info.geometry,
                    ));
                    if refused == 0 && depth >= QUEUED_FRAMES {
                        refused = 1;
                        log::warn!(
                            "rust-airplay: the renderer is {QUEUED_FRAMES} frames behind; \
                             frames are being dropped and the picture will be incomplete"
                        );
                    }
                    if sent % 200 == 0 {
                        log::info!("media     {sent} video frames queued, {depth} waiting");
                    }
                })
                .await;
            // Dropping the queue is what ends the writer, and waiting for it is what
            // makes the count below the frames that were actually handed over.
            feed.end();
            {
                match playing.join() {
                    Ok(shown) => log::info!(
                        "media     {shown} video frames shown of {frames}, {} dropped to keep up",
                        feed.dropped()
                    ),
                    Err(_) => log::warn!("rust-airplay: the video thread ended unexpectedly"),
                }
            }
            match outcome {
                // The client closing the connection is how a mirror session ends.
                Ok(()) => log::info!("media     the mirror stream ended after {frames} frames"),
                // A connection that comes apart ends that connection, not the session:
                // a client reconnects after a mirror stream goes wrong, and a receiver
                // that dropped its listener because of one bad packet would never see
                // it again. The loop goes back to accepting.
                Err(error) => log::warn!(
                    "rust-airplay: the mirror stream stopped after {frames} frames: {error}\n\
                     rust-airplay: waiting for the client to connect again"
                ),
            }
        }
    });

    // The callback outlives the configuration it arrived in, and a handler set is built per
    // connection, so it is captured once here rather than reached for through `config`.
    let on_client = config.on_client.clone();
    let client_policy = config.client_policy.clone();
    // A client changes the volume with `SET_PARAMETER volume:`; the renderer is where a
    // volume means anything, so the two are connected here.
    let volume_renderer = Arc::clone(&config.renderer);
    let volume_curve = config.volume_curve;
    let result = server
        .run(move || {
            let log = trace_log.clone();
            let mut handlers =
                RouteHandlers::with_pairing(identity.clone(), Arc::clone(&handlers_state));
            // The ports this run actually listens on, so a client is told where
            // to send instead of guessing.
            handlers.set_setup_ports(setup_ports);
            handlers.set_client_policy(client_policy.clone());
            if let Some(callback) = on_artwork.clone() {
                handlers.set_artwork_callback(move |mime, bytes| callback(mime, bytes));
            }
            if let Some(callback) = on_metadata.clone() {
                handlers.set_metadata_callback(move |bytes| callback(bytes));
            }
            if let Some(callback) = on_remote_control.clone() {
                handlers.set_remote_control_callback(move |dacp, remote| callback(dacp, remote));
            }
            {
                let renderer = Arc::clone(&volume_renderer);
                handlers.set_parameter_callback(move |parameter| {
                    if let crate::server::SetParameter::Volume(db) = parameter {
                        // The client sends decibels: -30 is silence, 0 is full, and -144
                        // is its mute signal.
                        let gain = client_gain(db, volume_curve);
                        log::info!(
                            "media     the client set the volume to {db:.1} dB (gain {gain:.3})"
                        );
                        if let Err(error) = renderer.set_volume(crate::Volume::new(gain)) {
                            log::warn!("rust-airplay: the renderer refused a volume: {error}");
                        }
                    }
                });
            }
            // A session that carries a verified client key is a client worth
            // remembering, so the next run can answer for it.
            {
                let known = Arc::clone(&known);
                // Cloned per connection: the callback is moved into the handler that
                // reports a verified client, and that handler runs once per session.
                let on_client = on_client.clone();
                // A flush carries the sequence the client wants to resume at, so a
                // handler can flush the session that is already playing.
                let flushing = Arc::clone(&audio_flush);
                let video_flushing = Arc::clone(&video_flush);
                handlers.set_flush_callback(move |next| {
                    log::info!("media     the client flushed, resuming at sequence {next}");
                    if let Some(handle) = flushing.lock().ok().and_then(|slot| slot.clone()) {
                        handle.request(next);
                    }
                    // The picture on screen is the one the client is leaving behind, and
                    // the frames queued for it are the same. Dropping them is what a flush
                    // means; the writer notices the generation and flushes its stream.
                    let queue = video_flushing.lock().ok().and_then(|slot| slot.clone());
                    if let Some(queue) = queue {
                        let generation = queue.clear();
                        log::info!("media     video queue flushed (generation {generation})");
                    }
                });
                let media_key = Arc::clone(&media_key);
                let mirror_keys = Arc::clone(&mirror_keys);
                let timing_target = Arc::clone(&timing_target);
                // The audio key has to outlive the request that carried it *and* the
                // connection that served it, so it is the session's rather than this
                // handler set's.
                let session_audio_key = Arc::clone(&session_audio_key);
                let declared = Arc::clone(&declared_audio);
                handlers.set_setup_callback(move |request| {
                    for stream in &request.streams {
                        if stream.kind == 96
                            && let Some(codec) = stream
                                .compression_type
                                .and_then(AudioCodec::from_compression_type)
                        {
                            let spf = stream.samples_per_frame.unwrap_or(480);
                            if let Ok(mut slot) = declared.lock() {
                                *slot = Some((codec, spf));
                            }
                        }
                    }
                    // Which streams a client asked for is what decides whether the
                    // mirror listener will ever see a connection, so it is part of
                    // what a session log has to say.
                    let asked: Vec<String> = request
                        .streams
                        .iter()
                        .map(|stream| {
                            // The coding and the frame size, when the client named them:
                            // `ct` is the one field that says which decoder a stream needs,
                            // and a receiver that does not print it is a receiver that
                            // cannot be told its assumption is wrong.
                            let coding = match stream.compression_type {
                                Some(2) => "ct 2 (ALAC)".to_owned(),
                                Some(8) => "ct 8 (AAC-ELD)".to_owned(),
                                Some(other) => format!("ct {other}"),
                                None => "ct absent".to_owned(),
                            };
                            let spf = match stream.samples_per_frame {
                                Some(spf) => format!(", spf {spf}"),
                                None => String::new(),
                            };
                            match stream.stream_connection_id {
                                Some(id) => {
                                    format!("type {} (id {id}, {coding}{spf})", stream.kind)
                                }
                                None => format!("type {} ({coding}{spf})", stream.kind),
                            }
                        })
                        .collect();
                    log::info!("media     SETUP keys [{}]", request.keys.join(", "));
                    log::info!(
                        "media     SETUP asked for [{}], audio key {}, iv {}",
                        asked.join(", "),
                        if request.audio_key.is_some() {
                            "yes"
                        } else {
                            "no"
                        },
                        if request.audio_iv.is_some() {
                            "yes"
                        } else {
                            "no"
                        }
                    );
                    // The clock exchange needs the address the client's control
                    // connection came from, at the port its `SETUP` named. A client
                    // that names no port is the AirPlay 2 "Remote Control" protocol
                    // upstream does not serve (`raop_handlers.h:902-907`), and one
                    // whose request had no transport at all cannot be reached.
                    match (request.client_address, request.client_timing_port) {
                        (Some(address), Some(port)) => {
                            if let Some(sender) = lock(&timing_target).take() {
                                let target = std::net::SocketAddr::new(address.ip(), port);
                                let _ = sender.send(target);
                            }
                        }
                        (address, port) => log::info!(
                            "media     no clock exchange: address {}, timingPort {}",
                            address.map_or("unknown".to_owned(), |a| a.ip().to_string()),
                            port.map_or("absent".to_owned(), |p| p.to_string())
                        ),
                    }
                    // The session key starts the receive loop, once, however many
                    // connections a client opens. It is also kept, because a device
                    // sends its `type: 110` stream entry in a later request without
                    // repeating the key that stream is encrypted under.
                    if let (Some(key), Some(iv)) = (request.audio_key, request.audio_iv) {
                        *lock(&session_audio_key) = Some(key);
                        if let Some(sender) = lock(&media_key).take() {
                            let _ = sender.send((key, iv));
                            log::info!("*** media session keyed, audio can arrive ***");
                        }
                    }
                    // The mirror stream's key is the audio key hashed with the
                    // connection identifier the client chose, and a device sends
                    // those in *different* requests: the key in the first `SETUP`
                    // of a session, the `type: 110` stream entry in a later one
                    // without the key repeated (`raop_handlers.h:955-967` derives
                    // it from the audio key the connection already holds). This
                    // used to be read from the same request, which meant a device
                    // that splits them never got a mirror stream at all: the
                    // listener below waits for keys that were never derived, so a
                    // client that connects is not even accepted.
                    let mirror_stream = request
                        .streams
                        .iter()
                        .find(|stream| stream.kind == MIRROR_STREAM_TYPE);
                    match mirror_stream.and_then(|stream| stream.stream_connection_id) {
                        Some(id) => {
                            let key = request.audio_key.or(*lock(&session_audio_key));
                            let Some(key) = key else {
                                log::warn!(
                                    "rust-airplay: a mirror stream was asked for before any \
                                     audio key arrived, so its bytes cannot be decrypted"
                                );
                                return;
                            };
                            // The keys are published where the listener reads them, so a
                            // connection that is already waiting is released and one that
                            // arrives later finds them.
                            let keys = crate::media::mirror::stream_keys(id, &key);
                            log::info!("*** mirror stream keyed (id {id}), video can arrive ***");
                            lock(&mirror_keys).send_replace(Some(keys));
                        }
                        // A `type: 110` entry with no identifier is a session this
                        // receiver cannot key, and the listener would otherwise wait for
                        // keys nothing will ever derive. Saying so is the difference
                        // between a stream that never arrived and one that arrived and
                        // could not be read — the two looked identical in the last two
                        // sessions, which is what made them slow to tell apart.
                        None if mirror_stream.is_some() => log::warn!(
                            "rust-airplay: the client asked for a mirror stream without \
                             naming its connection id, so its keys cannot be derived"
                        ),
                        None => {}
                    }
                    let Some(client) = request.client_identity else {
                        return;
                    };
                    if lock(&known).insert(client) {
                        log::info!("*** client {} is now remembered ***", hex(&client));
                        if let Some(remember) = &on_client {
                            remember(&client);
                        }
                    }
                });
            }
            // A trace names what a client asked and what it got, which is what
            // makes a device session readable; it never carries a body or key.
            handlers.set_trace_callback(move |trace| {
                // `Active-Remote`/`DACP-ID` name the remote-control connection a
                // client uses; they are shown because a device session is hard to
                // follow without them, not because they prove anything.
                let remote = match (trace.active_remote, trace.dacp_id) {
                    (None, None) => String::new(),
                    (active, dacp) => {
                        format!(" remote={}/{}", active.unwrap_or("-"), dacp.unwrap_or("-"))
                    }
                };
                let line = format!(
                    "[{:>7}ms] -> {:<14} {:<40} cseq={:<6} body={:<6} {}{}{} => {}{}",
                    started.elapsed().as_millis(),
                    trace.method,
                    trace.target,
                    trace
                        .cseq
                        .map(|cseq| cseq.to_string())
                        .unwrap_or_else(|| "-".to_owned()),
                    trace.body_len,
                    trace.content_type.unwrap_or("-"),
                    trace
                        .user_agent
                        .map(|agent| format!(" ua={agent}"))
                        .unwrap_or_default(),
                    if trace.status == 200 { "" } else { " !" },
                    trace.status,
                    remote,
                );
                log::info!("{line}");
                if let Some(log) = log.as_ref() {
                    let _ = writeln!(&mut *lock(log), "{line}");
                }
            });
            handlers
        })
        .await;
    advertiser.unregister().ok();
    result.map_err(|error| Error::from(format!("the service stopped: {error}")))
}
#[cfg(test)]
mod tests {
    use super::{ClockProbe, FreshestFrames, QueuedVideo};

    #[test]
    fn a_streaming_report_is_written_out_as_xml() {
        // Upstream prints these as XML when `-FPSdata` is on (`raop_rtp_mirror.c:816-821`);
        // the point is that a person can read what the client says about its own stream.
        let mut report = plist::Dictionary::new();
        report.insert("fps".to_owned(), plist::Value::from(30u64));
        let payload = crate::plist::Plist::from_value(plist::Value::Dictionary(report))
            .encode_binary()
            .expect("a report");
        let text = super::describe_report(&payload);
        assert!(text.contains("<key>fps</key>"), "{text}");
        assert!(text.contains("<integer>30</integer>"), "{text}");

        // Anything that is not a plist is still evidence, so it is summarised rather than
        // silently dropped.
        let text = super::describe_report(&[0xff, 0x00]);
        assert!(text.contains("not a plist"), "{text}");
    }

    fn frame(timestamp: u64) -> QueuedVideo {
        (
            vec![0u8; 4],
            timestamp,
            true,
            0,
            crate::render::VideoCodec::H264,
            None,
        )
    }

    #[test]
    fn a_client_s_decibels_become_the_gain_a_renderer_plays_at() {
        // The path from `SET_PARAMETER volume` to `Renderer::set_volume`: what a client
        // sends is decibels, and what a sound card takes is a linear gain.
        use super::client_gain;
        use crate::VolumeCurve;
        let flat = VolumeCurve::default();
        assert!((client_gain(0.0, flat) - 1.0).abs() < 1e-12);
        assert_eq!(client_gain(-30.0, flat), 0.0);
        assert_eq!(client_gain(-144.0, flat), 0.0);
        // Half the slider is -15 dB, about 0.178 of the amplitude.
        assert!((client_gain(-15.0, flat) - 10f64.powf(-0.75)).abs() < 1e-12);
        // A value above full is full, not silence.
        assert!((client_gain(5.0, flat) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn a_flush_drops_what_was_queued_and_tells_the_writer() {
        // `FLUSH` is the client saying the picture it is about to send is not the one on
        // screen. The writer owns the renderer's stream, so it has to be told too - that is
        // what the generation is for.
        let queue = FreshestFrames::new();
        assert_eq!(queue.put(frame(1)), 1);
        assert_eq!(queue.put(frame(2)), 2);
        let before = queue.generation();

        let after = queue.clear();
        assert_eq!(after, before + 1, "a flush is one generation");
        assert_eq!(queue.generation(), after);
        // Nothing is left to take, and the queue is not ended: frames after a flush are
        // the ones that should play.
        assert!(queue.try_take().is_none());
        assert_eq!(queue.put(frame(3)), 1);
        assert!(queue.try_take().is_some());
    }

    #[test]
    fn a_ninety_kilohertz_video_clock_is_recognised() {
        // Audio at 44.1 kHz and video at 90 kHz describe the same instants if the numbers
        // are what they claim: one second of samples is 44100, and one second of the video
        // clock is 90000. The arrivals have to tell the same story.
        let mut probe = ClockProbe {
            audio: Some((44_100, 1_000_000_000)),
            video: Some((90_000, 1_000_000_000)),
            ..ClockProbe::default()
        };
        let (name, residual) = probe.agreement().expect("the two agree");
        assert_eq!(name, "90000");
        assert!(residual.abs() < 1e-9, "residual {residual}");

        // A stream that starts later has to be described by its timestamp, not by when it
        // arrived: two seconds of arrival difference and one second of timestamp
        // difference is a disagreement, and the probe must not claim otherwise.
        probe.audio = Some((44_100 * 2, 1_000_000_000));
        assert!(probe.agreement().is_none());
    }
}
