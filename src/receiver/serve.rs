// SPDX-License-Identifier: GPL-3.0-or-later
//! The receiver's main loop and the tasks it starts.

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::discovery::{Advertisement, Advertiser, Protection};
use crate::render::AudioCodec;
use crate::server::{
    DeviceIdentity, PairingState, PinMode, RouteHandlers, Server, ServerConfig, SetupPorts,
};

use super::Config;
use super::audio_task::AudioTask;
use super::mirror_task::MirrorTask;
use super::runtime::*;
use super::state::*;

/// Serves clients until the process is asked to stop.
///
/// This is [`serve`] with the process's Ctrl+C as the shutdown signal. A program that wants
/// another stop condition - a signal, a command, a test - calls [`serve`] and supplies the
/// future that completes when the receiver should return.
///
/// # Errors
///
/// Returns [`Error`] when a port cannot be bound, the receiver cannot be announced, or a
/// media socket cannot be opened. A session that fails later is reported and does not stop
/// the receiver: the next client is why it is still running.
pub async fn run(config: Config) -> Result<(), Error> {
    serve(config, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

/// Serves clients until `shutdown` completes.
///
/// The returned future resolves `Ok(())` once the control service has stopped and the
/// advertisement has been withdrawn. Every loop the receiver started is told to end, so the
/// control port is free when this returns.
///
/// # Errors
///
/// Same as [`run`].
pub async fn serve<F>(config: Config, shutdown: F) -> Result<(), Error>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let seed = config.seed;
    // One stop edge for every loop: the control plane, the media loops and the PIN watcher.
    let (stop_sender, stopping) = tokio::sync::watch::channel(false);
    let shutdown_task = tokio::spawn(async move {
        shutdown.await;
        log::info!("stopping");
        let _ = stop_sender.send(true);
    });
    let renderer = Arc::clone(&config.renderer);
    let device_id = config
        .device_id
        .clone()
        .unwrap_or_else(|| derived_device_id(&seed));

    // A client a previous session verified may start `/pair-verify` on a fresh connection;
    // one that never completed a session is not known yet, which is the honest limit of
    // remembering keys only once a session carries them.
    let known = Arc::clone(&config.clients);

    let mut state = PairingState::new(seed, config.pin);
    // The remembered-client list gates `/pair-verify` only while a PIN is configured.
    // With the PIN disabled the legacy `/pair-setup` is the only way a first client can
    // join, so treating the list as an access control there would lock out every new
    // client; the list is still recorded and reported.
    if config.pin != PinMode::Disabled {
        state = state.with_client_registered({
            let known = Arc::clone(&known);
            move |key| lock(&known).contains(key)
        });
    }
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
    // The protocol validates the same range when it parses `-al`.
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
        bind: std::net::SocketAddr::new(config.bind, config.port),
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
    let advertiser = if config.advertise {
        let advertiser = Advertiser::register(&advertisement)
            .map_err(|error| format!("cannot announce the receiver: {error}"))?;
        for fullname in advertiser.fullnames() {
            log::info!("advertised {fullname}");
        }
        Some(advertiser)
    } else {
        log::info!("advertisement disabled; clients must be told the control address");
        None
    };

    // The PIN only exists once a client asks for one, so it is printed when it
    // appears rather than up front.
    let pin_state = Arc::clone(&state);
    let pin_stop = stopping.clone();
    let on_pin = config.on_pin.clone();
    std::thread::spawn(move || {
        let mut shown: Option<String> = None;
        while !*pin_stop.borrow() {
            let pin = pin_state.pending_pin();
            if pin != shown {
                if let Some(pin) = pin.as_deref() {
                    log::debug!("pairing   a PIN is pending");
                    if let Some(callback) = &on_pin {
                        callback(pin);
                    }
                }
                shown = pin;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    });

    let handlers_state = Arc::clone(&state);
    log::info!("waiting for a client");
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
        std::net::SocketAddr::new(config.bind, 0),
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
    // The control plane runs until the caller's shutdown completes, and a receive loop that
    // outlived it would keep a sound card or a window open with nothing to play into it.
    let audio_stop = stopping.clone();
    // The audio key of the session. A receiver serves more than one session, and a
    // reconnecting client sends a new key; a one-shot channel would deliver the first key
    // and lose every later one, so the key lives in a watch channel the audio loop can
    // follow from session to session.
    let (audio_keys, audio_keys_rx) = tokio::sync::watch::channel::<Option<SessionKey>>(None);
    let audio_generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
    // What the client says it is sending, as `(coding, samples per frame)`. The SETUP that
    // names an audio stream carries it, and it can arrive a
    // moment after the SETUP that carries the key, so the audio task waits for it briefly.
    let declared_audio: Arc<Mutex<Option<(AudioCodec, u16)>>> = Arc::new(Mutex::new(None));
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
    // The host the session's control connection came from. The media sockets are bound
    // to an interface, so this is what keeps a second host on the network from sending
    // into a session it does not own.
    let session_peer: Arc<Mutex<Option<std::net::IpAddr>>> = Arc::new(Mutex::new(None));
    // Where the client receives resend requests for the audio stream, from the
    // `controlPort` of its `SETUP`. A receiver without it can only wait for the
    // reorder window to give up on a lost packet.
    let session_control: Arc<Mutex<Option<std::net::SocketAddr>>> = Arc::new(Mutex::new(None));
    // Where the clock exchange goes: the timing port a client named in its `SETUP`,
    // at the address its control connection came from. The receiver starts that
    // exchange, so a session that never learns this never ticks. A watch channel,
    // because a later session names another address.
    let (timing_target, timing_target_rx) =
        tokio::sync::watch::channel::<Option<std::net::SocketAddr>>(None);
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
    // The generation a `FLUSH` bumps. The writer owns the renderer's audio stream and
    // learns about the flush through this counter, the way the video writer learns
    // through its queue's generation.
    let audio_flush_generation: Arc<Mutex<Option<Arc<std::sync::atomic::AtomicU64>>>> =
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
    let audio_flush_generations = Arc::clone(&audio_flush_generation);
    let audio_peer = Arc::clone(&session_peer);
    let audio_control = Arc::clone(&session_control);
    let audio_probes = Arc::clone(&probe);
    let declared_audio_task = Arc::clone(&declared_audio);
    let audio_task = AudioTask {
        audio_keys_rx,
        audio_stop,
        clock: Arc::clone(&clock),
        declared_audio_task: Arc::clone(&declared_audio_task),
        audio_codec,
        audio_renderer: Arc::clone(&audio_renderer),
        audio_flush_task: Arc::clone(&audio_flush_task),
        audio_flush_generations: Arc::clone(&audio_flush_generations),
        audio_sockets: Arc::clone(&audio_sockets),
        audio_peer: Arc::clone(&audio_peer),
        audio_control: Arc::clone(&audio_control),
        audio_probes: Arc::clone(&audio_probes),
        timing_target_rx,
        dump_audio: config.dump_audio.clone(),
    };
    tokio::spawn(audio_task.run());

    // A mirroring client connects over TCP after its `SETUP`, and until it does
    // there is nothing to read from. Each connection gets a session of its own: a
    // client that reconnects starts its stream over.
    let mirror_sockets = Arc::clone(&media);
    let mirror_renderer = Arc::clone(&renderer);
    let mirror_stop = stopping.clone();
    let mirror_probe = Arc::clone(&probe);
    let mirror_peer = Arc::clone(&session_peer);
    let pace_video = config.pace_video;
    let log_reports = config.log_streaming_reports;
    let on_artwork = config.on_artwork.clone();
    let on_metadata = config.on_metadata.clone();
    let on_remote_control = config.on_remote_control.clone();
    let video_flush_task = Arc::clone(&video_flush);
    let mirror_task = MirrorTask {
        mirror_sockets,
        mirror_renderer,
        mirror_stop,
        mirror_probe,
        mirror_peer,
        pace_video,
        log_reports,
        video_flush_task,
        started,
        mirror_ready,
        dump_video: config.dump_video.clone(),
    };
    tokio::spawn(mirror_task.run());

    // The callback outlives the configuration it arrived in, and a handler set is built per
    // connection, so it is captured once here rather than reached for through `config`.
    let on_client = config.on_client.clone();
    let client_policy = config.client_policy.clone();
    // One volume for every connection: a client that sets it on one and reads it on
    // another is reading the same session.
    let client_volume = Arc::new(Mutex::new(identity.initial_volume));
    // A client changes the volume with `SET_PARAMETER volume:`; the renderer is where a
    // volume means anything, so the two are connected here.
    let volume_renderer = Arc::clone(&config.renderer);
    let volume_curve = config.volume_curve;
    let result = tokio::select! {
        result = server.run(move || {
            let log = trace_log.clone();
            let mut handlers =
                RouteHandlers::with_pairing(identity.clone(), Arc::clone(&handlers_state));
            // The ports this run actually listens on, so a client is told where
            // to send instead of guessing.
            handlers.set_setup_ports(setup_ports);
            handlers.set_client_policy(client_policy.clone());
            handlers.set_debug_body(config.debug_setup_body);
            handlers.set_client_volume(Arc::clone(&client_volume));
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
                let flush_generations = Arc::clone(&audio_flush_generation);
                let video_flushing = Arc::clone(&video_flush);
                handlers.set_flush_callback(move |next| {
                    log::info!("media     the client flushed, resuming at sequence {next}");
                    if let Some(handle) = flushing.lock().ok().and_then(|slot| slot.clone()) {
                        handle.request(next);
                    }
                    if let Some(generation) = flush_generations
                        .lock()
                        .ok()
                        .and_then(|slot| slot.clone())
                    {
                        generation.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                let audio_keys = audio_keys.clone();
                let audio_generation = Arc::clone(&audio_generation);
                let mirror_keys = Arc::clone(&mirror_keys);
                let timing_target = timing_target.clone();
                let session_peer = Arc::clone(&session_peer);
                let session_control = Arc::clone(&session_control);
                // The audio key has to outlive the request that carried it *and* the
                // connection that served it, so it is the session's rather than this
                // handler set's.
                let session_audio_key = Arc::clone(&session_audio_key);
                let declared = Arc::clone(&declared_audio);
                handlers.set_setup_callback(move |request| {
                    if let Some(address) = request.client_address {
                        *lock(&session_peer) = Some(address.ip());
                    }
                    if let (Some(address), Some(port)) = (
                        request.client_address,
                        request
                            .streams
                            .iter()
                            .find(|stream| stream.kind == 96)
                            .and_then(|stream| stream.control_port),
                    ) {
                        *lock(&session_control) =
                            Some(std::net::SocketAddr::new(address.ip(), port));
                    }
                    for stream in &request.streams {
                        if stream.kind == 96 {
                            if let Some(codec) = stream
                                .compression_type
                                .and_then(AudioCodec::from_compression_type)
                            {
                                let spf = stream.samples_per_frame.unwrap_or(480);
                                if let Ok(mut slot) = declared.lock() {
                                    *slot = Some((codec, spf));
                                }
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
                    // the protocol does not serve, and one
                    // whose request had no transport at all cannot be reached.
                    match (request.client_address, request.client_timing_port) {
                        (Some(address), Some(port)) => {
                            let target = std::net::SocketAddr::new(address.ip(), port);
                            timing_target.send_replace(Some(target));
                            log::info!("media     clock exchange target {target}");
                        }
                        (address, port) => log::info!(
                            "media     no clock exchange: address {}, timingPort {}",
                            address.map_or("unknown".to_owned(), |a| a.ip().to_string()),
                            port.map_or("absent".to_owned(), |p| p.to_string())
                        ),
                    }
                    // The session key starts the receive loop. It is also kept, because a
                    // device sends its `type: 110` stream entry in a later request without
                    // repeating the key that stream is encrypted under. A reconnecting
                    // client sends a new key, and the watch channel carries it to the
                    // loop that is already running: a one-shot delivery would keep
                    // decrypting the second session with the first session's key.
                    if let (Some(key), Some(iv)) = (request.audio_key, request.audio_iv) {
                        *lock(&session_audio_key) = Some(key);
                        let current = *audio_keys.borrow();
                        if current.map(|session| (session.key, session.iv)) != Some((key, iv)) {
                            let generation = audio_generation
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                                + 1;
                            audio_keys.send_replace(Some(SessionKey {
                                key,
                                iv,
                                generation,
                            }));
                            log::info!(
                                "*** media session {generation} keyed, audio can arrive ***"
                            );
                        }
                    }
                    // The mirror stream's key is the audio key hashed with the
                    // connection identifier the client chose, and a device sends
                    // those in *different* requests: the key in the first `SETUP`
                    // of a session, the `type: 110` stream entry in a later one
                    // without the key repeated ( derives
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
            // A `TEARDOWN` ends the media session: the key, the clock target and the
            // flush slots belong to that session and are released here rather than
            // left for the next client to overwrite.
            {
                let audio_keys = audio_keys.clone();
                let timing_target = timing_target.clone();
                let mirror_keys = Arc::clone(&mirror_keys);
                let session_audio_key = Arc::clone(&session_audio_key);
                let session_peer = Arc::clone(&session_peer);
                let session_control = Arc::clone(&session_control);
                let audio_flushing = Arc::clone(&audio_flush);
                let flush_generations = Arc::clone(&audio_flush_generation);
                let video_flushing = Arc::clone(&video_flush);
                let declared = Arc::clone(&declared_audio);
                handlers.set_teardown_callback(move || {
                    *lock(&session_audio_key) = None;
                    *lock(&session_peer) = None;
                    *lock(&session_control) = None;
                    audio_keys.send_replace(None);
                    timing_target.send_replace(None);
                    lock(&mirror_keys).send_replace(None);
                    *lock(&audio_flushing) = None;
                    *lock(&flush_generations) = None;
                    *lock(&video_flushing) = None;
                    if let Ok(mut slot) = declared.lock() {
                        *slot = None;
                    }
                    log::info!("media     session torn down");
                });
            }
            handlers
        }) => result,
        _ = stopped(stopping.clone()) => Ok(()),
    };
    if let Some(advertiser) = advertiser {
        advertiser.unregister().ok();
    }
    shutdown_task.abort();
    result.map_err(|error| Error::from(format!("the service stopped: {error}")))
}
