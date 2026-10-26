// SPDX-License-Identifier: GPL-3.0-or-later
//! The audio receive loop and the tasks one session starts.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

use crate::media::audio::FlushHandle;
use crate::media::ports::MediaSockets;
use crate::media::timing::RemoteClock;
use crate::render::{AudioCodec, Renderer};

use super::runtime::*;
use super::state::*;

/// Everything the audio loop needs, moved in once so the loop owns no borrowed state.
pub(super) struct AudioTask {
    pub(super) audio_keys_rx: watch::Receiver<Option<SessionKey>>,
    pub(super) audio_stop: Stopping,
    pub(super) clock: Arc<Mutex<RemoteClock>>,
    pub(super) declared_audio_task: Arc<Mutex<Option<(AudioCodec, u16)>>>,
    pub(super) audio_codec: AudioCodec,
    pub(super) audio_renderer: Arc<dyn Renderer>,
    pub(super) audio_flush_task: Arc<Mutex<Option<FlushHandle>>>,
    pub(super) audio_flush_generations: Arc<Mutex<Option<Arc<AtomicU64>>>>,
    pub(super) audio_sockets: Arc<MediaSockets>,
    pub(super) audio_peer: Arc<Mutex<Option<IpAddr>>>,
    pub(super) audio_control: Arc<Mutex<Option<SocketAddr>>>,
    pub(super) audio_probes: Arc<Mutex<ClockProbe>>,
    pub(super) timing_target_rx: watch::Receiver<Option<SocketAddr>>,
    pub(super) dump_audio: Option<PathBuf>,
}

impl AudioTask {
    pub(super) async fn run(self) {
        let AudioTask {
            audio_keys_rx,
            audio_stop,
            clock,
            declared_audio_task,
            audio_codec,
            audio_renderer,
            audio_flush_task,
            audio_flush_generations,
            audio_sockets,
            audio_peer,
            audio_control,
            audio_probes,
            timing_target_rx,
            dump_audio,
        } = self;
        let mut keys = audio_keys_rx;
        loop {
            // Wait for a key: the first session, or the one after a teardown.
            let session_key = loop {
                let current = *keys.borrow_and_update();
                if let Some(current) = current {
                    break current;
                }
                tokio::select! {
                    _ = stopped(audio_stop.clone()) => return,
                    changed = keys.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                }
            };
            let (key, iv) = (session_key.key, session_key.iv);
            // Every session starts its own clock; the previous one described another
            // device.
            if let Ok(mut clock) = clock.lock() {
                *clock = crate::media::timing::RemoteClock::new();
            }
            // A client that names its coding gets that coding; one that never does
            // falls back to the configured default after a short wait. The protocol starts
            // audio from the same declaration, so the wait
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
            // A flush asks the renderer to drop what it has not played. The writer owns
            // the stream, so it learns about the request through this counter and
            // through the generation carried with every queued frame.
            let flush_generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
            if let Ok(mut slot) = audio_flush_generations.lock() {
                *slot = Some(Arc::clone(&flush_generation));
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
            let (feed, queued) =
                std::sync::mpsc::sync_channel::<(crate::AudioFrame, u64)>(QUEUED_AUDIO_FRAMES);
            let played = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let played_writer = std::sync::Arc::clone(&played);
            let writer_generation = Arc::clone(&flush_generation);
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
                    let mut flushed = 0u64;
                    while let Ok((frame, generation)) = queued.recv() {
                        let current = writer_generation.load(Ordering::Relaxed);
                        if generation < current {
                            // The client flushed while this frame was in the queue:
                            // the renderer has been told to drop what it held, and this
                            // frame belongs to what it dropped.
                            continue;
                        }
                        if generation > flushed {
                            flushed = generation;
                            if let Err(error) = playing.flush() {
                                log::warn!(
                                    "rust-airplay: the audio stream would not flush: {error}"
                                );
                            }
                        }
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
            // receiver is the one that starts it, and the protocol keeps it going
            // for as long as the session does.
            let timing_sockets = Arc::clone(&audio_sockets);
            let timing_stop = audio_stop.clone();
            let timing_clock = Arc::clone(&clock);
            let audio_probe = Arc::clone(&audio_probes);
            let audio_rate = crate::AudioConfig::default().sample_rate;
            let timing_targets = timing_target_rx.clone();
            let timing_task = tokio::spawn(async move {
                let mut stop = timing_stop;
                let mut target_signal = timing_targets.clone();
                let mut target = loop {
                    if let Some(current) = *timing_targets.borrow() {
                        break current;
                    }
                    tokio::select! {
                        _ = stop.changed() => return,
                        changed = target_signal.changed() => {
                            if changed.is_err() {
                                return;
                            }
                        }
                    }
                };
                log::info!("media     clock exchange with {target}");
                let mut sent: u64 = 0;
                loop {
                    // `build_request` takes Unix nanoseconds and puts the NTP form
                    // of them where the protocol puts the send time
                    //.
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
                    let t1 =
                        u32::from_be_bytes([request[24], request[25], request[26], request[27]]);
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
                        changed = target_signal.changed() => {
                            if changed.is_err() {
                                return;
                            }
                            match *timing_targets.borrow() {
                                Some(next) if next != target => {
                                    target = next;
                                    if let Ok(mut clock) = timing_clock.lock() {
                                        *clock = crate::media::timing::RemoteClock::new();
                                    }
                                    log::info!("media     clock exchange with {target}");
                                }
                                Some(_) => {}
                                None => return,
                            }
                        }
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
            // A diagnostic that cannot be written is a warning, not a reason to end a
            // session: the path comes from the program, and a program that asked for a
            // dump is one that wants the session anyway.
            let dump_frames = dump_audio.as_ref().and_then(|path| {
                match std::fs::File::create(path) {
                    Ok(mut file) => {
                        log::info!("media     writing the audio bytes to {}", path.display());
                        // The receive loop must not wait for a disk. A bounded queue and
                        // one writer thread keep a slow file from stalling the sockets;
                        // frames are dropped when the writer cannot keep up.
                        let (sender, receiver) = std::sync::mpsc::sync_channel::<Vec<u8>>(64);
                        std::thread::spawn(move || {
                            use std::io::Write;
                            for bytes in receiver {
                                if file.write_all(&bytes).is_err() {
                                    break;
                                }
                            }
                        });
                        Some(sender)
                    }
                    Err(error) => {
                        log::warn!("rust-airplay: cannot write {}: {error}", path.display());
                        None
                    }
                }
            });
            let dump_dropped = std::sync::atomic::AtomicU64::new(0);
            // What arrived, so "the client is not sending" and "we are throwing it
            // away" cannot be confused in a log. A session that never reaches the
            // frame counter still says which sockets were written to.
            let received = std::sync::Arc::new(crate::media::ports::Received::default());
            let watching = std::sync::Arc::clone(&received);
            let reporter = tokio::spawn(async move {
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
                            now.0,
                            now.1,
                            now.2,
                            now.3
                        );
                        if let Some(reason) = watching.last_error() {
                            log::info!("media     first datagram that did not fit: {reason}");
                        }
                        last = now;
                    }
                }
            });
            let mut session_watch = keys.clone();
            let peer = audio_peer.lock().ok().and_then(|peer| *peer);
            // Resend requests are sent from the control socket asynchronously: the
            // receive loop cannot wait for a socket write and still drain audio.
            let (resend_tx, mut resend_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u16>>();
            let control_sockets = Arc::clone(&audio_sockets);
            let control_target = Arc::clone(&audio_control);
            let resend_task = tokio::spawn(async move {
                let mut control_sequence = 0u16;
                while let Some(missing) = resend_rx.recv().await {
                    let Some(target) = control_target.lock().ok().and_then(|target| *target) else {
                        continue;
                    };
                    for sequence in missing {
                        control_sequence = control_sequence.wrapping_add(1);
                        let request =
                            crate::media::control::resend_request(control_sequence, sequence, 1);
                        if let Err(error) = control_sockets.send_control(target, &request).await {
                            log::warn!("rust-airplay: cannot send a resend request: {error}");
                            break;
                        }
                    }
                }
            });
            let outcome = tokio::select! {
                _ = stopped(audio_stop.clone()) => Ok(()),
                _ = session_watch.changed() => Ok(()),
                result = audio_sockets
                .serve_from(
                    &mut session,
                    &received,
                    peer,
                    |frame| {
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
                    if let Some(dump) = dump_frames.as_ref() {
                        let mut bytes = Vec::with_capacity(4 + frame.payload.len());
                        bytes.extend_from_slice(&(frame.payload.len() as u32).to_le_bytes());
                        bytes.extend_from_slice(&frame.payload);
                        if dump.try_send(bytes).is_err() {
                            let missed = dump_dropped.fetch_add(1, Ordering::Relaxed) + 1;
                            if missed == 1 {
                                log::warn!(
                                    "rust-airplay: the audio dump cannot keep up;                                      frames are being dropped from the diagnostic copy"
                                );
                            }
                        }
                    }
                    let queued = crate::AudioFrame {
                        data: frame.payload,
                        timestamp: u64::from(frame.timestamp),
                    };
                    let generation = flush_generation.load(Ordering::Relaxed);
                    if feed.try_send((queued, generation)).is_err() {
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
                }, |missing| {
                    let _ = resend_tx.send(missing.to_vec());
                })
                => result,
            };
            drop(feed);
            if let Some(playing) = playing {
                let _ = playing.join();
            }
            resend_task.abort();
            log::info!(
                "media     {} audio frames played of {}, {} dropped",
                played.load(std::sync::atomic::Ordering::Relaxed),
                frames.load(std::sync::atomic::Ordering::Relaxed),
                dropped.load(std::sync::atomic::Ordering::Relaxed)
            );
            let failed = outcome.is_err();
            if let Err(error) = outcome {
                log::warn!("rust-airplay: the media session stopped: {error}");
            }
            reporter.abort();
            timing_task.abort();
            if *audio_stop.borrow() {
                return;
            }
            if failed {
                // The socket failed while this key was current. Reopening it would
                // only fail again, so wait for the next `SETUP` or a teardown.
                while *keys.borrow() == Some(session_key) {
                    tokio::select! {
                        _ = stopped(audio_stop.clone()) => return,
                        changed = keys.changed() => {
                            if changed.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}
