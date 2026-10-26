// SPDX-License-Identifier: GPL-3.0-or-later
//! The mirror listener: accepting a connection, waiting for its keys and serving it.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::watch;

use crate::media::mirror::StreamKeys;
use crate::media::ports::MediaSockets;
use crate::render::Renderer;

use super::runtime::*;
use super::state::*;

/// Everything the mirror listener needs, moved in once.
pub(super) struct MirrorTask {
    pub(super) mirror_sockets: Arc<MediaSockets>,
    pub(super) mirror_renderer: Arc<dyn Renderer>,
    pub(super) mirror_stop: Stopping,
    pub(super) mirror_probe: Arc<Mutex<ClockProbe>>,
    pub(super) mirror_peer: Arc<Mutex<Option<IpAddr>>>,
    pub(super) pace_video: bool,
    pub(super) log_reports: bool,
    pub(super) video_flush_task: Arc<Mutex<Option<Arc<FreshestFrames>>>>,
    pub(super) started: Instant,
    pub(super) mirror_ready: watch::Receiver<Option<StreamKeys>>,
    pub(super) dump_video: Option<PathBuf>,
}

impl MirrorTask {
    pub(super) async fn run(self) {
        let MirrorTask {
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
            dump_video,
        } = self;
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
            // A mirror stream has to come from the host whose control connection owns
            // the session; the keys are not a reason to let a second host on the
            // network put frames into the renderer.
            if let Some(expected) = mirror_peer.lock().ok().and_then(|peer| *peer) {
                if stream.peer_addr().ip() != expected {
                    log::warn!(
                        "rust-airplay: refused a mirror connection from {} \
                         (session peer {expected})",
                        stream.peer_addr()
                    );
                    continue;
                }
            }
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
            let video_opened = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let writer_opened = std::sync::Arc::clone(&video_opened);
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
                    // The interval between the last two frames is the stream's capture
                    // spacing; it is what a backend that paces itself needs to know.
                    let mut previous_timestamp: Option<u64> = None;
                    let mut pace_reported = false;
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
                        if pace_video {
                            if let Some(wait) = crate::media::pace::Pacer::wait(due, now) {
                                std::thread::sleep(wait);
                                waited = wait.as_millis();
                            }
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
                                    writer_opened.store(true, std::sync::atomic::Ordering::Relaxed);
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
                        // When the receiver is not pacing the stream itself, the backend
                        // gets the spacing the stream is arriving at and can schedule its
                        // own waits. The first frame has no interval to report.
                        if !pace_video {
                            if let Some(previous) = previous_timestamp {
                                let ticks = timestamp.wrapping_sub(previous);
                                let seconds = if ticks > u64::MAX / 2 {
                                    0.0
                                } else {
                                    ticks as f64 / 4_294_967_296.0
                                };
                                if let Err(error) = video.set_pace(seconds) {
                                    if !pace_reported {
                                        pace_reported = true;
                                        log::warn!(
                                            "rust-airplay: the video stream would not take a pace: \
                                             {error}"
                                        );
                                    }
                                }
                            }
                        }
                        previous_timestamp = Some(timestamp);
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
            // The video dump is opened here, once, for the same reason: it names a file the
            // first frames are written to, and opening it per frame would make a diagnostic
            // cost something in every session that does not use it.
            let dumping = dump_video.clone().and_then(|path| {
                match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                {
                    Ok(mut file) => {
                        log::info!("media     writing the video bytes to {}", path.display());
                        // The receive loop must not wait for a disk. A bounded queue and
                        // one writer thread keep a slow file from stalling the socket;
                        // the diagnostic copy drops frames rather than the picture.
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
            let reporter = tokio::spawn(async move {
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
            let outcome = tokio::select! {
                _ = stopped(mirror_stop.clone()) => Ok(()),
                result = stream
                .serve(
                    &mut session,
                    |header, bytes| {
                        received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        received_bytes
                            .fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
                        // The protocol's `-FPSdata` prints the client's streaming reports, which
                        // are binary plists sent once a second.
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
                    // that is not advancing. The protocol calls its renderer's pause here
                    //; dropping the queue is what this
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
                    // The file is opened once, above, and only when the variable is
                    // set. The copy goes through a bounded queue to a writer thread, so
                    // this runs for every frame without the receive loop waiting on a
                    // disk; the queue drops its copy rather than the picture.
                    if let Some(dump) = dumping.as_ref() {
                        if frames <= 30 {
                            let _ = dump.try_send(frame.data.clone());
                        }
                    }
                    // A full queue means the picture is behind what a client sent. The
                    // oldest frame goes rather than the newest, so the lag stays at the
                    // queue's depth instead of growing: what the renderer gets is always
                    // the most recent frames there are. It is said once, because either
                    // way a dropped frame is one the rest of the stream may depend on.
                    sent += 1;
                    let received = started.elapsed().as_nanos() as u64;
                    let opened = video_opened.load(std::sync::atomic::Ordering::Relaxed);
                    let (depth, dropped) = feed.put((
                        frame.data,
                        frame.timestamp,
                        frame.idr,
                        received,
                        info.codec,
                        info.geometry,
                    ), opened);
                    if refused == 0 && dropped {
                        refused = 1;
                        log::warn!(
                            "rust-airplay: the renderer fell behind; the oldest frame was                              dropped and the picture may be damaged until the next key frame"
                        );
                    }
                    if sent % 200 == 0 {
                        log::info!("media     {sent} video frames queued, {depth} waiting");
                    }
                })
                => result,
            };
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
            reporter.abort();
            if *mirror_stop.borrow() {
                return;
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
    }
}
