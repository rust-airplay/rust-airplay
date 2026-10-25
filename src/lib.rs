// SPDX-License-Identifier: GPL-3.0-or-later
//! A library for building AirPlay 1 and AirPlay 2 receivers: the protocol, the media sessions,
//! and the boundary a playback backend plugs into.
//!
//! The crate answers a client from the moment it is discovered until its streams end:
//!
//! - [`discovery`] advertises the receiver over mDNS, so devices list it;
//! - [`server`] answers the RTSP control connection, with [`pairing`] and [`fairplay`]
//!   providing the authentication a client expects;
//! - [`media`] opens the timing, control, data and mirror sockets, decrypts the streams and
//!   turns them into [`render::AudioFrame`]s and [`render::VideoFrame`]s;
//! - [`render::Renderer`] is the seam: whatever implements it plays those frames.
//!
//! # Quick start
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use rust_airplay::{Config, NullRenderer};
//!
//! # async fn start() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::new("Living room", [0x2a; 32], Arc::new(NullRenderer::new()));
//! rust_airplay::run(config).await?;
//! # Ok(())
//! # }
//! ```
//!
//! [`NullRenderer`] counts frames and plays nothing, which is how a session is inspected
//! without a sound card or a display. A real playback backend implements [`render::Renderer`];
//! the repository's `docs/BACKEND.md` walks through that contract step by step, and the
//! `rust-airplay-gstream` crate is a complete implementation of it.
//!
//! # How the pieces fit
//!
//! | Module | What it is |
//! | --- | --- |
//! | [`receiver`] | the whole receiver as one call: [`receiver::run`] and [`receiver::Config`] |
//! | [`discovery`] | the mDNS service a client finds |
//! | [`server`] | the RTSP control connection and the routes it serves |
//! | [`pairing`], [`fairplay`], [`crypto`], [`srp`] | how a client proves who it is |
//! | [`media`] | media sockets, decryption, RTP, framing and pacing |
//! | [`render`] | the backend boundary and the values that cross it |
//! | [`control`], [`wire`], [`plist`], [`rtp`], [`ntp`] | protocol primitives the layers above are built from |
//!
//! # Runtime model
//!
//! [`receiver::run`] is `async` and serves every connection on the caller's Tokio runtime, so
//! that runtime has to be enabled. Work that blocks has a thread of its own - the video writer
//! and the audio `appsrc` pump - and a backend is handed one frame at a time from those
//! threads. [`render::Renderer`] and its streams are therefore `Send + Sync`, and audio and
//! video may call into them concurrently.
//!
//! [`receiver::run`] stops on Ctrl+C; [`receiver::serve`] is the same receiver with the stop
//! condition supplied by the caller, which is what a test or a program with its own signal
//! uses. A new `SETUP` carrying an audio key replaces the session the media loop is reading,
//! so one receiver process serves a client that reconnects.
//!
//! The crate does not print and does not touch the filesystem. It reports through the `log`
//! crate, and everything a program would otherwise have to know - the PIN, artwork, metadata,
//! the client list, where a trace goes - is a value or a callback on [`receiver::Config`].
//!
//! # Logging
//!
//! The crate never prints. It records through the [`log`] crate: session milestones at
//! `info`, the request trace at `debug`, and anything a program should see at `warn`. A
//! program installs the logger and chooses the filter, so the same library serves a quiet
//! receiver and a diagnostic run.
//!
//! [`receiver::Config::trace_log`] writes the request trace to a file whether or not the
//! console shows it, which is how a session is reconstructed after the fact.
//!
//! # Examples
//!
//! The repository ships a complete renderer in `examples/recorder.rs`. It implements the
//! whole [`render::Renderer`] contract and is compiled by `cargo test --all-targets`, so it can
//! be read as the shortest working backend.
//!
//! # Cargo features
//!
//! None. Every dependency is required, and there is one build configuration.
//!
//! # Minimum supported Rust version
//!
//! 1.85, because the crate is written in the 2024 edition. Raising it is a breaking change and
//! is noted in the changelog.
//!
//! # Licence
//!
//! GPL-3.0-or-later. Parts of it are translations of earlier free-software sources; see the
//! repository's [README](https://github.com/rust-airplay/rust-airplay#readme) and
//! [THIRD_PARTY_NOTICES](https://github.com/rust-airplay/rust-airplay/blob/main/THIRD_PARTY_NOTICES.md)
//! for their provenance and the licence terms. A program that links this crate is bound by the
//! same licence.
//!
//! # See also
//!
//! - [The backend guide](https://github.com/rust-airplay/rust-airplay/blob/main/docs/BACKEND.md):
//!   the renderer contract, in the order a backend meets it
//! - [The architecture](https://github.com/rust-airplay/rust-airplay/blob/main/docs/ARCHITECTURE.md):
//!   the crates and the path a session takes
//! - [The API guide](https://github.com/rust-airplay/rust-airplay/blob/main/docs/API.md):
//!   a map of the types this rustdoc describes in detail

pub mod control;
pub mod crypto;
pub mod discovery;
pub mod fairplay;
mod fairplay_tables;
pub mod media;
pub mod ntp;
pub mod pairing;
mod playfair;
mod playfair_tables;
pub mod plist;
pub mod receiver;
pub mod render;
pub mod rtp;
pub mod server;
pub mod srp;
pub mod wire;

pub use receiver::{
    ArtworkCallback, Config, Error as ReceiverError, MetadataCallback, PinCallback,
    RemoteControlCallback, run, serve,
};
pub use render::{
    AudioCodec, AudioConfig, AudioFrame, AudioStream, NullRenderer, RenderError, Renderer,
    VideoCodec, VideoConfig, VideoFrame, VideoStream, Volume, VolumeCurve, airplay_db_to_fraction,
};
