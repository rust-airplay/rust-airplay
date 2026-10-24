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
//! The crate does not print and does not touch the filesystem. It reports through the `log`
//! crate, and everything a program would otherwise have to know - the PIN, artwork, metadata,
//! the client list, where a trace goes - is a value or a callback on [`receiver::Config`].
//!
//! # Minimum supported Rust version
//!
//! 1.85, because the crate is written in the 2024 edition. Raising it is a breaking change and
//! is noted in the changelog.
//!
//! # Licence
//!
//! GPL-3.0-or-later, because parts of it are translations of GPL and LGPL sources. A program
//! that links this crate is bound by the same licence; see the repository's `README.md` and
//! `THIRD_PARTY_NOTICES.md`.

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
    RemoteControlCallback, run,
};
pub use render::{
    AudioCodec, AudioConfig, AudioFrame, AudioStream, NullRenderer, RenderError, Renderer,
    VideoCodec, VideoConfig, VideoFrame, VideoStream, Volume, VolumeCurve, airplay_db_to_fraction,
};
