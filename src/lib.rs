// SPDX-License-Identifier: GPL-3.0-or-later
//! An AirPlay receiver: the protocol, a media session, and the boundary a renderer plugs
//! into.
//!
//! A client discovers the receiver over mDNS ([`discovery`]), opens a control connection
//! and pairs ([`server`], [`pairing`]), sets up streams ([`media`]) and sends media that
//! this crate decrypts and turns into frames. What happens to those frames is not this
//! crate's decision: [`render::Renderer`] is the seam, and anything that implements it
//! plays the media. [`render::NullRenderer`] is the one that plays nothing.
//!
//! # What it is not
//!
//! This is an AirPlay *receiver*, which means it answers clients rather than driving them.
//! It does not encode, does not render pixels, and does not decide where a receiver's
//! identity is stored: [`server::DeviceIdentity`] and the client list a caller keeps are
//! values, and a caller reads and writes the files.
//!
//! # Licensing
//!
//! GPL-3.0-or-later, because parts of it are translations of GPL and LGPL sources. A
//! program that links this crate is bound by the same licence; see `README.md` and
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
