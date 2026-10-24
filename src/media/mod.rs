// SPDX-License-Identifier: GPL-3.0-or-later
//! The media streams a client sends after `SETUP`.
//!
//! The protocol splits this work in two: the protocol side receives datagrams, decrypts them and
//! puts them back in order (`lib/raop_rtp.c`, `lib/raop_rtp_mirror.c`,
//! `lib/raop_buffer.c`), and the renderer side decodes and plays them (`renderers/`). This
//! module is the first half: it belongs to the protocol core, depends on no media library, and
//! hands coded frames to whoever renders them.
//!
//! | Module | What it does |
//! | --- | --- |
//! | [`audio`] | RTP audio: decryption, a bounded reordering window, resend requests, flush |
//! | [`control`] | the UDP control socket: resend requests and the packets a client answers with |
//! | [`mirror`] | the TCP mirror stream: 128-byte headers, AES-CTR, codec data, geometry, pause |
//! | [`timing`] | the NTP exchange that gives a client timestamp a local meaning |
//! | [`pace`] | turning a stream's timestamps into due times, with a lead that is bounded |
//! | [`ports`] | the four ports a session binds, and the sockets bound to them |
//! | [`dmap`] | the now-playing listing a client sends with its audio |

pub mod audio;
pub mod control;
pub mod dmap;
pub mod mirror;
pub mod pace;
pub mod ports;
pub mod timing;
