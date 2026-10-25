// SPDX-License-Identifier: GPL-3.0-or-later
//! The receiver: what a program runs to answer clients.
//!
//! [`run`] is the whole of it. It binds the control service and the media sockets, announces
//! the receiver over mDNS, answers `SETUP` with the ports it bound, hands each session its
//! keys and plays what arrives through whatever [`Renderer`](crate::render::Renderer) the caller supplied. It returns
//! only when the process is asked to stop, and it does not start a runtime of its own: the
//! caller drives the future.
//!
//! # What a caller supplies
//!
//! Three values cannot be invented: the name a client sees, the seed every identity key
//! derives from, and the renderer that plays the media. [`Config::new`] fills in the rest.
//! Everything else is a field, and the ones a program usually touches are the PIN policy
//! ([`PinMode`](crate::server::PinMode)), the client list ([`Config::clients`] with [`Config::on_client`]), the PIN
//! callback ([`Config::on_pin`]) and the diagnostics ([`Config::trace_log`] and the two
//! dumps).
//!
//! # What it does not do
//!
//! It decides no policy: there is no command line, no path, no environment variable and no
//! printing here. Those are [`Config`] values and `log` records, and the program that runs a
//! receiver fills them in.
//!
//! # Examples
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use rust_airplay::{Config, NullRenderer};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::new("Living room", [0x42; 32], Arc::new(NullRenderer::new()));
//! rust_airplay::run(config).await?;
//! # Ok(())
//! # }
//! ```
//!
//! The future never returns `Ok` in a process that is not asked to stop; a program that ends
//! the receiver ends the future, which is the same as the stop signal.

mod config;
mod runtime;
mod serve;
mod state;

pub use config::{
    ArtworkCallback, ClientCallback, Config, MetadataCallback, PinCallback, RemoteControlCallback,
};
pub use runtime::Error;
pub use serve::{run, serve};

#[cfg(test)]
mod tests;
