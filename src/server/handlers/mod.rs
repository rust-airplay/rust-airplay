// SPDX-License-Identifier: GPL-3.0-or-later
//! Route handlers for the network control service.
//!
//! A handler contributes the status code, reason phrase, body and headers of the route it
//! serves. The routing decision, the `Audio-Jack-Status`/`Server`/`CSeq` envelope, and the
//! answer for a route no handler serves stay in [`crate::control`].

mod routes;
mod types;

pub use routes::RouteHandlers;
#[cfg(test)]
pub(crate) use routes::stream_connection_id;
pub use types::*;

#[cfg(test)]
use crate::control::{RouteHandler, RouteReply, RouteRequest};
#[cfg(test)]
use crate::fairplay::SETUP_REQUEST_LEN;
#[cfg(test)]
use crate::plist::Plist;
#[cfg(test)]
use crate::server::pairing::SessionAuth;

#[cfg(test)]
mod tests;
