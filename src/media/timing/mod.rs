// SPDX-License-Identifier: GPL-3.0-or-later
//! The timing port of a session.
//!
//! A client and a receiver agree on how their clocks relate by exchanging timing
//! packets on their own port, which `SETUP` negotiates. The protocol sends a
//! thirty-two byte request and reads three values out of the answer
//!
//!
//! ```text
//! request[0] 0x80
//! request[1] 0xd2, whose type is 0x52
//! request[2..3] 0x00 0x07
//! request[24..31] the local time when the request went out
//! ```
//!
//! and out of the response it reads
//!
//! ```text
//! response[8..11] t1, 32 bits, big endian
//! response[16..19] t2, 32 bits, the client's receive time
//! response[24..27] t3, 32 bits, the client's transmit time
//! ```
//!
//! This module is both halves of that exchange. [`build_request`] and [`parse_response`] are
//! the packet layer; [`RemoteClock`] is the clock on top of it, which filters the exchanges,
//! keeps the offset that turns a client timestamp into a local time, and refuses answers
//! that echo no request or repeat one.
//!
//! The arithmetic is integer nanoseconds because the wire values are whole seconds: `t1`,
//! `t2` and `t3` are 32-bit seconds and the protocol truncates the arrival time to the same
//! width. A fraction mixed into that arithmetic makes the offset
//! wrong by half a round trip. What the exchange establishes is an epoch, not a fine

mod clock;
mod request;

pub use clock::{ClockSample, OUTSTANDING_REQUESTS, RemoteClock, q32_32_to_nanos};
pub use request::{
    RESPONSE_MIN_LEN, RESPONSE_TYPE, TIMING_REQUEST_LEN, TimingError, TimingResponse,
    build_request, parse_response,
};

#[cfg(test)]
mod tests;
