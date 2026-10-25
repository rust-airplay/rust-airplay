// SPDX-License-Identifier: GPL-3.0-or-later
//! Pairing state of a receiver and of one control connection.
//!
//! [`PairingState`] holds the facts a receiver keeps across connections: the PIN, whether a
//! PIN is in use, and the long-term Ed25519 identity. [`PairingSession`] holds the exchange of
//! one client, next to that connection's FairPlay session.
//!
//! The rules below are deliberate, and each has a test:
//!
//! * A `/pair-setup-pin` step 3 is refused unless step 2 verified the client proof. The step 3
//!   keys derive from the SRP session key, and that key is all zeroes until the proof is
//!   checked; two requests without any PIN would otherwise let a peer install its own key on
//!   the receiver.
//! * `/pair-setup-pin` without a usable PIN is refused. An implicit PIN would make the SRP
//!   exchange authenticate nothing.
//! * A one-time PIN is consumed only when pairing succeeds, a repeated `/pair-pin-start` keeps
//!   the PIN already pending, and [`MAX_PIN_FAILURES`] wrong proofs drop it. The cost of
//!   consuming late is that two peers who both know the PIN can each complete a pairing until
//!   the first one succeeds; the failure bound keeps that window small.
//! * Values whose lengths the protocol does not require are validated before use, and a step
//!   whose state is missing answers `470` instead of dereferencing it.
//! * A `/pair-verify` step 1 that the injected registration predicate refuses stays refused for
//!   the rest of the connection, and only a `/pair-setup-pin` that proves the PIN lifts it.
//! * A key exchange that yields an all-zero shared secret is refused: a low-order point would
//!   let a peer derive the keystream without holding a private key.
//! * One connection starts one `/pair-verify` key exchange, and one connection opens at most
//!   [`MAX_SETUP_PIN_ATTEMPTS`] SRP contexts, so an unauthenticated peer cannot spend the
//!   receiver's modular exponentiation without limit.

mod session;
mod state;

pub(crate) use session::PairingSession;
#[cfg(test)]
pub(crate) use state::MAX_PASSWORD_FAILURES;
pub(crate) use state::{GCM_TAG_SIZE, MAX_SETUP_PIN_ATTEMPTS, MAX_SRP_PUBLIC, MAX_USERNAME};
pub use state::{MAX_PIN_FAILURES, OsRandom, PairingState, PinMode, RandomError, RandomSource};

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::crypto::{self, CryptoError, ed25519_public_key, x25519_public, x25519_shared};
use crate::pairing::{
    ED25519_KEY_SIZE, PAIRING_SIG_SIZE, X25519_KEY_SIZE, decrypt_pair_verify_signature,
    derive_pair_setup_keys, encrypt_pair_verify_signature, pair_setup_gcm_nonces,
    verify_pair_signature,
};
use crate::plist::{self, Plist};
use crate::srp::{
    APPLE_SESSION_KEY_SIZE, APPLE_SRP_HASH_SIZE, APPLE_SRP_SALT_SIZE, AppleSrpServer,
    constant_time_proof_eq,
};

fn digits(pin: u16) -> [u8; 4] {
    let pin = pin % 10_000;
    [
        b'0' + (pin / 1000) as u8,
        b'0' + (pin / 100 % 10) as u8,
        b'0' + (pin / 10 % 10) as u8,
        b'0' + (pin % 10) as u8,
    ]
}

/// Four zero-padded decimal digits as text.
fn display_pin(pin: u16) -> String {
    digits(pin).iter().map(|byte| *byte as char).collect()
}

/// Lower-case hexadecimal, for diagnostics that must not carry raw key bytes.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Why a pairing request was refused.
///
/// The control service answers every variant with `470 Client Authentication
/// Failure` and no body, the status the protocol uses for a failed pairing step
/// No variant carries key
/// material, so an error can be logged.
#[derive(Debug)]
pub enum PairingError {
    /// The request body was not a binary property list.
    NotPlist,
    /// The body carried neither the keys of a known step nor their types.
    UnexpectedKeys,
    /// A value had a length this crate does not accept.
    InvalidLength(&'static str),
    /// A step arrived before the step it depends on.
    OutOfOrder(&'static str),
    /// Pairing with a PIN is disabled, or no PIN is pending.
    PinUnavailable,
    /// The client proof did not match the PIN, or a signature did not verify.
    AuthenticationFailed,
    /// The random source could not produce bytes.
    Random,
    /// The SRP exchange was refused.
    Srp(crate::srp::SrpError),
    /// A cryptographic primitive refused its input.
    Crypto(CryptoError),
}

impl PairingError {
    /// Status code the protocol answers a failed pairing step with.
    pub fn status(&self) -> u16 {
        470
    }

    /// Reason phrase that belongs to [`PairingError::status`].
    pub fn reason(&self) -> &'static str {
        "Client Authentication Failure"
    }
}

impl fmt::Display for PairingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPlist => formatter.write_str("the request body is not a binary property list"),
            Self::UnexpectedKeys => {
                formatter.write_str("the request carries no known pairing step")
            }
            Self::InvalidLength(what) => write!(formatter, "invalid length of {what}"),
            Self::OutOfOrder(step) => {
                write!(formatter, "{step} has not completed on this connection")
            }
            Self::PinUnavailable => formatter.write_str("no PIN is available for pairing"),
            Self::AuthenticationFailed => formatter.write_str("client authentication failed"),
            Self::Random => formatter.write_str("the random source failed"),
            Self::Srp(error) => write!(formatter, "SRP exchange refused: {error}"),
            Self::Crypto(error) => write!(formatter, "cryptographic primitive refused: {error}"),
        }
    }
}

impl std::error::Error for PairingError {}

/// What the control service answers a pairing request with.
pub(crate) enum PairingReply {
    /// Add nothing to the default `200 OK`: the answer the protocol gives when a
    /// step has nothing to say, for example when a client should fall back to
    /// the legacy setup (, `:447-450`,
    /// `:474-476`).
    Silence,
    /// Binary property list body.
    Plist(plist::Value),
    /// Opaque body with `Content-Type: application/octet-stream`.
    Octets(Vec<u8>),
    /// `200 OK` with nothing added, after which the connection is closed
    Disconnect,
}

/// What one connection established before it asked for a media session.
///
/// The levels are evidence, not permissions: even [`SessionAuth::Verified`] only
/// proves that the peer holds the keys it presented, so a caller that needs an
/// access decision asks its own registry (see
/// [`PairingState::with_client_registered`]) or the password gate of `SETUP`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAuth {
    /// The connection authenticated nothing.
    None,
    /// `/pair-setup` completed; that flow authenticates neither side
    LegacySetup,
    /// `/pair-setup-pin` step 3 installed a client key after the PIN proof.
    PinVerified,
    /// The client signed the key exchange, so `/pair-verify` finished here.
    Verified,
}

/// Key material of a connection that finished `/pair-verify`.
///
/// A media session derives its stream keys from these values, so they are only
/// produced for a connection that completed the exchange, and only once
/// Lifecycle of one connection's pairing exchange, the port of the status values
/// of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    /// Nothing is set up on this connection.
    Initial,
    /// A setup step completed, so `/pair-verify` may start here.
    Setup,
    /// The first `/pair-verify` step completed.
    Handshake,
    /// `/pair-verify` verified the client on this connection.
    Finished,
}

impl Status {
    /// Whether `/pair-verify` may start, the inverse of the protocol's
    /// `pairing_session_check_handshake_status`.
    fn allows_handshake(self) -> bool {
        matches!(self, Self::Setup | Self::Handshake)
    }
}

#[cfg(test)]
mod tests;
