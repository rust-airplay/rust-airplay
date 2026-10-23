// SPDX-License-Identifier: GPL-3.0-or-later
//! Pairing state of a receiver and of one control connection.
//!
//! Upstream keeps the receiver-wide facts in `raop_t` — the PIN, whether a PIN
//! is in use, and the long-term Ed25519 identity of `pairing.c` — and the
//! exchange of one client in `raop_conn_t::session`, next to that connection's
//! FairPlay session (`upstream/UxPlay/lib/raop.c:145-151`, `:627-628`).
//! [`PairingState`] is the shared half and [`PairingSession`] the per-connection
//! half.
//!
//! # Documented differences from upstream
//!
//! Each of these is deliberate, and each has a test:
//!
//! * A `/pair-setup-pin` step 3 is refused unless step 2 verified the client
//!   proof. Upstream derives the step 3 keys from the SRP session key, which is
//!   still the all-zero buffer of a fresh context until the proof is checked
//!   (`upstream/UxPlay/lib/pairing.c:513`, `:587`, `:603`), so two requests
//!   without any PIN let a peer install its own key on the receiver.
//! * `/pair-setup-pin` without a usable PIN is refused. Upstream instead uses
//!   the implicit PIN `"0000"` whenever no PIN is configured
//!   (`upstream/UxPlay/lib/raop.c:627`, `raop_handlers.h:329-332`), which makes
//!   the SRP exchange authenticate nothing.
//! * A one-time PIN is consumed only when pairing succeeds, a repeated
//!   `/pair-pin-start` keeps the PIN that is already pending, and
//!   [`MAX_PIN_FAILURES`] wrong proofs drop it. Upstream clears the PIN on the
//!   first step and regenerates it on every request (`raop_handlers.h:258-267`,
//!   `:329-332`), so any peer can invalidate the PIN a user is reading and a
//!   fixed PIN can be guessed without limit. The cost of consuming late is that
//!   two peers who both know the PIN can each complete a pairing until the first
//!   one succeeds; the failure bound keeps that window small.
//! * A value whose length upstream does not check is validated before it is
//!   used (`raop_handlers.h:366`, `:408-409`), and the steps whose missing state
//!   upstream dereferences as a null pointer (`pairing.c:560`, `:603`) answer
//!   `470` instead.
//! * A `/pair-verify` step 1 that the injected registration predicate refuses
//!   stays refused for the rest of the connection, and only a `/pair-setup-pin`
//!   that proves the PIN lifts it. Upstream stops consulting the list once the
//!   connection is in its setup state (`raop_handlers.h:470-477`), so a client it
//!   has just turned away only has to ask a second time, which would make an
//!   injected list useless as access control.
//! * A key exchange key that yields an all-zero shared secret is refused. A
//!   low-order point would let the peer derive the keystream without holding a
//!   private key, and upstream's OpenSSL derive fails where the port has to
//!   check for itself (`crypto.c:245-265`).
//! * One connection starts one `/pair-verify` key exchange, and one connection
//!   opens at most [`MAX_SETUP_PIN_ATTEMPTS`] SRP contexts. Upstream accepts a
//!   repeat of either (`pairing.c:162-180` only refuses a finished session, and
//!   nothing bounds the modular exponentiation of a setup step), but a repeat
//!   either replaces the keys the connection already agreed on or spends work
//!   for an unauthenticated peer.

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

/// Longest client user name upstream accepts (`upstream/UxPlay/lib/pairing.h:24`).
const MAX_USERNAME: usize = 24;

/// Largest SRP public value a client may send: one 2048-bit block.
const MAX_SRP_PUBLIC: usize = crate::srp::APPLE_SRP_MODULUS_SIZE;

/// Length of an AES-GCM authentication tag.
const GCM_TAG_SIZE: usize = 16;

/// Random attempts to draw a PIN before the source is called broken.
const MAX_PIN_ATTEMPTS: usize = 8;

/// SRP contexts one connection may open.
///
/// Every `/pair-setup-pin` step 1 computes a fresh server public value, so an
/// unauthenticated peer could otherwise spend a modular exponentiation per
/// request for as long as it holds a connection slot. Upstream has no such
/// bound; the port bounds the work per connection and relies on the connection
/// limit and the idle deadline for the rest. The value is one above
/// [`MAX_PIN_FAILURES`] so that the per-connection bound never hides the
/// receiver-wide one: the last attempt that can still be counted as a wrong
/// proof is always allowed to happen.
const MAX_SETUP_PIN_ATTEMPTS: usize = MAX_PIN_FAILURES as usize + 1;

/// Wrong proofs a receiver tolerates before it drops a one-time PIN.
///
/// Upstream counts nothing, so a fixed PIN can be guessed online until it is
/// found; this bound is a port decision, and it applies to the shared state so
/// that opening a new connection does not reset it.
pub const MAX_PIN_FAILURES: u32 = 5;

/// Refused password digests a receiver tolerates before it stops answering
/// challenges.
///
/// Upstream keeps counting and, in its random-password mode, hands out a new
/// password once the count is reached (`upstream/UxPlay@3dbf7cee:lib/raop_handlers.h:664-669`);
/// a configured password cannot be rotated like that, so the port stops
/// accepting new attempts on a connection that keeps guessing.
pub const MAX_PASSWORD_FAILURES: u32 = 5;

/// Secret bytes a pairing exchange needs.
///
/// Every use of randomness in pairing goes through this trait — the one-time
/// PIN, the SRP salt, the SRP private value and the X25519 ephemeral key — so a
/// test can drive the protocol deterministically. An implementation must be a
/// cryptographically secure generator.
pub trait RandomSource: Send {
    /// Fills `output` completely, or reports that it cannot.
    ///
    /// # Errors
    ///
    /// Returns [`RandomError`] when no secure bytes could be produced.
    fn fill(&mut self, output: &mut [u8]) -> Result<(), RandomError>;
}

/// Why no random bytes could be produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomError;

impl fmt::Display for RandomError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the random source failed")
    }
}

impl std::error::Error for RandomError {}

/// Random source backed by the operating system.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), RandomError> {
        getrandom::getrandom(output).map_err(|_| RandomError)
    }
}

/// How a receiver treats the PIN of the modern pairing flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinMode {
    /// Pairing with a PIN is refused.
    Disabled,
    /// A PIN `/pair-pin-start` generates, valid until one pairing succeeds.
    OneTime,
    /// A PIN the caller chose. Only the low four digits are used, which is how
    /// upstream stores a configured PIN (`upstream/UxPlay/lib/uxplay.cpp:1654`).
    Fixed(u16),
}

/// Predicate that decides whether a client may start `/pair-verify` without a
/// setup of its own, answering for the client's public key.
pub type ClientRegisteredCheck = Box<dyn Fn(&[u8; ED25519_KEY_SIZE]) -> bool + Send + Sync>;

/// Receiver-wide pairing state, shared by the handlers of every connection.
///
/// A caller creates one value, shares it with the handler factory and keeps it
/// for the lifetime of the receiver: the long-term identity is what a client
/// caches, so a receiver that changes it has to be paired again
/// (`upstream/UxPlay/lib/raop.c:659-674`).
pub struct PairingState {
    identity_seed: [u8; ED25519_KEY_SIZE],
    identity_public: [u8; ED25519_KEY_SIZE],
    pin_mode: PinMode,
    password: Option<Vec<u8>>,
    password_failures: Mutex<u32>,
    pending_pin: Mutex<Option<u16>>,
    failures: Mutex<u32>,
    random: Mutex<Box<dyn RandomSource>>,
    client_registered: Option<ClientRegisteredCheck>,
}

impl PairingState {
    /// Creates receiver state for `identity_seed` with the given PIN policy,
    /// using the operating system as the random source.
    pub fn new(identity_seed: [u8; ED25519_KEY_SIZE], pin_mode: PinMode) -> Self {
        Self::with_random(identity_seed, pin_mode, Box::new(OsRandom))
    }

    /// Creates receiver state with an explicit random source.
    pub fn with_random(
        identity_seed: [u8; ED25519_KEY_SIZE],
        pin_mode: PinMode,
        random: Box<dyn RandomSource>,
    ) -> Self {
        Self {
            identity_seed,
            identity_public: ed25519_public_key(&identity_seed),
            pin_mode,
            password: None,
            password_failures: Mutex::new(0),
            pending_pin: Mutex::new(None),
            failures: Mutex::new(0),
            random: Mutex::new(random),
            client_registered: None,
        }
    }

    /// Sets the password a client has to authenticate with before `SETUP`.
    ///
    /// Upstream gets the same value from its `-pw` option and asks for it with
    /// an RFC 2617 digest challenge (`upstream/UxPlay@3dbf7cee:lib/raop_handlers.h:649-748`).
    /// A receiver without a password answers `SETUP` without a challenge, which
    /// is what an AirPlay 1 client expects when nothing is protected.
    pub fn with_password(mut self, password: impl Into<Vec<u8>>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Whether a password was configured.
    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }

    /// Failures a password may collect before this receiver stops answering
    /// challenges for new attempts.
    ///
    /// Upstream counts the same events; the bound and the shared counter are the
    /// port's own, so guessing a password costs attempts across all connections.
    pub fn password_failures(&self) -> u32 {
        *self.guard(&self.password_failures)
    }

    /// Counts one refused password.
    pub(crate) fn record_password_failure(&self) {
        *self.guard(&self.password_failures) += 1;
    }

    /// Checks an RFC 2617 digest against the configured password.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::PinUnavailable`] when no password is configured,
    /// and [`PairingError::AuthenticationFailed`] once the failure bound is
    /// reached, so a caller answers `401` in both cases.
    pub(crate) fn verify_password_digest(
        &self,
        method: &str,
        authorization: &crate::pairing::DigestAuthorization,
    ) -> Result<(), PairingError> {
        let Some(password) = self.password.as_deref() else {
            return Err(PairingError::PinUnavailable);
        };
        if self.password_failures() >= MAX_PASSWORD_FAILURES {
            return Err(PairingError::AuthenticationFailed);
        }
        let password = String::from_utf8_lossy(password);
        let expected = crate::pairing::digest_auth_response(
            method,
            &authorization.username,
            &authorization.realm,
            &password,
            &authorization.nonce,
            &authorization.uri,
            authorization.qop.as_deref(),
            authorization.nonce_count.as_deref(),
            authorization.client_nonce.as_deref(),
        );
        if crate::pairing::constant_time_eq(expected.as_bytes(), authorization.response.as_bytes())
        {
            *self.guard(&self.password_failures) = 0;
            Ok(())
        } else {
            self.record_password_failure();
            Err(PairingError::AuthenticationFailed)
        }
    }

    /// Fills `output` from the random source, for a caller that needs bytes this
    /// state owns instead of its own source.
    pub(crate) fn fill_random(&self, output: &mut [u8]) -> Result<(), PairingError> {
        self.guard(&self.random)
            .fill(output)
            .map_err(|_| PairingError::Random)
    }

    /// Adds the predicate that decides whether a client may start
    /// `/pair-verify` on a connection with no setup of its own.    ///
    /// Upstream asks its application the same question and treats a missing list
    /// as "registered" (`upstream/UxPlay/lib/raop_handlers.h:504-516`), so a
    /// receiver without a predicate accepts every client; injecting one is how a
    /// caller opts into an access-control list. The predicate answers for one
    /// client public key and must not block.
    pub fn with_client_registered(
        mut self,
        check: impl Fn(&[u8; ED25519_KEY_SIZE]) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.client_registered = Some(Box::new(check));
        self
    }

    /// Public key of the receiver's long-term pairing identity.
    ///
    /// This is the `pk` of `/info` and the key every client authenticates the
    /// receiver with, so a caller has to keep it stable across restarts.
    pub fn identity_public(&self) -> [u8; ED25519_KEY_SIZE] {
        self.identity_public
    }

    /// PIN policy of this receiver.
    pub fn pin_mode(&self) -> PinMode {
        self.pin_mode
    }

    /// PIN a user is expected to enter, as four decimal digits.
    ///
    /// A caller shows this to the user after `/pair-pin-start`; it is `None`
    /// while pairing is disabled and while a one-time PIN has not been generated
    /// yet or has been consumed.
    pub fn pending_pin(&self) -> Option<String> {
        let pin = match self.pin_mode {
            PinMode::Disabled => None,
            PinMode::Fixed(pin) => Some(pin % 10_000),
            PinMode::OneTime => *self.guard(&self.pending_pin),
        };
        pin.map(display_pin)
    }

    /// Locks `mutex`, recovering from a poisoned lock.
    ///
    /// A panic in a handler must not turn every later request into a panic, and
    /// none of the values here can be left inconsistent: they are single
    /// integers and options.
    fn guard<'a, T>(&self, mutex: &'a Mutex<T>) -> MutexGuard<'a, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Draws a PIN in `1..=9999`, the range upstream's `random_pin` produces
    /// (`upstream/UxPlay/lib/pairing.c:484-498`).
    fn random_pin(&self) -> Result<u16, PairingError> {
        let mut random = self.guard(&self.random);
        for _ in 0..MAX_PIN_ATTEMPTS {
            let mut bytes = [0u8; 2];
            random.fill(&mut bytes).map_err(|_| PairingError::Random)?;
            let pin = u16::from_be_bytes(bytes) % 10_000;
            if pin != 0 {
                return Ok(pin);
            }
        }
        // Upstream retries forever when its random source fails; a stated error
        // is the difference between a stuck handler and a bounded one.
        Err(PairingError::Random)
    }

    /// PIN the next setup step has to be answered with.
    fn pin_for_setup(&self) -> Result<[u8; 4], PairingError> {
        match self.pin_mode {
            PinMode::Disabled => Err(PairingError::PinUnavailable),
            PinMode::Fixed(pin) => Ok(digits(pin)),
            PinMode::OneTime => match *self.guard(&self.pending_pin) {
                Some(pin) => Ok(digits(pin)),
                // Upstream would fall back to `"0000"` here; requiring a
                // generated PIN is what makes the exchange authenticate.
                None => Err(PairingError::PinUnavailable),
            },
        }
    }

    /// Starts a PIN exchange and returns the PIN a user has to enter.
    fn start_pin(&self) -> Result<[u8; 4], PairingError> {
        match self.pin_mode {
            PinMode::Disabled => Err(PairingError::PinUnavailable),
            PinMode::Fixed(pin) => Ok(digits(pin)),
            PinMode::OneTime => {
                let mut pending = self.guard(&self.pending_pin);
                let pin = match *pending {
                    // Keep the PIN a user is already looking at; upstream
                    // regenerates it on every request.
                    Some(pin) => pin,
                    None => {
                        let pin = self.random_pin()?;
                        *pending = Some(pin);
                        *self.guard(&self.failures) = 0;
                        pin
                    }
                };
                Ok(digits(pin))
            }
        }
    }

    /// Counts one refused proof, dropping a one-time PIN at the bound.
    fn record_failure(&self) {
        let mut failures = self.guard(&self.failures);
        *failures += 1;
        if *failures >= MAX_PIN_FAILURES {
            *self.guard(&self.pending_pin) = None;
        }
    }

    /// Clears the failure count and consumes a one-time PIN.
    fn record_success(&self) {
        *self.guard(&self.failures) = 0;
        *self.guard(&self.pending_pin) = None;
    }
}

impl fmt::Debug for PairingState {
    /// Describes the receiver without printing its private seed.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingState")
            .field("identity_public", &hex(&self.identity_public))
            .field("pin_mode", &self.pin_mode)
            .finish_non_exhaustive()
    }
}

impl Drop for PairingState {
    /// Overwrites the identity seed when the receiver goes away.
    ///
    /// Best effort by design: it clears the copy this value owns, not whatever a
    /// crashing dump or a swapped-out page may still hold.
    fn drop(&mut self) {
        self.identity_seed.fill(0);
    }
}

/// Four zero-padded decimal digits, `snprintf("%04u")` of the C code.
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
/// Failure` and no body, the status upstream uses for a failed pairing step
/// (`upstream/UxPlay/lib/raop_handlers.h:431-432`). No variant carries key
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
    /// Status code upstream answers a failed pairing step with.
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
    /// Add nothing to the default `200 OK`: the answer upstream gives when a
    /// step has nothing to say, for example when a client should fall back to
    /// the legacy setup (`upstream/UxPlay/lib/raop_handlers.h:319-324`, `:447-450`,
    /// `:474-476`).
    Silence,
    /// Binary property list body.
    Plist(plist::Value),
    /// Opaque body with `Content-Type: application/octet-stream`.
    Octets(Vec<u8>),
    /// `200 OK` with nothing added, after which the connection is closed
    /// (`upstream/UxPlay/lib/raop_handlers.h:533-537`).
    Disconnect,
}

/// What one connection established before it asked for a media session.
///
/// The levels are evidence, not permissions: even [`SessionAuth::Verified`] only
/// proves that the peer holds the keys it presented, so a caller that needs an
/// access decision asks its own registry (see
/// [`PairingState::with_client_registered`]) or the password gate of `SETUP`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAuth {
    /// The connection authenticated nothing.
    None,
    /// `/pair-setup` completed; that flow authenticates neither side
    /// (`upstream/UxPlay/lib/raop_handlers.h:440-460`).
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
/// ([`PairingSession::take_session_keys`]).
pub(crate) struct SessionKeys {
    /// X25519 shared secret of the connection's key exchange.
    pub(crate) ecdh_secret: [u8; X25519_KEY_SIZE],
    /// Public key the client presented in the verified exchange.
    ///
    /// It is *claimed* rather than proven: the signature only shows that the
    /// peer holds the matching private key. Whether that client may be served is
    /// the caller's registration decision.
    pub(crate) client_identity: Option<[u8; ED25519_KEY_SIZE]>,
}

/// Lifecycle of one connection's pairing exchange, the port of the status values
/// of `upstream/UxPlay/lib/pairing.c:148-159`.
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
    /// Whether `/pair-verify` may start, the inverse of upstream's
    /// `pairing_session_check_handshake_status`.
    fn allows_handshake(self) -> bool {
        matches!(self, Self::Setup | Self::Handshake)
    }
}

/// Pairing exchange of one connection, upstream's `raop_conn_t::session`.
///
/// Temporary material — the SRP context, the session key of a verified proof,
/// the X25519 key pair and the key the client presented — belongs to the client
/// that opened the connection and is dropped with it.
pub(crate) struct PairingSession {
    shared: Arc<PairingState>,
    status: Status,
    srp: Option<AppleSrpServer>,
    session_key: Option<[u8; APPLE_SESSION_KEY_SIZE]>,
    client_public_key: Option<[u8; ED25519_KEY_SIZE]>,
    ecdh_public: Option<[u8; X25519_KEY_SIZE]>,
    ecdh_client_public: Option<[u8; X25519_KEY_SIZE]>,
    ecdh_shared: Option<[u8; X25519_KEY_SIZE]>,
    registration_refused: bool,
    setup_pin_attempts: usize,
    pin_verified: bool,
}

impl PairingSession {
    /// Starts a session on the shared receiver state.
    pub(crate) fn new(shared: Arc<PairingState>) -> Self {
        Self {
            shared,
            status: Status::Initial,
            srp: None,
            session_key: None,
            client_public_key: None,
            ecdh_public: None,
            ecdh_client_public: None,
            ecdh_shared: None,
            registration_refused: false,
            setup_pin_attempts: 0,
            pin_verified: false,
        }
    }

    /// `/pair-pin-start`: `raop_handler_pairpinstart`.
    ///
    /// Upstream adds nothing to the reply (`upstream/UxPlay/lib/raop_handlers.h:270-273`);
    /// the PIN reaches the user through [`PairingState::pending_pin`], which
    /// keeps the display out of the handler and out of any held lock.
    pub(crate) fn pin_start(&mut self) -> Result<PairingReply, PairingError> {
        self.shared.start_pin()?;
        Ok(PairingReply::Silence)
    }

    /// The receiver-wide state this connection pairs against.
    pub(crate) fn shared(&self) -> &Arc<PairingState> {
        &self.shared
    }

    /// What this connection established, for a caller that has to branch on it.
    pub(crate) fn authentication(&self) -> SessionAuth {
        if self.status == Status::Finished {
            return SessionAuth::Verified;
        }
        if self.pin_verified {
            return SessionAuth::PinVerified;
        }
        if matches!(self.status, Status::Setup | Status::Handshake) {
            return SessionAuth::LegacySetup;
        }
        SessionAuth::None
    }

    /// Takes the key material of a connection that finished `/pair-verify`.
    ///
    /// The material is handed out at most once, and only after the second
    /// `/pair-verify` step verified the client's signature
    /// (`upstream/UxPlay/lib/pairing.c:108-119` hands it out for any connection
    /// that started a handshake, which this crate deliberately narrows). A caller
    /// that gets `None` has no verified session on this connection and must not
    /// derive stream keys.
    pub(crate) fn take_session_keys(&mut self) -> Option<SessionKeys> {
        if self.status != Status::Finished {
            return None;
        }
        let ecdh_secret = self.ecdh_shared.take()?;
        Some(SessionKeys {
            ecdh_secret,
            client_identity: self.client_public_key,
        })
    }

    /// `/pair-setup-pin`: `raop_handler_pairsetup_pin`.
    ///
    /// The three steps are told apart by the keys they carry, in the order
    /// upstream tests them (`upstream/UxPlay/lib/raop_handlers.h:310-430`).
    pub(crate) fn setup_pin(&mut self, body: &[u8]) -> Result<PairingReply, PairingError> {
        // Upstream parses with `plist_from_bin` (`raop_handlers.h:302`), so an
        // XML property list is refused even though the plist layer could read it.
        if !body.starts_with(b"bplist00") {
            return Err(PairingError::NotPlist);
        }
        let request = Plist::parse(body).map_err(|_| PairingError::NotPlist)?;
        let method = request.get("method").and_then(plist::Value::as_string);
        let user = request.get("user").and_then(plist::Value::as_string);
        if let (Some(method), Some(user)) = (method, user) {
            return self.setup_pin_one(method, user);
        }
        let public_key = request.get("pk").and_then(plist::Value::as_data);
        let proof = request.get("proof").and_then(plist::Value::as_data);
        if let (Some(public_key), Some(proof)) = (public_key, proof) {
            return self.setup_pin_two(public_key, proof);
        }
        let epk = request.get("epk").and_then(plist::Value::as_data);
        let auth_tag = request.get("authTag").and_then(plist::Value::as_data);
        if let (Some(epk), Some(auth_tag)) = (epk, auth_tag) {
            return self.setup_pin_three(epk, auth_tag);
        }
        Err(PairingError::UnexpectedKeys)
    }

    /// First step: try a PIN, answer with the SRP public value and salt.
    fn setup_pin_one(&mut self, method: &str, user: &str) -> Result<PairingReply, PairingError> {
        // Upstream compares with `strncmp(method, "pin", strlen(method))`, so any
        // prefix of "pin" is accepted and anything else falls through to the
        // default `200 OK` with no body (`raop_handlers.h:319-324`).
        if !"pin".starts_with(method) {
            return Ok(PairingReply::Silence);
        }
        let user = user.as_bytes();
        if user.is_empty() || user.len() > MAX_USERNAME {
            return Err(PairingError::InvalidLength("pairing user name"));
        }
        if self.setup_pin_attempts >= MAX_SETUP_PIN_ATTEMPTS {
            // Each attempt costs this receiver a modular exponentiation, and
            // nothing in the request is authenticated yet.
            return Err(PairingError::AuthenticationFailed);
        }
        self.setup_pin_attempts += 1;
        let pin = self.shared.pin_for_setup()?;
        let mut salt = [0u8; APPLE_SRP_SALT_SIZE];
        self.shared.fill_random(&mut salt)?;
        let mut private_b = [0u8; 32];
        self.shared.fill_random(&mut private_b)?;
        let server =
            AppleSrpServer::new(user, &pin, &salt, &private_b).map_err(PairingError::Srp)?;
        // The client's public value is not known yet, so the answer needs the
        // server public value on its own (`pairing.c:543-550`).
        let public = server.server_public().map_err(PairingError::Srp)?;
        self.srp = Some(server);
        self.session_key = None;
        self.client_public_key = None;
        Ok(PairingReply::Plist(plist::dictionary([
            ("pk", plist::Value::Data(public)),
            ("salt", plist::Value::Data(salt.to_vec())),
        ])))
    }

    /// Second step: check the client proof and answer with the server proof.
    fn setup_pin_two(
        &mut self,
        public_key: &[u8],
        proof: &[u8],
    ) -> Result<PairingReply, PairingError> {
        let Some(server) = self.srp.as_ref() else {
            return Err(PairingError::OutOfOrder("pair-setup-pin step 1"));
        };
        if public_key.is_empty() || public_key.len() > MAX_SRP_PUBLIC {
            return Err(PairingError::InvalidLength("SRP client public key"));
        }
        if proof.len() != APPLE_SRP_HASH_SIZE {
            return Err(PairingError::InvalidLength("SRP client proof"));
        }
        let response = match server.respond(public_key) {
            Ok(response) => response,
            Err(error) => {
                self.srp = None;
                self.shared.record_failure();
                return Err(PairingError::Srp(error));
            }
        };
        // The SRP context is spent either way: upstream keeps its own until the
        // next step and then frees it, so a retry of this step crashes it.
        self.srp = None;
        if !constant_time_proof_eq(&response.expected_proof, proof) {
            self.shared.record_failure();
            return Err(PairingError::AuthenticationFailed);
        }
        self.session_key = Some(response.session_key);
        Ok(PairingReply::Plist(plist::dictionary([(
            "proof",
            plist::Value::Data(response.server_proof.to_vec()),
        )])))
    }

    /// Third step: exchange the long-term public keys.
    fn setup_pin_three(
        &mut self,
        epk: &[u8],
        auth_tag: &[u8],
    ) -> Result<PairingReply, PairingError> {
        // The session key only exists once step 2 verified the proof; upstream
        // derives the keys below from the zero-filled key of an unverified
        // context, which lets a peer skip this check entirely.
        let Some(session_key) = self.session_key else {
            return Err(PairingError::OutOfOrder("pair-setup-pin step 2"));
        };
        if epk.len() != ED25519_KEY_SIZE {
            return Err(PairingError::InvalidLength("pairing key exchange key"));
        }
        if auth_tag.len() != GCM_TAG_SIZE {
            return Err(PairingError::InvalidLength("pairing authentication tag"));
        }
        let keys = derive_pair_setup_keys(&session_key);
        let (decrypt_iv, encrypt_iv) = pair_setup_gcm_nonces(&session_key);
        let client_public =
            match crypto::aes128_gcm16_decrypt(&keys.key, &decrypt_iv, epk, auth_tag) {
                Ok(plaintext) if plaintext.len() == ED25519_KEY_SIZE => plaintext,
                Ok(_) => return Err(PairingError::InvalidLength("pairing key exchange key")),
                Err(error) => {
                    // The session key is spent; another attempt starts over.
                    self.session_key = None;
                    return Err(PairingError::Crypto(error));
                }
            };
        let identity = self.shared.identity_public();
        let (sealed, tag) = crypto::aes128_gcm16_encrypt(&keys.key, &encrypt_iv, &identity)
            .map_err(PairingError::Crypto)?;
        self.client_public_key = client_public.try_into().ok();
        self.session_key = None;
        self.status = Status::Setup;
        // The client proved the PIN, which is the strongest evidence this
        // connection can carry until `/pair-verify` finishes.
        self.pin_verified = true;
        // A client that just proved it knows the PIN is no longer a refused one,
        // which is what keeps a legitimate pairing able to verify afterwards.
        self.registration_refused = false;
        self.shared.record_success();
        Ok(PairingReply::Plist(plist::dictionary([
            ("epk", plist::Value::Data(sealed)),
            ("authTag", plist::Value::Data(tag.to_vec())),
        ])))
    }

    /// `/pair-setup`: `raop_handler_pairsetup`.
    ///
    /// The legacy flow carries no secret: upstream ignores the content of the
    /// 32-byte body and answers with the receiver's public key
    /// (`upstream/UxPlay/lib/raop_handlers.h:440-460`), which is why the reply
    /// must not be treated as authentication anywhere.
    pub(crate) fn setup(&mut self, body: &[u8]) -> Result<PairingReply, PairingError> {
        if body.len() != ED25519_KEY_SIZE {
            return Ok(PairingReply::Silence);
        }
        self.status = Status::Setup;
        Ok(PairingReply::Octets(self.shared.identity_public().to_vec()))
    }

    /// `/pair-verify`: `raop_handler_pairverify`.
    pub(crate) fn verify(&mut self, body: &[u8]) -> Result<PairingReply, PairingError> {
        let mut register_check = false;
        if !self.status.allows_handshake() {
            if self.shared.pin_mode() == PinMode::Disabled {
                // The default reply without a body is the client's cue to fall
                // back to `/pair-setup` (`raop_handlers.h:474-476`).
                return Ok(PairingReply::Silence);
            }
            self.status = Status::Setup;
            register_check = true;
        } else if self.registration_refused {
            // Upstream stops checking the client as soon as the connection is in
            // its setup state (`:470-477`), so a client it just refused only has
            // to ask again. A refusal therefore stays for the rest of this
            // connection, which is what makes an injected registration list an
            // access control rather than a single-shot gate; a client that
            // authenticates with the PIN clears it below.
            register_check = true;
        }
        if body.len() < 4 {
            return Ok(PairingReply::Silence);
        }
        match body[0] {
            1 => {
                if self.status != Status::Setup {
                    // One key exchange per connection: a second one would quietly
                    // replace the keys the first one agreed on, which is what the
                    // connection's session material is derived from.
                    return Ok(PairingReply::Silence);
                }
                self.verify_handshake(body, register_check)
            }
            0 => self.verify_finish(body),
            _ => Ok(PairingReply::Silence),
        }
    }

    /// First `/pair-verify` step: start the key exchange and sign our key.
    fn verify_handshake(
        &mut self,
        body: &[u8],
        register_check: bool,
    ) -> Result<PairingReply, PairingError> {
        if body.len() != 4 + X25519_KEY_SIZE + ED25519_KEY_SIZE {
            return Ok(PairingReply::Silence);
        }
        let client_ecdh = array::<X25519_KEY_SIZE>(&body[4..36], "pair-verify key exchange key")?;
        let client_identity = array::<ED25519_KEY_SIZE>(&body[36..68], "pair-verify client key")?;
        if register_check {
            if let Some(check) = self.shared.client_registered.as_ref() {
                // Without a predicate upstream treats every client as registered
                // (`raop_handlers.h:504-516`); a caller that needs the check
                // injects one.
                if !check(&client_identity) {
                    self.registration_refused = true;
                    return Ok(PairingReply::Silence);
                }
            }
        }
        let mut private = [0u8; X25519_KEY_SIZE];
        self.shared.fill_random(&mut private)?;
        let public = x25519_public(&private);
        let shared = x25519_shared(&private, &client_ecdh);
        if shared.iter().all(|byte| *byte == 0) {
            // A low-order public key yields a zero secret, which would let the
            // peer derive the keystream without holding a private key.
            return Err(PairingError::AuthenticationFailed);
        }
        let signature = encrypt_pair_verify_signature(
            &self.shared.identity_seed,
            &public,
            &client_ecdh,
            &shared,
        )
        .map_err(PairingError::Crypto)?;
        self.ecdh_public = Some(public);
        self.ecdh_client_public = Some(client_ecdh);
        self.ecdh_shared = Some(shared);
        self.client_public_key = Some(client_identity);
        self.status = Status::Handshake;
        let mut reply = public.to_vec();
        reply.extend_from_slice(&signature);
        Ok(PairingReply::Octets(reply))
    }

    /// Second `/pair-verify` step: verify the client's signature.
    ///
    /// A signature that does not verify is answered with the default `200 OK`
    /// and closes the connection, which is what upstream asks its httpd to do
    /// (`upstream/UxPlay/lib/raop_handlers.h:533-537`); that reply carries no
    /// content type, unlike the successful one below it.
    fn verify_finish(&mut self, body: &[u8]) -> Result<PairingReply, PairingError> {
        if body.len() != 4 + PAIRING_SIG_SIZE {
            return Ok(PairingReply::Silence);
        }
        let (Some(shared), Some(our_ecdh), Some(client_ecdh), Some(client_identity)) = (
            self.ecdh_shared,
            self.ecdh_public,
            self.ecdh_client_public,
            self.client_public_key,
        ) else {
            return Ok(PairingReply::Disconnect);
        };
        if self.status != Status::Handshake {
            return Ok(PairingReply::Disconnect);
        }
        let encrypted = array::<PAIRING_SIG_SIZE>(&body[4..], "pair-verify signature")?;
        let Ok(signature) = decrypt_pair_verify_signature(&encrypted, &shared) else {
            return Ok(PairingReply::Disconnect);
        };
        if !verify_pair_signature(&signature, &client_ecdh, &our_ecdh, &client_identity) {
            return Ok(PairingReply::Disconnect);
        }
        self.status = Status::Finished;
        Ok(PairingReply::Octets(Vec::new()))
    }
}

impl fmt::Debug for PairingSession {
    /// Describes the exchange without printing key material.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingSession")
            .field("status", &self.status)
            .field("srp", &self.srp.is_some())
            .field("session_key", &self.session_key.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for PairingSession {
    /// Overwrites the secrets this connection agreed on.
    ///
    /// The same best-effort caveat as [`PairingState`] applies; the point is that
    /// a closed connection does not leave its session key or shared secret in a
    /// buffer that a later connection could reuse.
    fn drop(&mut self) {
        if let Some(key) = self.session_key.as_mut() {
            key.fill(0);
        }
        if let Some(secret) = self.ecdh_shared.as_mut() {
            secret.fill(0);
        }
    }
}

/// Fixed-size array from a slice of external input.
fn array<const N: usize>(slice: &[u8], what: &'static str) -> Result<[u8; N], PairingError> {
    slice
        .try_into()
        .map_err(|_| PairingError::InvalidLength(what))
}

#[cfg(test)]
mod tests;
