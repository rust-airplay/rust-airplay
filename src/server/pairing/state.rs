// SPDX-License-Identifier: GPL-3.0-or-later
//! Receiver-wide pairing state: identity, PIN policy and password lockout.

use super::*;

/// Longest client user name the protocol accepts.
pub(crate) const MAX_USERNAME: usize = 24;

/// Largest SRP public value a client may send: one 2048-bit block.
pub(crate) const MAX_SRP_PUBLIC: usize = crate::srp::APPLE_SRP_MODULUS_SIZE;

/// Length of an AES-GCM authentication tag.
pub(crate) const GCM_TAG_SIZE: usize = 16;

/// Random attempts to draw a PIN before the source is called broken.
const MAX_PIN_ATTEMPTS: usize = 8;

/// SRP contexts one connection may open.
///
/// Every `/pair-setup-pin` step 1 computes a fresh server public value, so an
/// unauthenticated peer could otherwise spend a modular exponentiation per
/// request for as long as it holds a connection slot. The protocol has no such
/// bound; the port bounds the work per connection and relies on the connection
/// limit and the idle deadline for the rest. The value is one above
/// [`MAX_PIN_FAILURES`] so that the per-connection bound never hides the
/// receiver-wide one: the last attempt that can still be counted as a wrong
/// proof is always allowed to happen.
pub(crate) const MAX_SETUP_PIN_ATTEMPTS: usize = MAX_PIN_FAILURES as usize + 1;

/// Wrong proofs a receiver tolerates before it drops a one-time PIN.
///
/// The protocol counts nothing, so a fixed PIN can be guessed online until it is
/// found; this bound is a port decision, and it applies to the shared state so
/// that opening a new connection does not reset it.
pub const MAX_PIN_FAILURES: u32 = 5;

/// How long a PIN is refused after the failure bound is reached.
///
/// The protocol counts nothing, so a fixed PIN can be guessed online until it is found;
/// an unbounded guess is also what would let one unauthenticated peer spend the
/// receiver's modular exponentiations forever. A bounded window keeps guessing
/// expensive without making the receiver unusable until a restart.
pub const PIN_LOCKOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Refused PIN proofs, and the moment this receiver is willing to try one again.
#[derive(Debug, Default)]
struct PinFailures {
    count: u32,
    blocked_until: Option<std::time::Instant>,
}

/// Refused password digests a receiver tolerates before it stops answering
/// challenges.
///
/// The protocol keeps counting and, in its random-password mode, hands out a new
/// password once the count is reached;
/// a configured password cannot be rotated like that, so the port stops
/// accepting new attempts on a connection that keeps guessing.
pub const MAX_PASSWORD_FAILURES: u32 = 5;

/// How long password attempts are refused after the failure bound is reached.
///
/// A permanent lockout would let one unauthenticated client disable password-protected
/// `SETUP` for as long as the process runs, and a password cannot be rotated the way a
/// random one can. A bounded window keeps guessing expensive without handing that lever
/// to anyone on the network.
pub const PASSWORD_LOCKOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Refused digests, and the moment this receiver is willing to answer one again.
#[derive(Debug, Default)]
struct PasswordFailures {
    count: u32,
    blocked_until: Option<std::time::Instant>,
}

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
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinMode {
    /// Pairing with a PIN is refused.
    Disabled,
    /// A PIN `/pair-pin-start` generates, valid until one pairing succeeds.
    OneTime,
    /// A PIN the caller chose. Only the low four digits are used, which is how
    /// the protocol stores a configured PIN.
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
pub struct PairingState {
    pub(super) identity_seed: [u8; ED25519_KEY_SIZE],
    identity_public: [u8; ED25519_KEY_SIZE],
    pin_mode: PinMode,
    password: Option<Vec<u8>>,
    password_failures: Mutex<PasswordFailures>,
    password_lockout: std::time::Duration,
    pin_failures: Mutex<PinFailures>,
    pin_lockout: std::time::Duration,
    pending_pin: Mutex<Option<u16>>,
    random: Mutex<Box<dyn RandomSource>>,
    pub(super) client_registered: Option<ClientRegisteredCheck>,
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
            password_failures: Mutex::new(PasswordFailures::default()),
            password_lockout: PASSWORD_LOCKOUT,
            pin_failures: Mutex::new(PinFailures::default()),
            pin_lockout: PIN_LOCKOUT,
            pending_pin: Mutex::new(None),
            random: Mutex::new(random),
            client_registered: None,
        }
    }

    /// Sets the password a client has to authenticate with before `SETUP`.
    ///
    /// The protocol gets the same value from its `-pw` option and asks for it with
    /// an RFC 2617 digest challenge.
    /// A receiver without a password answers `SETUP` without a challenge, which
    /// is what an AirPlay 1 client expects when nothing is protected.
    pub fn with_password(mut self, password: impl Into<Vec<u8>>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Sets how long password attempts are refused after the failure bound.
    ///
    /// The default is 30 seconds. A test shortens it; a receiver on a hostile
    /// network may lengthen it, at the cost of a longer window in which a legitimate
    /// client cannot get in after an attack.
    pub fn with_password_lockout(mut self, window: std::time::Duration) -> Self {
        self.password_lockout = window;
        self
    }

    /// Sets how long PIN attempts are refused after the failure bound.
    ///
    /// The default is 30 seconds. It applies to a fixed PIN and to a one-time PIN, and a
    /// new one-time PIN does not clear it: otherwise asking for a fresh PIN would be a
    /// way to reset the guess counter.
    pub fn with_pin_lockout(mut self, window: std::time::Duration) -> Self {
        self.pin_lockout = window;
        self
    }

    /// Whether a password was configured.
    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }

    /// Failures a password may collect before this receiver stops answering
    /// challenges for new attempts.
    ///
    /// The protocol counts the same events; the bound and the shared counter are the
    /// port's own, so guessing a password costs attempts across all connections.
    pub fn password_failures(&self) -> u32 {
        self.guard(&self.password_failures).count
    }

    /// Checks an RFC 2617 digest against the configured password.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::PinUnavailable`] when no password is configured,
    /// and [`PairingError::AuthenticationFailed`] once the failure bound is
    /// reached, so a caller answers `401` in both cases. The bound is a lockout
    /// window rather than a permanent stop: when the window has passed, the next
    /// attempt is checked normally, so an attack cannot disable a password-protected
    /// receiver for the life of the process.
    pub(crate) fn verify_password_digest(
        &self,
        method: &str,
        authorization: &crate::pairing::DigestAuthorization,
    ) -> Result<(), PairingError> {
        let Some(password) = self.password.as_deref() else {
            return Err(PairingError::PinUnavailable);
        };
        let mut failures = self.guard(&self.password_failures);
        let now = std::time::Instant::now();
        if let Some(until) = failures.blocked_until {
            if now < until {
                return Err(PairingError::AuthenticationFailed);
            }
            failures.count = 0;
            failures.blocked_until = None;
        }
        if failures.count >= MAX_PASSWORD_FAILURES {
            failures.blocked_until = Some(now + self.password_lockout);
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
            failures.count = 0;
            failures.blocked_until = None;
            Ok(())
        } else {
            failures.count += 1;
            if failures.count >= MAX_PASSWORD_FAILURES {
                failures.blocked_until = Some(now + self.password_lockout);
            }
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
    /// `/pair-verify` on a connection with no setup of its own. ///
    /// The protocol asks its application the same question and treats a missing list
    /// as "registered", so a
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

    /// Draws a PIN in `1..=9999`, the range the protocol's `random_pin` produces
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
        // The protocol retries forever when its random source fails; a stated error
        // is the difference between a stuck handler and a bounded one.
        Err(PairingError::Random)
    }

    /// Whether a PIN attempt is allowed, clearing an expired lockout.
    fn pin_allowed(&self) -> Result<(), PairingError> {
        let mut failures = self.guard(&self.pin_failures);
        if let Some(until) = failures.blocked_until {
            if std::time::Instant::now() < until {
                return Err(PairingError::AuthenticationFailed);
            }
            failures.count = 0;
            failures.blocked_until = None;
        }
        Ok(())
    }

    /// PIN the next setup step has to be answered with.
    pub(super) fn pin_for_setup(&self) -> Result<[u8; 4], PairingError> {
        self.pin_allowed()?;
        match self.pin_mode {
            PinMode::Disabled => Err(PairingError::PinUnavailable),
            PinMode::Fixed(pin) => Ok(digits(pin)),
            PinMode::OneTime => match *self.guard(&self.pending_pin) {
                Some(pin) => Ok(digits(pin)),
                // The protocol would fall back to `"0000"` here; requiring a
                // generated PIN is what makes the exchange authenticate.
                None => Err(PairingError::PinUnavailable),
            },
        }
    }

    /// Starts a PIN exchange and returns the PIN a user has to enter.
    pub(super) fn start_pin(&self) -> Result<[u8; 4], PairingError> {
        self.pin_allowed()?;
        match self.pin_mode {
            PinMode::Disabled => Err(PairingError::PinUnavailable),
            PinMode::Fixed(pin) => Ok(digits(pin)),
            PinMode::OneTime => {
                let mut pending = self.guard(&self.pending_pin);
                let pin = match *pending {
                    // Keep the PIN a user is already looking at; the protocol
                    // regenerates it on every request.
                    Some(pin) => pin,
                    None => {
                        let pin = self.random_pin()?;
                        *pending = Some(pin);
                        pin
                    }
                };
                Ok(digits(pin))
            }
        }
    }

    /// Counts one refused proof, dropping a one-time PIN at the bound.
    pub(super) fn record_failure(&self) {
        let mut failures = self.guard(&self.pin_failures);
        failures.count += 1;
        if failures.count >= MAX_PIN_FAILURES {
            failures.blocked_until = Some(std::time::Instant::now() + self.pin_lockout);
            *self.guard(&self.pending_pin) = None;
        }
    }

    /// Clears the failure count and consumes a one-time PIN.
    pub(super) fn record_success(&self) {
        let mut failures = self.guard(&self.pin_failures);
        failures.count = 0;
        failures.blocked_until = None;
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
