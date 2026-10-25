// SPDX-License-Identifier: GPL-3.0-or-later
//! One connection's pairing exchange.

use super::*;

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

/// Pairing exchange of one connection, the protocol's `raop_conn_t::session`.
///
/// Temporary material — the SRP context, the session key of a verified proof,
/// the X25519 key pair and the key the client presented — belongs to the client
/// that opened the connection and is dropped with it.
pub(crate) struct PairingSession {
    shared: Arc<PairingState>,
    pub(super) status: Status,
    srp: Option<AppleSrpServer>,
    session_key: Option<[u8; APPLE_SESSION_KEY_SIZE]>,
    pub(super) client_public_key: Option<[u8; ED25519_KEY_SIZE]>,
    ecdh_public: Option<[u8; X25519_KEY_SIZE]>,
    ecdh_client_public: Option<[u8; X25519_KEY_SIZE]>,
    ecdh_shared: Option<[u8; X25519_KEY_SIZE]>,
    pub(super) registration_refused: bool,
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
    /// The protocol adds nothing to the reply;
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
    /// ( hands it out for any connection
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
    /// the protocol tests them.
    pub(crate) fn setup_pin(&mut self, body: &[u8]) -> Result<PairingReply, PairingError> {
        // The protocol parses with `plist_from_bin`, so an
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
        // The protocol compares with `strncmp(method, "pin", strlen(method))`, so any
        // prefix of "pin" is accepted and anything else falls through to the
        // default `200 OK` with no body.
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
        // server public value on its own.
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
        // The SRP context is spent either way: the protocol keeps its own until the
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
        // The session key only exists once step 2 verified the proof; the protocol
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
    /// The legacy flow carries no secret: the protocol ignores the content of the
    /// 32-byte body and answers with the receiver's public key
    ///, which is why the reply
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
                // back to `/pair-setup`.
                return Ok(PairingReply::Silence);
            }
            self.status = Status::Setup;
            register_check = true;
        } else if self.registration_refused {
            // The protocol stops checking the client as soon as the connection is in
            // its setup state (`:470-477`), so a client it just refused only has
            // to ask again. A refusal therefore stays for the rest of this
            // connection, which is what makes an injected registration list an
            // access control rather than a single-shot gate; a client that
            // authenticates with the PIN clears it below.
            register_check = true;
        }
        // A legacy `/pair-setup` proves nothing: it only asks for the receiver's public
        // key. A client that takes that path must still satisfy the registration check,
        // or the list would be advisory and a caller's access control would not exist.
        if self.status == Status::Setup && !self.pin_verified {
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
                // Without a predicate the protocol treats every client as registered
                //; a caller that needs the check
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
    /// and closes the connection, which is what the protocol asks its httpd to do
    ///; that reply carries no
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
