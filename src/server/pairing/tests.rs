// SPDX-License-Identifier: GPL-3.0-or-later
//! Tests for the pairing service.
use super::*;
use crate::crypto::{Aes128CtrState, ed25519_sign, ed25519_verify};
use crate::pairing::derive_pair_verify_keys;
use crate::srp::test_client;

/// Identity seed of the receiver under test.
const IDENTITY_SEED: [u8; 32] = [0x5a; 32];

/// Deterministic random source: it repeats a fixed byte sequence, so every
/// value a test sees is reproducible.
struct FixedRandom {
    next: u8,
}

impl FixedRandom {
    fn new() -> Self {
        Self { next: 1 }
    }
}

impl RandomSource for FixedRandom {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), RandomError> {
        for byte in output.iter_mut() {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
        Ok(())
    }
}

fn state(pin_mode: PinMode) -> Arc<PairingState> {
    Arc::new(PairingState::with_random(
        IDENTITY_SEED,
        pin_mode,
        Box::new(FixedRandom::new()),
    ))
}

/// Body of one `/pair-setup-pin` step as a binary property list.
fn request(entries: Vec<(&str, plist::Value)>) -> Vec<u8> {
    Plist::from_value(plist::dictionary(entries))
        .encode_binary()
        .expect("encode")
}

fn body_of(reply: &PairingReply) -> &[u8] {
    match reply {
        PairingReply::Octets(body) => body,
        _ => panic!("expected an opaque body"),
    }
}

fn plist_of(reply: &PairingReply) -> Plist {
    match reply {
        PairingReply::Plist(value) => Plist::from_value(value.clone()),
        _ => panic!("expected a property list"),
    }
}

fn field(plist: &Plist, key: &'static str) -> Vec<u8> {
    plist.get_data(key).expect("data field").to_vec()
}

/// Body of the first `/pair-setup-pin` step for `username`.
fn step_one_request(username: &[u8]) -> Vec<u8> {
    request(vec![
        ("method", plist::Value::from("pin")),
        (
            "user",
            plist::Value::from(String::from_utf8_lossy(username).into_owned()),
        ),
    ])
}

/// Runs steps 1 and 2 of `/pair-setup-pin` and returns the client exchange.
fn setup_pin_two_steps(
    session: &mut PairingSession,
    pin: &[u8],
    username: &[u8],
) -> (test_client::Exchange, [u8; 16]) {
    let first = session
        .setup_pin(&request(vec![
            ("method", plist::Value::from("pin")),
            (
                "user",
                plist::Value::from(String::from_utf8_lossy(username).into_owned()),
            ),
        ]))
        .expect("step 1");
    let reply = plist_of(&first);
    let salt: [u8; 16] = field(&reply, "salt").try_into().expect("salt");
    let server_public = field(&reply, "pk");
    let exchange = test_client::exchange(username, pin, &salt, &[0x07; 32], &server_public);
    let second = session
        .setup_pin(&request(vec![
            ("pk", plist::Value::Data(exchange.public_key.clone())),
            ("proof", plist::Value::Data(exchange.proof.to_vec())),
        ]))
        .expect("step 2");
    assert_eq!(
        field(&plist_of(&second), "proof"),
        exchange.server_proof.to_vec()
    );
    (exchange, salt)
}

/// Seals `plaintext` the way a client seals its key exchange key in step 3.
fn seal_step_three(
    session_key: &[u8; APPLE_SESSION_KEY_SIZE],
    plaintext: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let keys = derive_pair_setup_keys(session_key);
    let (decrypt_iv, _) = pair_setup_gcm_nonces(session_key);
    let (sealed, tag) =
        crypto::aes128_gcm16_encrypt(&keys.key, &decrypt_iv, plaintext).expect("seal");
    (sealed, tag.to_vec())
}

fn step_three_request(epk: Vec<u8>, auth_tag: Vec<u8>) -> Vec<u8> {
    request(vec![
        ("epk", plist::Value::Data(epk)),
        ("authTag", plist::Value::Data(auth_tag)),
    ])
}

#[test]
fn pin_start_reports_the_pin_a_user_has_to_enter() {
    let shared = state(PinMode::OneTime);
    let mut session = PairingSession::new(Arc::clone(&shared));
    assert!(session.pin_start().is_ok());
    let pin = shared.pending_pin().expect("a PIN is pending");
    assert_eq!(pin.len(), 4);
    assert!(pin.chars().all(|digit| digit.is_ascii_digit()));
    // A second request keeps the PIN a user may already be reading.
    assert!(session.pin_start().is_ok());
    assert_eq!(shared.pending_pin().as_deref(), Some(pin.as_str()));

    let fixed = state(PinMode::Fixed(42));
    assert_eq!(fixed.pending_pin().as_deref(), Some("0042"));
    assert!(PairingSession::new(fixed).pin_start().is_ok());

    let disabled = state(PinMode::Disabled);
    assert!(matches!(
        PairingSession::new(disabled).pin_start(),
        Err(PairingError::PinUnavailable)
    ));
}

#[test]
fn setup_without_a_pin_is_refused() {
    let mut session = PairingSession::new(state(PinMode::Disabled));
    assert!(matches!(
        session.setup_pin(&request(vec![
            ("method", plist::Value::from("pin")),
            ("user", plist::Value::from("client")),
        ])),
        Err(PairingError::PinUnavailable)
    ));

    // A one-time PIN only exists after `/pair-pin-start`.
    let mut session = PairingSession::new(state(PinMode::OneTime));
    assert!(matches!(
        session.setup_pin(&request(vec![
            ("method", plist::Value::from("pin")),
            ("user", plist::Value::from("client")),
        ])),
        Err(PairingError::PinUnavailable)
    ));
}

#[test]
fn setup_pin_requires_a_binary_plist_and_a_known_step() {
    let shared = state(PinMode::Fixed(1234));
    let mut session = PairingSession::new(shared);
    assert!(matches!(
        session.setup_pin(b"<?xml version=\"1.0\"?><plist/>"),
        Err(PairingError::NotPlist)
    ));
    assert!(matches!(
        session.setup_pin(&request(vec![("method", plist::Value::from("pin"))])),
        Err(PairingError::UnexpectedKeys)
    ));
    // Upstream's `strncmp` accepts any prefix of "pin" and falls back to the
    // default reply for anything else.
    assert!(matches!(
        session.setup_pin(&request(vec![
            ("method", plist::Value::from("pins")),
            ("user", plist::Value::from("client")),
        ])),
        Ok(PairingReply::Silence)
    ));
}

#[test]
fn setup_pin_rejects_out_of_order_and_oversized_steps() {
    let shared = state(PinMode::Fixed(1234));
    let mut session = PairingSession::new(Arc::clone(&shared));

    // Step 2 and step 3 before step 1: upstream dereferences a null SRP
    // context here, the port answers 470 through this error.
    assert!(matches!(
        session.setup_pin(&request(vec![
            ("pk", plist::Value::Data(vec![2; 32])),
            ("proof", plist::Value::Data(vec![0; 20])),
        ])),
        Err(PairingError::OutOfOrder(_))
    ));
    assert!(matches!(
        session.setup_pin(&step_three_request(vec![0; 32], vec![0; 16])),
        Err(PairingError::OutOfOrder(_))
    ));

    assert!(session.pin_start().is_ok());
    let username = b"AA:BB:CC:DD:EE:FF";
    let long_user = request(vec![
        ("method", plist::Value::from("pin")),
        ("user", plist::Value::from("x".repeat(25))),
    ]);
    assert!(matches!(
        session.setup_pin(&long_user),
        Err(PairingError::InvalidLength("pairing user name"))
    ));
    let (exchange, _) = setup_pin_two_steps(&mut session, b"1234", username);
    // Step 2 already consumed the SRP context, so it cannot run twice.
    assert!(matches!(
        session.setup_pin(&request(vec![
            ("pk", plist::Value::Data(exchange.public_key.clone())),
            ("proof", plist::Value::Data(exchange.proof.to_vec())),
        ])),
        Err(PairingError::OutOfOrder(_))
    ));

    // A public value or proof of the wrong length is refused before it
    // reaches the big-integer math, where upstream over-reads the buffer.
    let mut fresh = PairingSession::new(Arc::clone(&shared));
    fresh
        .setup_pin(&request(vec![
            ("method", plist::Value::from("pin")),
            ("user", plist::Value::from("client")),
        ]))
        .expect("step 1");
    let oversized_public = request(vec![
        ("pk", plist::Value::Data(vec![2; MAX_SRP_PUBLIC + 1])),
        ("proof", plist::Value::Data(vec![0; APPLE_SRP_HASH_SIZE])),
    ]);
    assert!(matches!(
        fresh.setup_pin(&oversized_public),
        Err(PairingError::InvalidLength("SRP client public key"))
    ));
    let short_proof = request(vec![
        ("pk", plist::Value::Data(vec![2; 32])),
        (
            "proof",
            plist::Value::Data(vec![0; APPLE_SRP_HASH_SIZE - 1]),
        ),
    ]);
    assert!(matches!(
        fresh.setup_pin(&short_proof),
        Err(PairingError::InvalidLength("SRP client proof"))
    ));
}

#[test]
fn setup_pin_refuses_the_third_step_without_a_verified_proof() {
    let shared = state(PinMode::Fixed(1234));
    let mut session = PairingSession::new(Arc::clone(&shared));
    let username = b"AA:BB:CC:DD:EE:FF";
    let first = session
        .setup_pin(&request(vec![
            ("method", plist::Value::from("pin")),
            ("user", plist::Value::from("AA:BB:CC:DD:EE:FF")),
        ]))
        .expect("step 1");

    // The attack upstream is open to: derive the step 3 keys from the
    // all-zero session key of a context whose proof was never checked.
    let zero_key = [0u8; APPLE_SESSION_KEY_SIZE];
    let attacker_key = [0x11u8; ED25519_KEY_SIZE];
    let (epk, auth_tag) = seal_step_three(&zero_key, &attacker_key);
    let outcome = session.setup_pin(&step_three_request(epk, auth_tag));
    assert!(
        matches!(outcome, Err(PairingError::OutOfOrder(_))),
        "step 3 must not run without a verified proof"
    );
    assert!(session.client_public_key.is_none());
    assert_eq!(session.status, Status::Initial);

    // The same connection can still pair properly afterwards.
    let salt: [u8; 16] = field(&plist_of(&first), "salt").try_into().expect("salt");
    let server_public = field(&plist_of(&first), "pk");
    let exchange = test_client::exchange(username, b"1234", &salt, &[0x07; 32], &server_public);
    session
        .setup_pin(&request(vec![
            ("pk", plist::Value::Data(exchange.public_key.clone())),
            ("proof", plist::Value::Data(exchange.proof.to_vec())),
        ]))
        .expect("step 2");
    let (epk, auth_tag) = seal_step_three(&exchange.session_key, &attacker_key);
    let reply = session
        .setup_pin(&step_three_request(epk, auth_tag))
        .expect("step 3");
    assert_eq!(session.client_public_key, Some(attacker_key));
    assert_eq!(session.status, Status::Setup);
    let reply = plist_of(&reply);
    let keys = derive_pair_setup_keys(&exchange.session_key);
    let (_, encrypt_iv) = pair_setup_gcm_nonces(&exchange.session_key);
    let identity = crypto::aes128_gcm16_decrypt(
        &keys.key,
        &encrypt_iv,
        &field(&reply, "epk"),
        &field(&reply, "authTag"),
    )
    .expect("the reply opens with the second nonce");
    assert_eq!(identity, shared.identity_public().to_vec());
}

#[test]
fn setup_pin_refuses_a_wrong_proof_and_bounds_attempts() {
    let shared = state(PinMode::Fixed(1234));
    let mut session = PairingSession::new(Arc::clone(&shared));
    let username = b"AA:BB:CC:DD:EE:FF";
    let first = session
        .setup_pin(&request(vec![
            ("method", plist::Value::from("pin")),
            ("user", plist::Value::from("AA:BB:CC:DD:EE:FF")),
        ]))
        .expect("step 1");
    let salt: [u8; 16] = field(&plist_of(&first), "salt").try_into().expect("salt");
    let server_public = field(&plist_of(&first), "pk");
    // The client used the wrong PIN, so its proof cannot match.
    let exchange = test_client::exchange(username, b"9999", &salt, &[0x07; 32], &server_public);
    assert!(matches!(
        session.setup_pin(&request(vec![
            ("pk", plist::Value::Data(exchange.public_key)),
            ("proof", plist::Value::Data(exchange.proof.to_vec())),
        ])),
        Err(PairingError::AuthenticationFailed)
    ));
    // A wrong proof is refused, and the session needs a new step 1.
    assert!(matches!(
        session.setup_pin(&request(vec![
            ("pk", plist::Value::Data(vec![2; 32])),
            ("proof", plist::Value::Data(vec![0; 20])),
        ])),
        Err(PairingError::OutOfOrder(_))
    ));
}

#[test]
fn a_one_time_pin_survives_a_bounded_number_of_failures() {
    let shared = state(PinMode::OneTime);
    let mut session = PairingSession::new(Arc::clone(&shared));
    session.pin_start().expect("pin start");
    let pin = shared.pending_pin().expect("pending PIN");
    let username = b"AA:BB:CC:DD:EE:FF";
    for attempt in 0..MAX_PIN_FAILURES {
        let first = session
            .setup_pin(&request(vec![
                ("method", plist::Value::from("pin")),
                ("user", plist::Value::from("AA:BB:CC:DD:EE:FF")),
            ]))
            .expect("step 1");
        let salt: [u8; 16] = field(&plist_of(&first), "salt").try_into().expect("salt");
        let server_public = field(&plist_of(&first), "pk");
        let wrong = test_client::exchange(username, b"0001", &salt, &[0x07; 32], &server_public);
        // The PIN from `pin_start` is what the server used, so the client
        // has to guess it; it cannot, and is refused.
        assert!(
            matches!(
                session.setup_pin(&request(vec![
                    ("pk", plist::Value::Data(wrong.public_key)),
                    ("proof", plist::Value::Data(wrong.proof.to_vec())),
                ])),
                Err(PairingError::AuthenticationFailed)
            ),
            "attempt {attempt} must be refused"
        );
        if attempt + 1 < MAX_PIN_FAILURES {
            assert_eq!(
                shared.pending_pin().as_deref(),
                Some(pin.as_str()),
                "the PIN survives {} of {MAX_PIN_FAILURES} failures",
                attempt + 1
            );
        }
    }
    // The bound is reached: the PIN is dropped and a new one is drawn.
    assert_eq!(shared.pending_pin(), None);
    session.pin_start().expect("pin start again");
    assert!(shared.pending_pin().is_some());
}

#[test]
fn pair_setup_answers_the_public_key_only_for_the_right_length() {
    let shared = state(PinMode::Fixed(1234));
    let mut session = PairingSession::new(Arc::clone(&shared));
    // Upstream ignores the content of the body and only checks its length.
    let reply = session.setup(&[0u8; 32]).expect("legacy setup");
    assert_eq!(body_of(&reply), shared.identity_public());
    assert_eq!(session.status, Status::Setup);

    let mut session = PairingSession::new(Arc::clone(&shared));
    assert!(matches!(
        session.setup(&[0u8; 31]),
        Ok(PairingReply::Silence)
    ));
}

/// Client side of `/pair-verify`: keys the test controls, so the harness
/// never uses the function under test to build its own input.
struct VerifyClient {
    private: [u8; 32],
    public: [u8; 32],
    identity_seed: [u8; 32],
    identity_public: [u8; 32],
}

impl VerifyClient {
    fn new() -> Self {
        let private = [0x21u8; 32];
        let identity_seed = [0x33u8; 32];
        Self {
            public: x25519_public(&private),
            private,
            identity_seed,
            identity_public: ed25519_public_key(&identity_seed),
        }
    }

    /// Step 1 body: a four-byte mode, the client key exchange key and the
    /// client's public key (`upstream/UxPlay/lib/raop_handlers.h:488-497`).
    fn handshake_body(&self) -> Vec<u8> {
        let mut body = vec![1u8, 0, 0, 0];
        body.extend_from_slice(&self.public);
        body.extend_from_slice(&self.identity_public);
        body
    }

    /// Decrypts the reply of step 1 and checks the receiver's signature.
    fn verify_server(&self, reply: &[u8], receiver_public: &[u8; 32]) -> Result<(), ()> {
        let server_ecdh: [u8; 32] = reply[..32].try_into().map_err(|_| ())?;
        let mut signature: [u8; 64] = reply[32..].try_into().map_err(|_| ())?;
        let shared = x25519_shared(&self.private, &server_ecdh);
        let keys = derive_pair_verify_keys(&shared);
        let mut cipher = Aes128CtrState::new(&keys.key, &keys.iv).map_err(|_| ())?;
        cipher.apply(&mut signature);
        let message = [server_ecdh, self.public].concat();
        ed25519_verify(receiver_public, &message, &signature)
            .then_some(())
            .ok_or(())
    }

    /// Body of step 2, signing the transcript and using the second block of
    /// the shared keystream.
    fn finish_body(&self, reply: &[u8]) -> Vec<u8> {
        let server_ecdh: [u8; 32] = reply[..32].try_into().expect("server key");
        let shared = x25519_shared(&self.private, &server_ecdh);
        let keys = derive_pair_verify_keys(&shared);
        let mut signature = ed25519_sign(&self.identity_seed, &[self.public, server_ecdh].concat());
        let mut cipher = Aes128CtrState::new(&keys.key, &keys.iv).expect("key and iv");
        let mut discarded = [0u8; 64];
        cipher.apply(&mut discarded);
        cipher.apply(&mut signature);
        let mut body = vec![0u8, 0, 0, 0];
        body.extend_from_slice(&signature);
        body
    }
}

#[test]
fn pair_verify_handshakes_and_finishes() {
    let shared = state(PinMode::Fixed(1234));
    let mut session = PairingSession::new(Arc::clone(&shared));
    // Legacy setup puts the connection into the state pair-verify needs,
    // which is also how upstream lets a client verify the receiver.
    session.setup(&[0u8; 32]).expect("setup");

    let client = VerifyClient::new();
    let reply = session.verify(&client.handshake_body()).expect("handshake");
    let body = body_of(&reply).to_vec();
    assert_eq!(body.len(), 96);
    client
        .verify_server(&body, &shared.identity_public())
        .expect("the receiver's signature must verify");
    assert_eq!(session.status, Status::Handshake);

    let finish = client.finish_body(&body);
    assert!(matches!(
        session.verify(&finish),
        Ok(PairingReply::Octets(ref body)) if body.is_empty()
    ));
    assert_eq!(session.status, Status::Finished);
}

#[test]
fn pair_verify_refuses_a_bad_signature_and_keeps_its_shape() {
    let shared = state(PinMode::Fixed(1234));
    let mut session = PairingSession::new(Arc::clone(&shared));
    session.setup(&[0u8; 32]).expect("setup");
    let client = VerifyClient::new();
    let reply = session.verify(&client.handshake_body()).expect("handshake");
    let body = body_of(&reply).to_vec();

    let mut finish = client.finish_body(&body);
    finish[10] ^= 0x01;
    assert!(matches!(
        session.verify(&finish),
        Ok(PairingReply::Disconnect)
    ));

    // Wrong lengths and unknown steps answer with the default reply.
    let mut session = PairingSession::new(Arc::clone(&shared));
    session.setup(&[0u8; 32]).expect("setup");
    assert!(matches!(
        session.verify(&[1, 0, 0]),
        Ok(PairingReply::Silence)
    ));
    // A body of the wrong length and an unknown mode both fall through to
    // the default reply, which upstream's `switch` has no default for.
    assert!(matches!(
        session.verify(&[1u8; 67]),
        Ok(PairingReply::Silence)
    ));
    assert!(matches!(
        session.verify(&[2u8; 68]),
        Ok(PairingReply::Silence)
    ));
    assert!(matches!(
        session.verify(&[3u8; 68]),
        Ok(PairingReply::Silence)
    ));
}

#[test]
fn pair_verify_without_setup_follows_the_pin_policy() {
    // No PIN: upstream lets the client fall back to the legacy setup.
    let mut session = PairingSession::new(state(PinMode::Disabled));
    assert!(matches!(
        session.verify(&[1u8; 68]),
        Ok(PairingReply::Silence)
    ));

    // With a PIN the connection is moved into the setup state instead, and
    // the first step completes the handshake.
    let shared = state(PinMode::Fixed(1234));
    let mut session = PairingSession::new(Arc::clone(&shared));
    let client = VerifyClient::new();
    let reply = session.verify(&client.handshake_body()).expect("handshake");
    assert_eq!(body_of(&reply).len(), 96);
    assert_eq!(session.status, Status::Handshake);
}

#[test]
fn pair_verify_honours_the_registration_predicate() {
    let shared = Arc::new(
        PairingState::with_random(
            IDENTITY_SEED,
            PinMode::Fixed(1234),
            Box::new(FixedRandom::new()),
        )
        .with_client_registered(|_| false),
    );
    let mut session = PairingSession::new(Arc::clone(&shared));
    let client = VerifyClient::new();
    // Upstream stops checking the list once the connection reaches its setup
    // state, so a refused client would only have to ask again; the refusal
    // has to survive the retry.
    for attempt in 0..2 {
        assert!(
            matches!(
                session.verify(&client.handshake_body()),
                Ok(PairingReply::Silence)
            ),
            "attempt {attempt} must be refused"
        );
    }
    assert_eq!(session.status, Status::Setup);

    // Proving the PIN is what lifts the refusal, so a client that pairs on
    // this connection can still verify on it afterwards.
    session.pin_start().expect("pin start");
    let username = b"AA:BB:CC:DD:EE:FF";
    let (exchange, _) = setup_pin_two_steps(&mut session, b"1234", username);
    let (epk, auth_tag) = seal_step_three(&exchange.session_key, &client.identity_public);
    session
        .setup_pin(&step_three_request(epk, auth_tag))
        .expect("step 3");
    let reply = session.verify(&client.handshake_body()).expect("handshake");
    assert_eq!(body_of(&reply).len(), 96);
}

#[test]
fn pair_verify_accepts_a_registered_client() {
    let shared = Arc::new(
        PairingState::with_random(
            IDENTITY_SEED,
            PinMode::Fixed(1234),
            Box::new(FixedRandom::new()),
        )
        .with_client_registered(|_| true),
    );
    let mut session = PairingSession::new(Arc::clone(&shared));
    let client = VerifyClient::new();
    let reply = session.verify(&client.handshake_body()).expect("handshake");
    assert_eq!(body_of(&reply).len(), 96);
}

#[test]
fn setup_pin_bounds_the_work_one_connection_can_cause() {
    let shared = state(PinMode::Fixed(1234));
    let mut session = PairingSession::new(Arc::clone(&shared));
    let username = b"AA:BB:CC:DD:EE:FF";
    for attempt in 0..MAX_SETUP_PIN_ATTEMPTS {
        assert!(
            session.setup_pin(&step_one_request(username)).is_ok(),
            "attempt {attempt} opens an SRP context"
        );
    }
    // Beyond the bound the receiver refuses instead of spending another
    // modular exponentiation for an unauthenticated peer.
    assert!(matches!(
        session.setup_pin(&step_one_request(username)),
        Err(PairingError::AuthenticationFailed)
    ));
}

#[test]
fn session_keys_are_handed_out_only_once_and_only_after_verification() {
    let shared = state(PinMode::Fixed(1234));
    let mut session = PairingSession::new(Arc::clone(&shared));
    let client = VerifyClient::new();

    // Nothing on this connection, nothing to hand out.
    assert_eq!(session.authentication(), SessionAuth::None);
    assert!(session.take_session_keys().is_none());

    // The legacy setup opens the verify path but authenticates nobody, so it
    // still must not produce stream material.
    session.setup(&[0u8; 32]).expect("setup");
    assert_eq!(session.authentication(), SessionAuth::LegacySetup);
    assert!(session.take_session_keys().is_none());

    // A started key exchange is not a finished one.
    let reply = session.verify(&client.handshake_body()).expect("handshake");
    let body = body_of(&reply).to_vec();
    assert!(session.take_session_keys().is_none());

    let finish = client.finish_body(&body);
    assert!(matches!(
        session.verify(&finish),
        Ok(PairingReply::Octets(_))
    ));
    assert_eq!(session.authentication(), SessionAuth::Verified);
    let keys = session.take_session_keys().expect("verified session");
    assert_eq!(
        keys.ecdh_secret,
        airplay_core_shared_secret(&client, &body),
        "the material is the shared secret of this connection's exchange"
    );
    // Handed out once: a second media session cannot reuse it.
    assert!(session.take_session_keys().is_none());
}

/// Shared secret of the test client's exchange, computed from the client's
/// private key and the receiver's public key.
fn airplay_core_shared_secret(client: &VerifyClient, reply: &[u8]) -> [u8; X25519_KEY_SIZE] {
    let server_ecdh: [u8; X25519_KEY_SIZE] = reply[..32].try_into().expect("server key");
    x25519_shared(&client.private, &server_ecdh)
}

#[test]
fn session_keys_are_not_handed_out_to_a_connection_the_predicate_refused() {
    let shared = Arc::new(
        PairingState::with_random(
            IDENTITY_SEED,
            PinMode::Fixed(1234),
            Box::new(FixedRandom::new()),
        )
        .with_client_registered(|_| false),
    );
    let mut session = PairingSession::new(Arc::clone(&shared));
    let client = VerifyClient::new();
    assert!(matches!(
        session.verify(&client.handshake_body()),
        Ok(PairingReply::Silence)
    ));
    assert_eq!(session.authentication(), SessionAuth::LegacySetup);
    assert!(session.take_session_keys().is_none());
}

#[test]
fn pin_verification_is_visible_to_a_caller() {
    let shared = state(PinMode::Fixed(1234));
    let mut session = PairingSession::new(Arc::clone(&shared));
    session.pin_start().expect("pin start");
    let username = b"AA:BB:CC:DD:EE:FF";
    let (exchange, _) = setup_pin_two_steps(&mut session, b"1234", username);
    let (epk, auth_tag) = seal_step_three(&exchange.session_key, &[0x33; 32]);
    session
        .setup_pin(&step_three_request(epk, auth_tag))
        .expect("step 3");
    assert_eq!(session.authentication(), SessionAuth::PinVerified);
    // Proving the PIN is not the same as verifying the exchange.
    assert!(session.take_session_keys().is_none());
}

#[test]
fn pair_verify_starts_one_key_exchange_per_connection() {
    let shared = state(PinMode::Fixed(1234));
    let mut session = PairingSession::new(Arc::clone(&shared));
    session.setup(&[0u8; 32]).expect("setup");
    let client = VerifyClient::new();
    let reply = session.verify(&client.handshake_body()).expect("handshake");
    assert_eq!(body_of(&reply).len(), 96);

    // A second key exchange would replace the keys this connection already
    // agreed on, so it is refused.
    assert!(matches!(
        session.verify(&client.handshake_body()),
        Ok(PairingReply::Silence)
    ));
    assert_eq!(session.status, Status::Handshake);
}

#[test]
fn pair_verify_refuses_a_low_order_key_exchange_key() {
    let shared = state(PinMode::Fixed(1234));
    let mut session = PairingSession::new(Arc::clone(&shared));
    session.setup(&[0u8; 32]).expect("setup");
    let mut body = vec![1u8, 0, 0, 0];
    body.extend_from_slice(&[0u8; 32]);
    body.extend_from_slice(&ed25519_public_key(&[0x33; 32]));
    assert!(matches!(
        session.verify(&body),
        Err(PairingError::AuthenticationFailed)
    ));
}

#[test]
fn debug_output_carries_no_key_material() {
    let shared = state(PinMode::Fixed(1234));
    let mut session = PairingSession::new(Arc::clone(&shared));
    session.pin_start().expect("pin start");
    let session_text = format!("{session:?}");
    let state_text = format!("{shared:?}");
    assert!(state_text.contains("identity_public"));
    assert!(!state_text.contains(&hex(&IDENTITY_SEED)));
    assert!(!session_text.contains(&hex(&IDENTITY_SEED)));
    assert!(session_text.contains("Handshake") || session_text.contains("Initial"));
    let error = PairingError::AuthenticationFailed.to_string();
    assert!(!error.contains(&hex(&IDENTITY_SEED)));
}
