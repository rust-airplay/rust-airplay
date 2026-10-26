// SPDX-License-Identifier: GPL-3.0-or-later
//! The Apple-labelled key derivations and signature helpers.

use crate::crypto::{Aes128CtrState, CryptoError, sha512_concat};

/// Length of an X25519 public key or private scalar.
pub const X25519_KEY_SIZE: usize = 32;

/// Length of an Ed25519 public key or private seed.
pub const ED25519_KEY_SIZE: usize = 32;

/// Length of the signature both sides of `/pair-verify` exchange.
pub const PAIRING_SIG_SIZE: usize = 64;

/// AES key and IV one pairing step derives from a shared secret.
///
/// Deliberately without `Debug`: the two fields are secret key material, and a
/// derived `Debug` would print them into any log that formats the value.
pub struct PairVerifyKeys {
    /// AES-128 key.
    pub key: [u8; 16],
    /// Initial counter block.
    pub iv: [u8; 16],
}

/// Key and IV of `/pair-verify`, derived from the X25519 shared secret
pub fn derive_pair_verify_keys(shared_secret: &[u8; X25519_KEY_SIZE]) -> PairVerifyKeys {
    PairVerifyKeys {
        key: sha512_concat(&[b"Pair-Verify-AES-Key", shared_secret])[..16]
            .try_into()
            .unwrap(),
        iv: sha512_concat(&[b"Pair-Verify-AES-IV", shared_secret])[..16]
            .try_into()
            .unwrap(),
    }
}

/// Key and IV of `/pair-setup-pin` step 3, derived from the SRP session key
/// # Examples
///
/// ```
/// use rust_airplay::pairing::derive_pair_setup_keys;
///
/// let keys = derive_pair_setup_keys(&[0x33; 32]);
/// assert_eq!(keys.key.len(), 16);
/// assert_ne!(keys.key, keys.iv);
/// ```
pub fn derive_pair_setup_keys(session_key: &[u8]) -> PairVerifyKeys {
    let key_hash = sha512_concat(&[b"Pair-Setup-AES-Key", session_key]);
    let iv_hash = sha512_concat(&[b"Pair-Setup-AES-IV", session_key]);
    PairVerifyKeys {
        key: key_hash[..16].try_into().unwrap(),
        iv: iv_hash[..16].try_into().unwrap(),
    }
}

/// Pair-Setup AES-GCM nonces of `/pair-setup-pin` step 3, decrypt first.
///
/// Both directions derive one base IV from the `Pair-Setup-AES-IV` label and the
/// SRP session key. The client's key exchange key is decrypted with the base IV
/// incremented by one and the reply is encrypted with it incremented by two
/// ( and `:635-637`, where the second
/// increment is the undocumented nonce adjustment). Neither nonce travels on the
/// wire.
pub fn pair_setup_gcm_nonces(session_key: &[u8]) -> ([u8; 16], [u8; 16]) {
    let base = derive_pair_setup_keys(session_key).iv;
    let mut decrypt = base;
    decrypt[15] = decrypt[15].wrapping_add(1);
    let mut encrypt = base;
    encrypt[15] = encrypt[15].wrapping_add(2);
    (decrypt, encrypt)
}

/// Key and IV a stream of one audio session uses, derived from the session's
/// audio key and connection identifier (
/// labels its stream material the same way).
pub fn derive_stream_material(
    audio_key: &[u8; 16],
    stream_connection_id: u64,
) -> ([u8; 16], [u8; 16]) {
    let key_label = format!("AirPlayStreamKey{stream_connection_id}");
    let iv_label = format!("AirPlayStreamIV{stream_connection_id}");
    let key_hash = sha512_concat(&[key_label.as_bytes(), audio_key]);
    let iv_hash = sha512_concat(&[iv_label.as_bytes(), audio_key]);
    (
        key_hash[..16].try_into().unwrap(),
        iv_hash[..16].try_into().unwrap(),
    )
}

/// Signs the two key exchange keys of `/pair-verify` and encrypts the result.
///
/// The server signs `our_ecdh_public || peer_ecdh_public` and uses the first 64
/// bytes of the shared keystream.
pub fn encrypt_pair_verify_signature(
    private_key: &[u8; 32],
    our_ecdh_public: &[u8; 32],
    peer_ecdh_public: &[u8; 32],
    shared_secret: &[u8; 32],
) -> Result<[u8; PAIRING_SIG_SIZE], CryptoError> {
    let message = [*our_ecdh_public, *peer_ecdh_public].concat();
    let mut signature = crate::crypto::ed25519_sign(private_key, &message);
    let keys = derive_pair_verify_keys(shared_secret);
    let mut cipher = Aes128CtrState::new(&keys.key, &keys.iv)?;
    cipher.apply(&mut signature);
    Ok(signature)
}

/// Decrypts the signature a client sends in the second `/pair-verify` step.
///
/// The server and the client share one AES-CTR keystream: the server's own
/// signature used its first 64 bytes, so the client's signature is decrypted
/// with the second 64 bytes. The protocol advances the stream with one throwaway
/// round before decrypting; skipping
/// that step would make every real client's signature fail to verify while a
/// self-consistent encrypt/decrypt round trip still passes.
pub fn decrypt_pair_verify_signature(
    encrypted_signature: &[u8; PAIRING_SIG_SIZE],
    shared_secret: &[u8; 32],
) -> Result<[u8; PAIRING_SIG_SIZE], CryptoError> {
    let keys = derive_pair_verify_keys(shared_secret);
    let mut cipher = Aes128CtrState::new(&keys.key, &keys.iv)?;
    let mut discarded = [0u8; PAIRING_SIG_SIZE];
    cipher.apply(&mut discarded);
    let mut plain = *encrypted_signature;
    cipher.apply(&mut plain);
    Ok(plain)
}

/// Verifies the signature a client sends in the second `/pair-verify` step.
///
/// The client signs `peer_ecdh_public || our_ecdh_public`, the opposite order of
/// the server's own signature.
pub fn verify_pair_signature(
    signature: &[u8; PAIRING_SIG_SIZE],
    peer_ecdh_public: &[u8; 32],
    our_ecdh_public: &[u8; 32],
    peer_ed25519_public: &[u8; 32],
) -> bool {
    let message = [*peer_ecdh_public, *our_ecdh_public].concat();
    crate::crypto::ed25519_verify(peer_ed25519_public, &message, signature)
}
