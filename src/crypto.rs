// SPDX-License-Identifier: GPL-3.0-or-later
//! RustCrypto-backed primitives used by AirPlay pairing and media decryption.
//!
//! Protocol code chooses the exact mode, IV length and key derivation labels; these helpers
//! only run the primitive. They intentionally do not silently pad, truncate or normalize
//! input: a key of the wrong length is an error, not a value quietly stretched to fit, because
//! the other side of a pairing exchange would compute a different key and the only symptom
//! would be an authentication failure much later.

use aes::Aes128;
use aes_gcm::{
    AesGcm, Nonce, Tag,
    aead::{AeadInPlace, KeyInit},
};
use cbc::Decryptor;
use cipher::{BlockDecryptMut, KeyIvInit, StreamCipher, block_padding::NoPadding};
use ctr::Ctr128BE;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha512};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

type Aes128Ctr = Ctr128BE<Aes128>;
type Aes128Gcm16 = AesGcm<Aes128, cipher::consts::U16>;

/// Why a cryptographic operation refused its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// A key, IV, nonce, tag or block count was outside the size the operation requires.
    InvalidLength(&'static str),
    /// The key or IV was the right size but not a usable value for this cipher.
    InvalidKey,
    /// An AEAD tag did not authenticate the record.
    AuthenticationFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength(name) => write!(f, "invalid length for {name}"),
            Self::InvalidKey => f.write_str("invalid key or IV"),
            Self::AuthenticationFailed => f.write_str("AEAD authentication failed"),
        }
    }
}
impl std::error::Error for CryptoError {}

/// Hashes the concatenation of `parts` with SHA-512.
///
/// AirPlay derives keys from a label followed by a shared secret, so the concatenation is the
/// contract: hashing the parts separately produces a different, wrong key.
#[must_use]
pub fn sha512_concat(parts: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Hashes the concatenation of `parts` with SHA-1.
///
/// SHA-1 is what the SRP exchange and the legacy pairing transcript use; it is not a choice.
#[must_use]
pub fn sha1_concat(parts: &[&[u8]]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Hashes the concatenation of `parts` with MD5.
///
/// The digest only appears in RTSP digest authorization, where it is part of the wire
/// protocol.
#[must_use]
pub fn md5_concat(parts: &[&[u8]]) -> [u8; 16] {
    let mut hasher = Md5::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Takes the first `output_len` bytes of a SHA-512 hash of `parts`.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidLength`] when `output_len` is longer than a SHA-512 digest.
pub fn sha512_derive(parts: &[&[u8]], output_len: usize) -> Result<Vec<u8>, CryptoError> {
    if output_len > 64 {
        return Err(CryptoError::InvalidLength("SHA-512 output"));
    }
    Ok(sha512_concat(parts)[..output_len].to_vec())
}

/// AES-CTR with the OpenSSL EVP counter convention AirPlay uses.
#[derive(Clone)]
pub struct Aes128CtrState {
    cipher: Aes128Ctr,
    key: [u8; 16],
    iv: [u8; 16],
}

impl Aes128CtrState {
    /// Starts a keystream with a 16-byte key and a 16-byte IV.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] when either value is not 16 bytes.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, CryptoError> {
        let key: [u8; 16] = key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength("AES-128 key"))?;
        let iv: [u8; 16] = iv
            .try_into()
            .map_err(|_| CryptoError::InvalidLength("AES-CTR IV"))?;
        let cipher = Aes128Ctr::new_from_slices(&key, &iv).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { cipher, key, iv })
    }

    /// Encrypts or decrypts `data` in place, advancing the counter by its length.
    ///
    /// Counter mode is its own inverse, and the counter position is what ties a packet to the
    /// keystream a sender used: the caller applies the same state to consecutive bytes of a
    /// stream, in order.
    pub fn apply(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }

    /// Rewinds to the start of the keystream.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] when the stored key and IV cannot start a cipher,
    /// which cannot happen after a successful [`Aes128CtrState::new`].
    pub fn reset(&mut self) -> Result<(), CryptoError> {
        self.cipher =
            Aes128Ctr::new_from_slices(&self.key, &self.iv).map_err(|_| CryptoError::InvalidKey)?;
        Ok(())
    }
}

/// Decrypts whole AES-128-CBC blocks with no padding.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidLength`] when the input is not a whole number of blocks and
/// [`CryptoError::InvalidKey`] for a key or IV of the wrong size.
pub fn aes128_cbc_decrypt(key: &[u8], iv: &[u8], input: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if input.len() % 16 != 0 {
        return Err(CryptoError::InvalidLength("AES-CBC blocks"));
    }
    let mut output = input.to_vec();
    let decrypted = Decryptor::<Aes128>::new_from_slices(key, iv)
        .map_err(|_| CryptoError::InvalidKey)?
        .decrypt_padded_mut::<NoPadding>(&mut output)
        .map_err(|_| CryptoError::InvalidLength("AES-CBC blocks"))?;
    Ok(decrypted.to_vec())
}

/// Decrypts one AES-128-GCM-16 record with an empty associated-data field.
///
/// AirPlay pairing uses a 16-byte nonce, so a key, IV or tag of any other length
/// is rejected with [`CryptoError::InvalidLength`] instead of panicking.
pub fn aes128_gcm16_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = aes_gcm::Key::<Aes128Gcm16>::from_exact_iter(key.iter().copied())
        .ok_or(CryptoError::InvalidLength("AES-128 key"))?;
    let nonce = Nonce::<cipher::consts::U16>::from_exact_iter(iv.iter().copied())
        .ok_or(CryptoError::InvalidLength("AES-GCM IV"))?;
    let tag = Tag::<cipher::consts::U16>::from_exact_iter(tag.iter().copied())
        .ok_or(CryptoError::InvalidLength("AES-GCM tag"))?;
    let cipher = Aes128Gcm16::new(&key);
    let mut plaintext = ciphertext.to_vec();
    cipher
        .decrypt_in_place_detached(&nonce, b"", &mut plaintext, &tag)
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    Ok(plaintext)
}

/// Encrypts one AES-128-GCM-16 record with an empty associated-data field.
///
/// The counterpart of [`aes128_gcm16_decrypt`], needed for the reply of the
/// Apple pairing setup: a key or IV
/// of any length other than 16 bytes is rejected with
/// [`CryptoError::InvalidLength`]. Returns the ciphertext and its tag.
///
/// # Examples
///
/// ```
/// use rust_airplay::crypto::{aes128_gcm16_decrypt, aes128_gcm16_encrypt};
///
/// let key = [0x11; 16];
/// let nonce = [0x22; 16];
/// let (ciphertext, tag) = aes128_gcm16_encrypt(&key, &nonce, b"pairing").expect("sealed");
/// let plaintext = aes128_gcm16_decrypt(&key, &nonce, &ciphertext, &tag).expect("opened");
/// assert_eq!(plaintext, b"pairing");
/// ```
pub fn aes128_gcm16_encrypt(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), CryptoError> {
    let key = aes_gcm::Key::<Aes128Gcm16>::from_exact_iter(key.iter().copied())
        .ok_or(CryptoError::InvalidLength("AES-128 key"))?;
    let nonce = Nonce::<cipher::consts::U16>::from_exact_iter(iv.iter().copied())
        .ok_or(CryptoError::InvalidLength("AES-GCM IV"))?;
    let cipher = Aes128Gcm16::new(&key);
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(&nonce, b"", &mut ciphertext)
        .map_err(|_| CryptoError::InvalidLength("AES-GCM plaintext"))?;
    let mut tag_bytes = [0u8; 16];
    tag_bytes.copy_from_slice(&tag);
    Ok((ciphertext, tag_bytes))
}

/// The X25519 public key of a private scalar.
#[must_use]
pub fn x25519_public(private_key: &[u8; 32]) -> [u8; 32] {
    x25519(*private_key, X25519_BASEPOINT_BYTES)
}

/// The X25519 shared secret between a private scalar and a peer public key.
#[must_use]
/// # Examples
///
/// ```
/// use rust_airplay::crypto::{x25519_public, x25519_shared};
///
/// let alice = [0x11; 32];
/// let bob = [0x22; 32];
/// let from_alice = x25519_shared(&alice, &x25519_public(&bob));
/// let from_bob = x25519_shared(&bob, &x25519_public(&alice));
/// assert_eq!(from_alice, from_bob);
/// ```
pub fn x25519_shared(private_key: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    x25519(*private_key, *peer_public)
}

/// Ed25519 public key of a 32-byte private seed.
///
/// A receiver advertises the public key of its long-term pairing identity
///, so the seed alone is enough to
/// describe the identity a caller injects.
pub fn ed25519_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    use ed25519_dalek::SigningKey;
    SigningKey::from_bytes(private_key)
        .verifying_key()
        .to_bytes()
}

/// Signs `message` with the private seed, producing the 64-byte signature the pairing
/// protocol carries.
#[must_use]
pub fn ed25519_sign(private_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    use ed25519_dalek::{Signer, SigningKey};
    SigningKey::from_bytes(private_key).sign(message).to_bytes()
}

/// Verifies a signature against a public key.
///
/// Returns `false` rather than an error: a wrong signature and a malformed public key are the
/// same answer to a pairing step, and the caller answers both the same way.
#[must_use]
pub fn ed25519_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    key.verify(message, &Signature::from_bytes(signature))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_known_vectors() {
        assert_eq!(
            sha1_concat(&[b"abc"]),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
            .map(|x| x)
        );
        assert_eq!(
            md5_concat(&[b"abc"]),
            [
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
                0x7f, 0x72
            ]
        );
    }

    #[test]
    fn ctr_is_streaming_and_resettable() {
        let mut first = Aes128CtrState::new(&[0; 16], &[0; 16]).unwrap();
        let mut second = Aes128CtrState::new(&[0; 16], &[0; 16]).unwrap();
        let mut all = [0u8; 32];
        let mut split = [0u8; 32];
        first.apply(&mut all);
        second.apply(&mut split[..7]);
        second.apply(&mut split[7..]);
        assert_eq!(all, split);
        second.reset().unwrap();
        let mut reset = [0u8; 32];
        second.apply(&mut reset);
        assert_eq!(all, reset);
    }

    #[test]
    fn matches_aes_ctr_and_cbc_vectors() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
            0xfe, 0xff,
        ];
        let mut ctr = Aes128CtrState::new(&key, &iv).unwrap();
        let mut block = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        ctr.apply(&mut block);
        assert_eq!(
            block,
            [
                0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d,
                0xb6, 0xce
            ]
        );
        let cbc_iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let ciphertext = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9,
            0x19, 0x7d,
        ];
        assert_eq!(
            aes128_cbc_decrypt(&key, &cbc_iv, &ciphertext).unwrap(),
            vec![
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
                0x17, 0x2a
            ]
        );
    }

    #[test]
    fn ed25519_round_trip() {
        let private = [7u8; 32];
        let public = ed25519_dalek::SigningKey::from_bytes(&private)
            .verifying_key()
            .to_bytes();
        let signature = ed25519_sign(&private, b"airplay");
        assert!(ed25519_verify(&public, b"airplay", &signature));
        assert!(!ed25519_verify(&public, b"tampered", &signature));
    }

    fn fixed_array<const N: usize>(hex: &str) -> [u8; N] {
        let mut output = [0u8; N];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        output
    }

    #[test]
    fn gcm_rejects_wrong_key_iv_or_tag_length() {
        assert_eq!(
            aes128_gcm16_decrypt(&[0; 15], &[0; 16], b"", &[0; 16]),
            Err(CryptoError::InvalidLength("AES-128 key"))
        );
        assert_eq!(
            aes128_gcm16_decrypt(&[0; 16], &[0; 15], b"", &[0; 16]),
            Err(CryptoError::InvalidLength("AES-GCM IV"))
        );
        assert_eq!(
            aes128_gcm16_decrypt(&[0; 16], &[0; 16], b"", &[0; 15]),
            Err(CryptoError::InvalidLength("AES-GCM tag"))
        );
    }

    #[test]
    fn gcm_round_trip_and_tamper_detection() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let cipher = Aes128Gcm16::new(&aes_gcm::Key::<Aes128Gcm16>::from_exact_iter(key).unwrap());
        let mut buffer = b"airplay pairing payload".to_vec();
        let tag = cipher
            .encrypt_in_place_detached(
                &Nonce::<cipher::consts::U16>::from_exact_iter(iv).unwrap(),
                b"",
                &mut buffer,
            )
            .unwrap();

        assert_eq!(
            aes128_gcm16_decrypt(&key, &iv, &buffer, &tag).unwrap(),
            b"airplay pairing payload"
        );

        let mut tampered = buffer.clone();
        tampered[0] ^= 1;
        assert_eq!(
            aes128_gcm16_decrypt(&key, &iv, &tampered, &tag),
            Err(CryptoError::AuthenticationFailed)
        );

        let mut wrong_tag = tag;
        wrong_tag[0] ^= 1;
        assert_eq!(
            aes128_gcm16_decrypt(&key, &iv, &buffer, &wrong_tag),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn x25519_matches_rfc7748_vectors() {
        let alice_private: [u8; 32] =
            fixed_array("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob_private: [u8; 32] =
            fixed_array("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let alice_public: [u8; 32] =
            fixed_array("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_public: [u8; 32] =
            fixed_array("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared: [u8; 32] =
            fixed_array("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        assert_eq!(x25519_public(&alice_private), alice_public);
        assert_eq!(x25519_public(&bob_private), bob_public);
        assert_eq!(x25519_shared(&alice_private, &bob_public), shared);
        assert_eq!(x25519_shared(&bob_private, &alice_public), shared);
    }

    #[test]
    fn sha512_derive_returns_prefixes_and_rejects_overlong_output() {
        assert_eq!(
            sha512_derive(&[b"abc"], 16).unwrap(),
            vec![
                0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
                0x41, 0x31
            ]
        );
        assert_eq!(sha512_derive(&[b"abc"], 64).unwrap().len(), 64);
        assert_eq!(
            sha512_derive(&[b"abc"], 65),
            Err(CryptoError::InvalidLength("SHA-512 output"))
        );
    }
}
