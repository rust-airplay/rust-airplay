// SPDX-License-Identifier: LGPL-2.1-or-later
//! FairPlay `/fp-setup` framing, and the state a connection keeps between its two steps.
//!
//! A client that wants its stream encrypted first asks the receiver for a FairPlay setup
//! message, then sends a 164-byte handshake that contains the receiver's key material, and
//! only then sends the 72-byte encrypted key from which the media AES key is decrypted. This
//! module validates those three messages and keeps the handshake message between them; the
//! PlayFair transform itself lives in this crate's private `playfair` module.
//!
//! The replies are fixed for the receiver's own key material, which is why this is a small
//! state machine rather than a cipher implementation.

use crate::fairplay_tables::{FP_HEADER, REPLY_MESSAGES};

/// Length of a `/fp-setup` request: the 16-byte message the client sends first.
pub const SETUP_REQUEST_LEN: usize = 16;
/// Length of the receiver's `/fp-setup` reply: one of four fixed messages, chosen by mode.
pub const SETUP_RESPONSE_LEN: usize = 142;
/// Length of the handshake message that carries the receiver's key material.
pub const HANDSHAKE_REQUEST_LEN: usize = 164;
/// Length of the receiver's handshake reply.
pub const HANDSHAKE_RESPONSE_LEN: usize = 32;
/// Length of the encrypted media key a client sends once the handshake is complete.
pub const ENCRYPTED_KEY_LEN: usize = 72;
/// Length of the media key the encrypted key decrypts to.
pub const DECRYPTED_KEY_LEN: usize = 16;

/// Why a FairPlay message was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FairPlayError {
    /// A message had a length other than the one its step requires.
    InvalidLength {
        /// Length the message had to have.
        expected: usize,
        /// Length it had.
        actual: usize,
    },
    /// The message's version byte is not one this receiver answers.
    UnsupportedVersion(u8),
    /// The setup request asked for a mode outside the four the reply table has.
    InvalidMode(u8),
    /// The encrypted key arrived before the handshake that key material depends on.
    HandshakeRequired,
    /// The stored handshake message did not pass the PlayFair transform, so the
    /// encrypted key could not be decrypted.
    DecryptionFailed,
}

impl std::fmt::Display for FairPlayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid FairPlay message length: expected {expected}, got {actual}"
                )
            }
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported FairPlay version 0x{version:02x}")
            }
            Self::InvalidMode(mode) => write!(f, "invalid FairPlay setup mode {mode}"),
            Self::HandshakeRequired => f.write_str("FairPlay handshake has not completed"),
            Self::DecryptionFailed => f.write_str("FairPlay key decryption failed"),
        }
    }
}

impl std::error::Error for FairPlayError {}

/// The FairPlay state of one control connection.
///
/// The handshake message is kept because the encrypted key cannot be decrypted without it.
/// One session serves one connection: two clients do not share a FairPlay exchange.
#[derive(Debug, Default)]
pub struct FairPlaySession {
    key_message: Option<[u8; HANDSHAKE_REQUEST_LEN]>,
}

impl FairPlaySession {
    /// A session that has not seen a handshake yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Answers the first `/fp-setup` request.
    ///
    /// The reply is selected by the mode byte and is fixed: it is the receiver's own FairPlay
    /// key material, not a value derived from the request.
    ///
    /// # Errors
    ///
    /// Returns [`FairPlayError::InvalidLength`] for a request that is not 16 bytes,
    /// [`FairPlayError::UnsupportedVersion`] for a version this receiver does not answer, and
    /// [`FairPlayError::InvalidMode`] for a mode outside the reply table.
    pub fn setup(&mut self, request: &[u8]) -> Result<[u8; SETUP_RESPONSE_LEN], FairPlayError> {
        require_len(request, SETUP_REQUEST_LEN)?;
        require_version(request)?;
        let mode = request[14];
        if mode > 3 {
            return Err(FairPlayError::InvalidMode(mode));
        }

        let start = usize::from(mode) * SETUP_RESPONSE_LEN;
        let mut response = [0u8; SETUP_RESPONSE_LEN];
        response.copy_from_slice(&REPLY_MESSAGES[start..start + SETUP_RESPONSE_LEN]);
        self.key_message = None;
        Ok(response)
    }

    /// Answers the 164-byte handshake and keeps it for [`FairPlaySession::decrypt`].
    ///
    /// # Errors
    ///
    /// Returns [`FairPlayError::InvalidLength`] for a request that is not 164 bytes and
    /// [`FairPlayError::UnsupportedVersion`] for a version this receiver does not answer.
    pub fn handshake(
        &mut self,
        request: &[u8],
    ) -> Result<[u8; HANDSHAKE_RESPONSE_LEN], FairPlayError> {
        require_len(request, HANDSHAKE_REQUEST_LEN)?;
        require_version(request)?;

        let mut key_message = [0u8; HANDSHAKE_REQUEST_LEN];
        key_message.copy_from_slice(request);
        self.key_message = Some(key_message);

        let mut response = [0u8; HANDSHAKE_RESPONSE_LEN];
        response[..FP_HEADER.len()].copy_from_slice(&FP_HEADER);
        response[FP_HEADER.len()..].copy_from_slice(&request[144..]);
        Ok(response)
    }

    /// Decrypts the 72-byte media key with the handshake message already received.
    ///
    /// # Errors
    ///
    /// Returns [`FairPlayError::InvalidLength`] for a key that is not 72 bytes,
    /// [`FairPlayError::HandshakeRequired`] when no handshake has been seen, and
    /// [`FairPlayError::DecryptionFailed`] when the PlayFair transform rejects the message.
    pub fn decrypt(&self, encrypted_key: &[u8]) -> Result<[u8; DECRYPTED_KEY_LEN], FairPlayError> {
        require_len(encrypted_key, ENCRYPTED_KEY_LEN)?;
        let message = self
            .key_message
            .as_ref()
            .ok_or(FairPlayError::HandshakeRequired)?;
        let mut cipher = [0u8; ENCRYPTED_KEY_LEN];
        cipher.copy_from_slice(encrypted_key);
        crate::playfair::playfair_decrypt(message, &cipher).ok_or(FairPlayError::DecryptionFailed)
    }

    /// Whether a handshake has been received on this connection.
    ///
    /// A client that sends its encrypted key without one is answered an error rather than a
    /// stream; this is the question a receiver asks before deciding how to answer.
    #[must_use]
    pub fn handshake_complete(&self) -> bool {
        self.key_message.is_some()
    }
}

fn require_len(input: &[u8], expected: usize) -> Result<(), FairPlayError> {
    if input.len() == expected {
        Ok(())
    } else {
        Err(FairPlayError::InvalidLength {
            expected,
            actual: input.len(),
        })
    }
}

fn require_version(input: &[u8]) -> Result<(), FairPlayError> {
    if input[4] == 0x03 {
        Ok(())
    } else {
        Err(FairPlayError::UnsupportedVersion(input[4]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_request(mode: u8) -> [u8; SETUP_REQUEST_LEN] {
        let mut request = [0u8; SETUP_REQUEST_LEN];
        request[4] = 0x03;
        request[14] = mode;
        request
    }

    #[test]
    fn setup_selects_fixed_reply_and_resets_handshake() {
        let mut session = FairPlaySession::new();
        let response = session.setup(&setup_request(2)).unwrap();
        assert_eq!(&response[..12], b"FPLY\x03\x01\x02\0\0\0\0\x82");
        assert!(!session.handshake_complete());
    }

    #[test]
    fn handshake_echoes_client_tail() {
        let mut session = FairPlaySession::new();
        let mut request = [0u8; HANDSHAKE_REQUEST_LEN];
        request[4] = 0x03;
        for (index, byte) in request[144..].iter_mut().enumerate() {
            *byte = index as u8;
        }

        let response = session.handshake(&request).unwrap();
        assert_eq!(&response[..12], &FP_HEADER);
        assert_eq!(&response[12..], &request[144..]);
        assert!(session.handshake_complete());
    }

    #[test]
    fn decrypts_key_after_handshake() {
        let mut session = FairPlaySession::new();
        let mut handshake = std::array::from_fn::<_, HANDSHAKE_REQUEST_LEN, _>(|index| {
            (index as u8).wrapping_mul(23).wrapping_add(9)
        });
        handshake[4] = 0x03;
        handshake[12] = 0;
        session.handshake(&handshake).unwrap();
        let cipher = std::array::from_fn::<_, ENCRYPTED_KEY_LEN, _>(|index| {
            (index as u8).wrapping_mul(31).wrapping_add(5)
        });
        assert_eq!(
            session.decrypt(&cipher).unwrap(),
            [
                0xb3, 0xa7, 0xf0, 0xcd, 0xaa, 0xc2, 0xfb, 0xeb, 0x9d, 0x67, 0x5a, 0x2e, 0xdc, 0x37,
                0xf1, 0xf1,
            ]
        );
    }

    #[test]
    fn decrypt_reports_transform_failure_separately_from_bad_mode() {
        let mut session = FairPlaySession::new();
        let mut handshake = [0u8; HANDSHAKE_REQUEST_LEN];
        handshake[4] = 0x03;
        // Byte 12 selects the PlayFair message mode; 4 is outside the four modes
        // UxPlay implements, so the transform must refuse the request.
        handshake[12] = 4;
        session.handshake(&handshake).unwrap();
        assert_eq!(
            session.decrypt(&[0u8; ENCRYPTED_KEY_LEN]),
            Err(FairPlayError::DecryptionFailed)
        );
    }

    #[test]
    fn rejects_invalid_state_and_lengths() {
        let mut session = FairPlaySession::new();
        assert_eq!(
            session.decrypt(&[0u8; ENCRYPTED_KEY_LEN]),
            Err(FairPlayError::HandshakeRequired)
        );
        assert!(matches!(
            session.setup(&[0u8; SETUP_REQUEST_LEN - 1]),
            Err(FairPlayError::InvalidLength { .. })
        ));
        assert_eq!(
            session.setup(&setup_request(4)),
            Err(FairPlayError::InvalidMode(4))
        );
        assert_eq!(
            session.setup(&{
                let mut request = setup_request(0);
                request[4] = 2;
                request
            }),
            Err(FairPlayError::UnsupportedVersion(2))
        );
    }
}
