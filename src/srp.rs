// SPDX-License-Identifier: GPL-3.0-or-later
//! Apple-compatible SRP-6a primitives used by AirPlay pair-setup.
//!
//! AirPlay uses the 2048-bit RFC 5054 group with SHA-1, but keeps the older Apple session-key
//! expansion: `SHA-1(S || 0u32)` concatenated with `SHA-1(S || 1u32)`. The public API keeps
//! the byte serialization rules explicit because they are part of the wire compatibility
//! contract: the same integers encoded with or without leading zero bytes produce different
//! hashes, and therefore a different key on the two sides.
//!
//! [`AppleSrpServer`] is the receiver's half of the exchange: it produces `B`, and given the
//! client's public value it derives the session key, checks the client's proof and produces
//! the receiver's own proof. It does not choose the salt, the verifier or the private scalar;
//! those are inputs, because where a password verifier lives is the caller's decision.

use std::sync::OnceLock;

use num_bigint::BigUint;
use num_traits::Zero;
use sha1::{Digest, Sha1};

/// Size of the session key the Apple exchange derives: two SHA-1 digests.
pub const APPLE_SESSION_KEY_SIZE: usize = 40;
/// Size of one SHA-1 digest, which is the size of every proof and hash in this module.
pub const APPLE_SRP_HASH_SIZE: usize = 20;
/// Size of the 2048-bit SRP modulus in bytes.
pub const APPLE_SRP_MODULUS_SIZE: usize = 256;
/// Size of the salt a verifier is derived with.
pub const APPLE_SRP_SALT_SIZE: usize = 16;

const MODULUS_HEX: &str = concat!(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050",
    "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50",
    "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8",
    "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773",
    "BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748",
    "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6",
    "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6",
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
);

static MODULUS: OnceLock<BigUint> = OnceLock::new();

/// Why an SRP value was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrpError {
    /// A value had the wrong size: a salt, a public key or an integer too large for the group.
    InvalidLength(&'static str),
    /// A value had the right size but is outside the group: zero, or a multiple of the
    /// modulus.
    InvalidValue(&'static str),
}

impl std::fmt::Display for SrpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength(name) => write!(f, "invalid length for {name}"),
            Self::InvalidValue(name) => write!(f, "invalid value for {name}"),
        }
    }
}

impl std::error::Error for SrpError {}

fn modulus() -> &'static BigUint {
    MODULUS.get_or_init(|| BigUint::parse_bytes(MODULUS_HEX.as_bytes(), 16).unwrap())
}

fn minimal_bytes(value: &BigUint) -> Vec<u8> {
    value.to_bytes_be()
}

fn padded_modulus_bytes(value: &BigUint) -> Result<[u8; APPLE_SRP_MODULUS_SIZE], SrpError> {
    let bytes = minimal_bytes(value);
    if bytes.len() > APPLE_SRP_MODULUS_SIZE {
        return Err(SrpError::InvalidLength("SRP integer"));
    }
    let mut output = [0u8; APPLE_SRP_MODULUS_SIZE];
    output[APPLE_SRP_MODULUS_SIZE - bytes.len()..].copy_from_slice(&bytes);
    Ok(output)
}

fn hash(parts: &[&[u8]]) -> [u8; APPLE_SRP_HASH_SIZE] {
    let mut digest = Sha1::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}

fn hash_number(value: &BigUint) -> [u8; APPLE_SRP_HASH_SIZE] {
    hash(&[&minimal_bytes(value)])
}

fn hash_padded_pair(left: &BigUint, right: &BigUint) -> Result<BigUint, SrpError> {
    let left = padded_modulus_bytes(left)?;
    let right = padded_modulus_bytes(right)?;
    Ok(BigUint::from_bytes_be(&hash(&[&left, &right])))
}

fn session_key_from_secret(secret: &BigUint) -> [u8; APPLE_SESSION_KEY_SIZE] {
    apple_session_key(&minimal_bytes(secret))
}

fn derive_verifier(username: &[u8], password: &[u8], salt: &[u8]) -> BigUint {
    let identity_password = hash(&[username, b":", password]);
    let x = BigUint::from_bytes_be(&hash(&[salt, &identity_password]));
    BigUint::from(2u8).modpow(&x, modulus())
}

fn proof(
    username: &[u8],
    salt: &[u8],
    client_public: &BigUint,
    server_public: &BigUint,
    session_key: &[u8; APPLE_SESSION_KEY_SIZE],
) -> [u8; APPLE_SRP_HASH_SIZE] {
    let n_hash = hash_number(modulus());
    let g_hash = hash_number(&BigUint::from(2u8));
    let identity_hash = hash(&[username]);
    let xor: [u8; APPLE_SRP_HASH_SIZE] = std::array::from_fn(|index| n_hash[index] ^ g_hash[index]);
    hash(&[
        &xor,
        &identity_hash,
        salt,
        &minimal_bytes(client_public),
        &minimal_bytes(server_public),
        session_key,
    ])
}

fn server_proof(
    client_public: &BigUint,
    client_proof: &[u8; APPLE_SRP_HASH_SIZE],
    session_key: &[u8; APPLE_SESSION_KEY_SIZE],
) -> [u8; APPLE_SRP_HASH_SIZE] {
    hash(&[&minimal_bytes(client_public), client_proof, session_key])
}

/// Derives the Apple session key from the premaster secret.
///
/// This is not the RFC 5054 key derivation: Apple hashes the premaster secret twice, with a
/// four-byte counter of zero and one appended, and concatenates the two digests. A client that
/// implements the RFC instead fails at the proof with no other symptom.
#[must_use]
pub fn apple_session_key(premaster_secret_be: &[u8]) -> [u8; APPLE_SESSION_KEY_SIZE] {
    let mut output = [0u8; APPLE_SESSION_KEY_SIZE];
    let first = hash(&[premaster_secret_be, &[0, 0, 0, 0]]);
    let second = hash(&[premaster_secret_be, &[0, 0, 0, 1]]);
    output[..APPLE_SRP_HASH_SIZE].copy_from_slice(&first);
    output[APPLE_SRP_HASH_SIZE..].copy_from_slice(&second);
    output
}

/// Derives a labelled key from the session key.
///
/// Each pairing step hashes its label in front of the session key
///, which is how one exchange yields several
/// independent keys without a second handshake.
#[must_use]
pub fn apple_proof_key(
    session_key: &[u8; APPLE_SESSION_KEY_SIZE],
    label: &[u8],
) -> [u8; APPLE_SRP_HASH_SIZE] {
    hash(&[label, session_key])
}

/// The receiver's half of one SRP exchange.
///
/// It holds the username, salt, verifier and private scalar; every method is `&self`, so one
/// server value answers both steps of the exchange. The private scalar is the caller's
/// randomness and must not be reused across exchanges.
#[derive(Debug)]
pub struct AppleSrpServer {
    username: Vec<u8>,
    salt: [u8; APPLE_SRP_SALT_SIZE],
    verifier: BigUint,
    private_b: BigUint,
}

/// What the receiver sends, and what it checks, in the second step of the exchange.
#[derive(Debug)]
pub struct AppleSrpResponse {
    /// The receiver's public value `B`, in the minimal encoding Apple uses.
    pub public_key: Vec<u8>,
    /// The shared session key both sides derive.
    pub session_key: [u8; APPLE_SESSION_KEY_SIZE],
    /// The proof the client must send; compare it with [`constant_time_proof_eq`].
    pub expected_proof: [u8; APPLE_SRP_HASH_SIZE],
    /// The proof the receiver sends back, which the client checks.
    pub server_proof: [u8; APPLE_SRP_HASH_SIZE],
}

impl AppleSrpServer {
    /// Builds a server from a password, deriving the verifier with Apple's rules.
    ///
    /// # Errors
    ///
    /// Returns [`SrpError::InvalidLength`] for a salt that is not 16 bytes or a private scalar
    /// too large for the group, and [`SrpError::InvalidValue`] for a zero scalar or a verifier
    /// outside the group.
    pub fn new(
        username: &[u8],
        password: &[u8],
        salt: &[u8],
        private_b: &[u8],
    ) -> Result<Self, SrpError> {
        let salt: [u8; APPLE_SRP_SALT_SIZE] = salt
            .try_into()
            .map_err(|_| SrpError::InvalidLength("SRP salt"))?;
        let verifier = derive_verifier(username, password, &salt);
        Self::from_verifier(username, &verifier.to_bytes_be(), &salt, private_b)
    }

    /// Builds a server from an already derived verifier.
    ///
    /// A caller that stores the verifier instead of the password uses this; the verifier is
    /// what a long-term pairing record keeps.
    ///
    /// # Errors
    ///
    /// Returns [`SrpError::InvalidValue`] for a zero private scalar or a verifier that is zero
    /// or not smaller than the modulus.
    pub fn from_verifier(
        username: &[u8],
        verifier: &[u8],
        salt: &[u8; APPLE_SRP_SALT_SIZE],
        private_b: &[u8],
    ) -> Result<Self, SrpError> {
        let private_b = BigUint::from_bytes_be(private_b);
        if private_b.is_zero() {
            return Err(SrpError::InvalidValue("SRP private b"));
        }
        let verifier = BigUint::from_bytes_be(verifier);
        if verifier.is_zero() || verifier >= *modulus() {
            return Err(SrpError::InvalidValue("SRP verifier"));
        }
        Ok(Self {
            username: username.to_vec(),
            salt: *salt,
            verifier,
            private_b,
        })
    }

    /// Server public value `B = k*v + g^b` in the minimal encoding Apple uses.
    ///
    /// `/pair-setup-pin` answers its first step with `B` before the client sends
    /// its own public value, so a
    /// server has to be able to produce `B` on its own. The value does not
    /// depend on the client's public value.
    pub fn server_public(&self) -> Result<Vec<u8>, SrpError> {
        Ok(minimal_bytes(&self.server_public_value()?))
    }

    fn server_public_value(&self) -> Result<BigUint, SrpError> {
        let n = modulus();
        let generator = BigUint::from(2u8);
        let multiplier = hash_padded_pair(n, &generator)?;
        let generator_b = generator.modpow(&self.private_b, n);
        Ok(((&multiplier * &self.verifier) + generator_b) % n)
    }

    /// Answers the client's public value with the receiver's proof.
    ///
    /// # Errors
    ///
    /// Returns [`SrpError::InvalidLength`] for a client public key that is empty or larger
    /// than the group, and [`SrpError::InvalidValue`] for one that is zero or a multiple of
    /// the modulus (neither of which has a usable shared secret).
    pub fn respond(&self, client_public_bytes: &[u8]) -> Result<AppleSrpResponse, SrpError> {
        // Apple sends the client public key as one 2048-bit Data block; reject an
        // empty or oversized value before it reaches the big-integer math.
        if client_public_bytes.is_empty() || client_public_bytes.len() > APPLE_SRP_MODULUS_SIZE {
            return Err(SrpError::InvalidLength("SRP client public key"));
        }
        let n = modulus();
        let client_public = BigUint::from_bytes_be(client_public_bytes);
        if client_public.is_zero() || (&client_public % n).is_zero() {
            return Err(SrpError::InvalidValue("SRP client public key"));
        }

        let server_public = self.server_public_value()?;
        let scrambling = hash_padded_pair(&client_public, &server_public)?;
        let verifier_power = self.verifier.modpow(&scrambling, n);
        let premaster = (&client_public * verifier_power).modpow(&self.private_b, n);
        let session_key = session_key_from_secret(&premaster);
        let expected_proof = proof(
            &self.username,
            &self.salt,
            &client_public,
            &server_public,
            &session_key,
        );
        let server_proof = server_proof(&client_public, &expected_proof, &session_key);

        Ok(AppleSrpResponse {
            public_key: minimal_bytes(&server_public),
            session_key,
            expected_proof,
            server_proof,
        })
    }
}

/// Compares a proof with the expected one without an early exit.
///
/// Equal-length inputs take the same time whether they match or not. An input of a different
/// length is a `false` without a comparison, which is a length leak an attacker already knows.
#[must_use]
pub fn constant_time_proof_eq(expected: &[u8; APPLE_SRP_HASH_SIZE], actual: &[u8]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    let mut difference = 0u8;
    for (expected, actual) in expected.iter().zip(actual) {
        difference |= expected ^ actual;
    }
    difference == 0
}

/// Deterministic SRP client used by the pairing tests of this crate.
///
/// It computes what Apple's client computes for `/pair-setup-pin`, from a fixed
/// private value, so the tests of the control service can drive the server
/// without a second copy of the group, the hashing rules or the proof layout.
#[cfg(test)]
pub(crate) mod test_client {
    use super::*;

    /// Client side of one exchange.
    pub(crate) struct Exchange {
        /// Public value `A` the client sends in step 2.
        pub(crate) public_key: Vec<u8>,
        /// Proof `M` the client sends in step 2.
        pub(crate) proof: [u8; APPLE_SRP_HASH_SIZE],
        /// Server proof `M2` the client expects in the reply of step 2.
        pub(crate) server_proof: [u8; APPLE_SRP_HASH_SIZE],
        /// Session key both sides derive.
        pub(crate) session_key: [u8; APPLE_SESSION_KEY_SIZE],
    }

    /// Runs the client side of one exchange against the server public value of
    /// step 1.
    pub(crate) fn exchange(
        username: &[u8],
        password: &[u8],
        salt: &[u8],
        private_a: &[u8; 32],
        server_public: &[u8],
    ) -> Exchange {
        let private_a = BigUint::from_bytes_be(private_a);
        let client_public = BigUint::from(2u8).modpow(&private_a, modulus());
        let server_public_value = BigUint::from_bytes_be(server_public);
        let x = BigUint::from_bytes_be(&hash(&[salt, &hash(&[username, b":", password])]));
        let verifier = BigUint::from(2u8).modpow(&x, modulus());
        let scrambling =
            hash_padded_pair(&client_public, &server_public_value).expect("scrambling value");
        let multiplier = hash_padded_pair(modulus(), &BigUint::from(2u8)).expect("multiplier");
        let kv = (&multiplier * verifier) % modulus();
        let base = (&server_public_value + modulus() - kv) % modulus();
        let exponent = &private_a + scrambling * x;
        let client_secret = base.modpow(&exponent, modulus());
        let session_key = session_key_from_secret(&client_secret);
        let proof = proof(
            username,
            salt,
            &client_public,
            &server_public_value,
            &session_key,
        );
        Exchange {
            public_key: minimal_bytes(&client_public),
            proof,
            server_proof: server_proof(&client_public, &proof, &session_key),
            session_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn expands_secret_to_two_apple_blocks() {
        let key = apple_session_key(&[1, 2, 3]);
        assert_eq!(key.len(), APPLE_SESSION_KEY_SIZE);
        assert_ne!(&key[..20], &key[20..]);
    }

    #[test]
    fn respond_rejects_missing_or_oversized_client_public_key() {
        let server = AppleSrpServer::new(
            b"AA:BB:CC:DD:EE:FF",
            b"1234",
            &[0; APPLE_SRP_SALT_SIZE],
            &[0x02; 32],
        )
        .unwrap();
        assert!(matches!(
            server.respond(&[]),
            Err(SrpError::InvalidLength("SRP client public key"))
        ));
        assert!(matches!(
            server.respond(&[0x02; APPLE_SRP_MODULUS_SIZE + 1]),
            Err(SrpError::InvalidLength("SRP client public key"))
        ));
        assert!(matches!(
            server.respond(&[0; APPLE_SRP_MODULUS_SIZE]),
            Err(SrpError::InvalidValue("SRP client public key"))
        ));
    }

    #[test]
    fn server_public_value_does_not_depend_on_the_client() {
        let server = AppleSrpServer::new(
            b"AA:BB:CC:DD:EE:FF",
            b"1234",
            &[0x01; APPLE_SRP_SALT_SIZE],
            &[0x02; 32],
        )
        .unwrap();
        let standalone = server.server_public().unwrap();
        let response = server
            .respond(&minimal_bytes(
                &BigUint::from(2u8).modpow(&BigUint::from_bytes_be(&[0x03; 32]), modulus()),
            ))
            .unwrap();
        // `/pair-setup-pin` step 1 answers with `B` before the client sends `A`,
        // so both paths have to produce the same value.
        assert_eq!(standalone, response.public_key);
        assert!(!standalone.is_empty());
        assert!(standalone.len() <= APPLE_SRP_MODULUS_SIZE);
    }

    #[test]
    fn completes_apple_srp_server_exchange() {
        let username = b"AA:BB:CC:DD:EE:FF";
        let password = b"1234";
        let salt: [u8; APPLE_SRP_SALT_SIZE] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let private_a = BigUint::from_bytes_be(&[0x03; 32]);
        let client_public = BigUint::from(2u8).modpow(&private_a, modulus());
        let server = AppleSrpServer::new(username, password, &salt, &[0x02; 32]).unwrap();
        let response = server.respond(&minimal_bytes(&client_public)).unwrap();

        let server_public = BigUint::from_bytes_be(&response.public_key);
        let x = BigUint::from_bytes_be(&hash(&[&salt, &hash(&[username, b":", password])]));
        let verifier = BigUint::from(2u8).modpow(&x, modulus());
        let scrambling = hash_padded_pair(&client_public, &server_public).unwrap();
        let k = hash_padded_pair(modulus(), &BigUint::from(2u8)).unwrap();
        let kv = (&k * verifier) % modulus();
        let base = (&server_public + modulus() - kv) % modulus();
        let exponent = &private_a + scrambling * x;
        let client_secret = base.modpow(&exponent, modulus());
        let client_session_key = session_key_from_secret(&client_secret);
        let client_proof = proof(
            username,
            &salt,
            &client_public,
            &server_public,
            &client_session_key,
        );

        assert_eq!(response.session_key, client_session_key);
        assert_eq!(response.expected_proof, client_proof);
        assert!(constant_time_proof_eq(
            &response.expected_proof,
            &client_proof
        ));
        // Vectors captured from an AirPlay SRP implementation with the same inputs.
        assert_eq!(
            hex(&response.public_key),
            "0132837009606bffe01477859648105a1a817354d8c1ac8d59ecb8fed84c435fe7e3ce97db6ebd3b5ea6f18647a875a4611a9e093df90c87c4c1d780d7c7069210759dd01a4a1f172a849ce346431132a51ffb950ebff1798f95c0bb97abdd2331b364aef4efd79abf573c3e094f48b4db2c8b2f9a0d4bc29b19bad030e8922f9f9628d3032848e3f5b92114dfd148c1a720181504828309cab2682bb1ba8d773078184ac1295d957ebf5858b21a2d9eba81f630d005a574fa71889b5da89bfe8d68042b8c9ca5b2296ce64adf7c2dc7c7390c566212434360a6e6474dddc5cf37c9de08043fa20a8d73d91c205259d449e419c94c5d33b472b10e73ad6ab570"
        );
        assert_eq!(
            hex(&response.session_key),
            "76be16971b769c905ff2db54b5194a6c4d289fb01b4aa2360a0a2b61b1e684430807d6023b90d231"
        );
        assert_eq!(
            hex(&response.expected_proof),
            "c3a0d4dd23073968a60337eec134af246fdfa986"
        );
        assert_eq!(
            hex(&response.server_proof),
            "7c410e701a244f6bd8d04f5aa12276a504d87bd8"
        );
        assert_eq!(
            hex(&response.server_proof),
            hex(&server_proof(
                &client_public,
                &client_proof,
                &client_session_key
            ))
        );
    }
}
