//! HTTP Message Signature cryptography (RFC 9421 §3.3).
//!
//! Provides [`HttpMessageSigner`] / [`HttpMessageVerifier`] and concrete
//! key types for the registered algorithms used by rama.

use aws_lc_rs::{
    hmac,
    rand::SystemRandom,
    signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
};
use rama_core::error::{BoxError, BoxErrorExt as _, ErrorContext as _};

use crate::jose::{EcdsaKey, JWA, RsaKey, Signer};

/// Algorithm identifier strings from the HTTP Signature Algorithms registry.
pub mod alg {
    pub const ED25519: &str = "ed25519";
    pub const HMAC_SHA256: &str = "hmac-sha256";
    pub const ECDSA_P256_SHA256: &str = "ecdsa-p256-sha256";
    pub const RSA_V1_5_SHA256: &str = "rsa-v1_5-sha256";
    pub const RSA_PSS_SHA512: &str = "rsa-pss-sha512";
}

/// Sign an HTTP message signature base.
pub trait HttpMessageSigner: Send + Sync {
    /// RFC 9421 `alg` parameter value for this key.
    fn algorithm(&self) -> &'static str;

    /// Sign the signature base bytes, returning the raw signature.
    fn sign_message(&self, data: &[u8]) -> Result<Vec<u8>, BoxError>;
}

/// Verify an HTTP message signature.
pub trait HttpMessageVerifier: Send + Sync {
    /// RFC 9421 `alg` parameter value this verifier accepts.
    fn algorithm(&self) -> &'static str;

    /// Verify `signature` over the signature base bytes.
    fn verify_message(&self, data: &[u8], signature: &[u8]) -> Result<(), BoxError>;
}

// --- Ed25519 ---

/// Ed25519 signing key for `alg=ed25519`.
#[derive(Debug)]
pub struct Ed25519SigningKey {
    inner: Ed25519KeyPair,
}

impl Ed25519SigningKey {
    /// Generate a new Ed25519 key pair.
    pub fn generate() -> Result<Self, BoxError> {
        let inner = Ed25519KeyPair::generate().context("generate Ed25519 key")?;
        Ok(Self { inner })
    }

    /// Load from a 32-byte seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self, BoxError> {
        let inner = Ed25519KeyPair::from_seed_unchecked(seed).context("Ed25519 from seed")?;
        Ok(Self { inner })
    }

    /// Load from PKCS#8 DER.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, BoxError> {
        let inner = Ed25519KeyPair::from_pkcs8(pkcs8).context("Ed25519 from pkcs8")?;
        Ok(Self { inner })
    }

    /// Public key bytes (32 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        self.inner.public_key().as_ref()
    }

    /// Verifier for this key's public half.
    #[must_use]
    pub fn verifier(&self) -> Ed25519VerifyingKey {
        Ed25519VerifyingKey::from_public_key_bytes(self.public_key_bytes())
    }
}

impl HttpMessageSigner for Ed25519SigningKey {
    fn algorithm(&self) -> &'static str {
        alg::ED25519
    }

    fn sign_message(&self, data: &[u8]) -> Result<Vec<u8>, BoxError> {
        Ok(self.inner.sign(data).as_ref().to_vec())
    }
}

/// Ed25519 verifying key for `alg=ed25519`.
#[derive(Debug, Clone)]
pub struct Ed25519VerifyingKey {
    public_key: Vec<u8>,
}

impl Ed25519VerifyingKey {
    #[must_use]
    pub fn from_public_key_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            public_key: bytes.into(),
        }
    }
}

impl HttpMessageVerifier for Ed25519VerifyingKey {
    fn algorithm(&self) -> &'static str {
        alg::ED25519
    }

    fn verify_message(&self, data: &[u8], signature: &[u8]) -> Result<(), BoxError> {
        let key = UnparsedPublicKey::new(&ED25519, &self.public_key);
        key.verify(data, signature)
            .map_err(|_err| BoxError::from_static_str("ed25519 signature verification failed"))
    }
}

// --- HMAC-SHA256 ---

/// HMAC-SHA256 key for `alg=hmac-sha256`.
#[derive(Debug)]
pub struct HmacSha256Key {
    key: hmac::Key,
}

impl HmacSha256Key {
    /// Create from raw key bytes.
    #[must_use]
    pub fn new(key_bytes: &[u8]) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, key_bytes),
        }
    }

    /// Generate a random 32-byte key.
    pub fn generate() -> Result<Self, BoxError> {
        let key = hmac::Key::generate(hmac::HMAC_SHA256, &SystemRandom::new())
            .context("generate HMAC-SHA256 key")?;
        Ok(Self { key })
    }
}

impl HttpMessageSigner for HmacSha256Key {
    fn algorithm(&self) -> &'static str {
        alg::HMAC_SHA256
    }

    fn sign_message(&self, data: &[u8]) -> Result<Vec<u8>, BoxError> {
        Ok(hmac::sign(&self.key, data).as_ref().to_vec())
    }
}

impl HttpMessageVerifier for HmacSha256Key {
    fn algorithm(&self) -> &'static str {
        alg::HMAC_SHA256
    }

    fn verify_message(&self, data: &[u8], signature: &[u8]) -> Result<(), BoxError> {
        hmac::verify(&self.key, data, signature)
            .map_err(|_err| BoxError::from_static_str("hmac-sha256 verification failed"))
    }
}

// --- ECDSA P-256 (reuses JOSE EcdsaKey) ---

/// Adapter: [`EcdsaKey`] (ES256) as HTTP message signer (`ecdsa-p256-sha256`).
pub struct EcdsaP256Sha256Signer {
    key: EcdsaKey,
}

impl EcdsaP256Sha256Signer {
    pub fn new(key: EcdsaKey) -> Result<Self, BoxError> {
        if key.alg() != JWA::ES256 {
            return Err(BoxError::from_static_str(
                "EcdsaP256Sha256Signer requires JWA::ES256",
            ));
        }
        Ok(Self { key })
    }

    pub fn generate() -> Result<Self, BoxError> {
        Self::new(EcdsaKey::generate()?)
    }

    #[must_use]
    pub fn inner(&self) -> &EcdsaKey {
        &self.key
    }
}

impl HttpMessageSigner for EcdsaP256Sha256Signer {
    fn algorithm(&self) -> &'static str {
        alg::ECDSA_P256_SHA256
    }

    fn sign_message(&self, data: &[u8]) -> Result<Vec<u8>, BoxError> {
        // Signature base is ASCII; JOSE Signer takes &str
        let s = std::str::from_utf8(data).context("signature base must be UTF-8")?;
        let sig = self.key.sign(s)?;
        Ok(sig.as_ref().to_vec())
    }
}

/// ECDSA P-256 verifying key from a JWK / raw public key.
pub struct EcdsaP256Sha256Verifier {
    key: UnparsedPublicKey<Vec<u8>>,
}

impl EcdsaP256Sha256Verifier {
    pub fn from_jwk(jwk: &crate::jose::JWK) -> Result<Self, BoxError> {
        Ok(Self {
            key: jwk.unparsed_public_key()?,
        })
    }
}

impl HttpMessageVerifier for EcdsaP256Sha256Verifier {
    fn algorithm(&self) -> &'static str {
        alg::ECDSA_P256_SHA256
    }

    fn verify_message(&self, data: &[u8], signature: &[u8]) -> Result<(), BoxError> {
        self.key
            .verify(data, signature)
            .map_err(|_err| BoxError::from_static_str("ecdsa-p256-sha256 verification failed"))
    }
}

// --- RSA (reuses JOSE RsaKey) ---

/// Adapter: [`RsaKey`] as HTTP message signer.
pub struct RsaHttpSigner {
    key: RsaKey,
    algorithm: &'static str,
}

impl RsaHttpSigner {
    pub fn rsa_v1_5_sha256(key: RsaKey) -> Result<Self, BoxError> {
        if key.create_jwk().alg != JWA::RS256 {
            return Err(BoxError::from_static_str(
                "RsaHttpSigner::rsa_v1_5_sha256 requires a JWA::RS256 key",
            ));
        }
        Ok(Self {
            key,
            algorithm: alg::RSA_V1_5_SHA256,
        })
    }

    pub fn rsa_pss_sha512(key: RsaKey) -> Result<Self, BoxError> {
        if key.create_jwk().alg != JWA::PS512 {
            return Err(BoxError::from_static_str(
                "RsaHttpSigner::rsa_pss_sha512 requires a JWA::PS512 key",
            ));
        }
        Ok(Self {
            key,
            algorithm: alg::RSA_PSS_SHA512,
        })
    }

    pub fn generate_rsa_v1_5_sha256(key_size: aws_lc_rs::rsa::KeySize) -> Result<Self, BoxError> {
        let key = RsaKey::try_new(
            aws_lc_rs::signature::RsaKeyPair::generate(key_size).context("generate RSA key")?,
            JWA::RS256,
            SystemRandom::new(),
        )?;
        Self::rsa_v1_5_sha256(key)
    }

    pub fn generate_rsa_pss_sha512(key_size: aws_lc_rs::rsa::KeySize) -> Result<Self, BoxError> {
        let key = RsaKey::try_new(
            aws_lc_rs::signature::RsaKeyPair::generate(key_size).context("generate RSA key")?,
            JWA::PS512,
            SystemRandom::new(),
        )?;
        Self::rsa_pss_sha512(key)
    }

    #[must_use]
    pub fn inner(&self) -> &RsaKey {
        &self.key
    }
}

impl HttpMessageSigner for RsaHttpSigner {
    fn algorithm(&self) -> &'static str {
        self.algorithm
    }

    fn sign_message(&self, data: &[u8]) -> Result<Vec<u8>, BoxError> {
        let s = std::str::from_utf8(data).context("signature base must be UTF-8")?;
        self.key.sign(s)
    }
}

/// RSA verifying key from a JWK.
pub struct RsaHttpVerifier {
    key: UnparsedPublicKey<Vec<u8>>,
    algorithm: &'static str,
}

impl RsaHttpVerifier {
    pub fn rsa_v1_5_sha256(jwk: &crate::jose::JWK) -> Result<Self, BoxError> {
        if jwk.alg != JWA::RS256 {
            return Err(BoxError::from_static_str(
                "RsaHttpVerifier::rsa_v1_5_sha256 requires a JWA::RS256 JWK",
            ));
        }
        Ok(Self {
            key: jwk.unparsed_public_key()?,
            algorithm: alg::RSA_V1_5_SHA256,
        })
    }

    pub fn rsa_pss_sha512(jwk: &crate::jose::JWK) -> Result<Self, BoxError> {
        if jwk.alg != JWA::PS512 {
            return Err(BoxError::from_static_str(
                "RsaHttpVerifier::rsa_pss_sha512 requires a JWA::PS512 JWK",
            ));
        }
        Ok(Self {
            key: jwk.unparsed_public_key()?,
            algorithm: alg::RSA_PSS_SHA512,
        })
    }
}

impl HttpMessageVerifier for RsaHttpVerifier {
    fn algorithm(&self) -> &'static str {
        self.algorithm
    }

    fn verify_message(&self, data: &[u8], signature: &[u8]) -> Result<(), BoxError> {
        self.key.verify(data, signature).map_err(|_err| {
            BoxError::from_static_str("rsa http message signature verification failed")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_round_trip() {
        let signer = Ed25519SigningKey::generate().unwrap();
        let verifier = signer.verifier();
        let data = b"\"@method\": GET\n\"@signature-params\": (\"@method\")";
        let sig = signer.sign_message(data).unwrap();
        verifier.verify_message(data, &sig).unwrap();
        assert!(verifier.verify_message(b"tampered", &sig).is_err());
    }

    #[test]
    fn hmac_round_trip() {
        let key = HmacSha256Key::new(b"secret-key-material-32bytes-long!!");
        let data = b"signature-base";
        let sig = key.sign_message(data).unwrap();
        key.verify_message(data, &sig).unwrap();
        assert!(key.verify_message(b"nope", &sig).is_err());
    }

    #[test]
    fn ecdsa_p256_round_trip() {
        let signer = EcdsaP256Sha256Signer::generate().unwrap();
        let jwk = signer.inner().create_jwk();
        let verifier = EcdsaP256Sha256Verifier::from_jwk(&jwk).unwrap();
        let data = b"\"@method\": POST\n\"@signature-params\": (\"@method\")";
        let sig = signer.sign_message(data).unwrap();
        verifier.verify_message(data, &sig).unwrap();
    }
}
