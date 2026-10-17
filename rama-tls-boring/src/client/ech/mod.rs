//! ECH GREASE shape controls for client connections.
//!
//! Shapes contain algorithms and lengths. BoringSSL generates new cryptographic
//! material for each connection; no captured keys or ciphertext are configured.

use rama_boring::ssl::EchGreaseShape;
use rama_core::{
    error::{BoxError, ErrorContext as _},
    extensions::Extension,
};
use rama_tls::client::TlsPoolComponent;

/// Shape of an ECH GREASE extension, applied independently of its enable switch.
///
/// Invalid shapes are rejected when building the connector, before it writes a
/// ClientHello. TLS 1.3 and [`super::BoringClientConfigExt::set_encrypted_client_hello`] must
/// also be enabled. A usable real ECH configuration takes precedence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Extension)]
#[extension(tags(tls))]
pub enum EchGrease {
    /// Use the provider's randomized lengths and hardware-dependent algorithms.
    /// Explicitly selecting this also overrides a shape inherited from a base config.
    #[default]
    Native,
    /// Reproduce retained ECH outer metadata using fresh encapsulation and payload.
    Shape {
        /// HPKE KDF identifier; the provider currently supports HKDF-SHA256 (1).
        kdf_id: u16,
        /// HPKE AEAD identifier: AES-128-GCM (1), AES-256-GCM (2) or ChaCha20-Poly1305 (3).
        aead_id: u16,
        /// Encapsulated key length in bytes; X25519 requires 32.
        encapsulated_key_len: usize,
        /// Encrypted payload length in bytes, including the authentication tag.
        payload_len: usize,
    },
}

impl EchGrease {
    pub(super) fn native_shape(self) -> Result<Option<EchGreaseShape>, BoxError> {
        match self {
            Self::Native => Ok(None),
            Self::Shape {
                kdf_id,
                aead_id,
                encapsulated_key_len,
                payload_len,
            } => EchGreaseShape::from_wire(kdf_id, aead_id, encapsulated_key_len, payload_len)
                .map(Some)
                .context("unsupported ECH GREASE shape"),
        }
    }
}

impl TlsPoolComponent for EchGrease {
    type Identity = Self;

    fn pool_component_identity(&self) -> Self {
        *self
    }
}

#[cfg(test)]
mod tests;
