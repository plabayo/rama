//! Algorithm-defined TLS 1.3 key-share encodings.

use crate::SupportedGroup;

impl SupportedGroup {
    /// Encoded client key-share length for groups modeled here.
    ///
    /// This describes the `key_exchange` bytes, excluding the group and vector
    /// length. `None` means the encoding is not modeled; it does not establish
    /// backend support. GREASE has no algorithm-defined length.
    ///
    /// Classical encodings follow [RFC 8446 section 4.2.8]; X25519MLKEM768
    /// follows [RFC 10024 section 4.1].
    ///
    /// [RFC 8446 section 4.2.8]: https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8
    /// [RFC 10024 section 4.1]: https://www.rfc-editor.org/rfc/rfc10024#section-4.1
    #[must_use]
    pub const fn tls13_client_key_share_len(self) -> Option<u16> {
        match self {
            // Uncompressed EC point: format byte, then the two coordinates.
            Self::SECP256R1 => Some(1 + 2 * 32),
            Self::SECP384R1 => Some(1 + 2 * 48),
            Self::SECP521R1 => Some(1 + 2 * 66),
            Self::X25519 => Some(32),
            Self::X448 => Some(56),
            // Finite-field DH public values are left-padded to the prime size.
            Self::FFDHE2048 => Some(2048 / 8),
            Self::FFDHE3072 => Some(3072 / 8),
            Self::FFDHE4096 => Some(4096 / 8),
            Self::FFDHE6144 => Some(6144 / 8),
            Self::FFDHE8192 => Some(8192 / 8),
            // ML-KEM-768 encapsulation key plus the X25519 public value.
            Self::X25519MLKEM768 => Some(1184 + 32),
            _ => None,
        }
    }
}
