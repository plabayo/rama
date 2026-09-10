use std::{fmt, sync::Arc};

#[cfg(all(feature = "aws-lc", not(feature = "ring")))]
use rama_crypto::dep::aws_lc_rs::{hkdf, hmac};
#[cfg(feature = "ring")]
use rama_crypto::dep::ring::{hkdf, hmac};

use crate::proto::{
    config::ConfigError,
    crypto::{HandshakeTokenKey, HmacKey},
};

/// Bytes of key material both key types take as a seed, and the fewest either accepts.
pub const KEY_MATERIAL_SIZE: usize = 32;

/// The key an endpoint derives the stateless reset tokens it issues from (RFC 9000 §10.3).
///
/// An endpoint gives a peer a token per connection ID, and the peer recognises a stateless
/// reset by that token. Endpoints holding the same key derive the same token for the same
/// connection ID, so a peer of one of them recognises a reset from another: that is how a
/// restarted process, or another endpoint of the same service, can reset a connection whose
/// state it does not have. An endpoint given no key generates one, which no other endpoint
/// holds. Whatever keeps the material between restarts has to keep it secret.
///
/// The material is derived with HMAC-SHA256 whichever provider is compiled in, so the same
/// bytes give the same tokens on all of them.
#[derive(Clone)]
pub struct StatelessResetKey(Arc<dyn HmacKey>);

impl StatelessResetKey {
    /// Construct a key from a seed of [`KEY_MATERIAL_SIZE`] bytes.
    #[must_use]
    pub fn from_seed(seed: &[u8; KEY_MATERIAL_SIZE]) -> Self {
        Self(Arc::new(hmac::Key::new(hmac::HMAC_SHA256, seed)))
    }

    /// Construct a key from at least [`KEY_MATERIAL_SIZE`] bytes of secret material. Longer
    /// material is used as it is; what the key is worth is the entropy in it.
    ///
    /// Fails when the material is shorter than that.
    pub fn try_from_bytes(material: &[u8]) -> Result<Self, ConfigError> {
        if material.len() < KEY_MATERIAL_SIZE {
            return Err(ConfigError::KeyMaterialTooShort);
        }
        Ok(Self(Arc::new(hmac::Key::new(hmac::HMAC_SHA256, material))))
    }

    pub(crate) fn into_key(self) -> Arc<dyn HmacKey> {
        self.0
    }
}

impl fmt::Debug for StatelessResetKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StatelessResetKey")
    }
}

/// The key a server seals address-validation tokens with (RFC 9000 §8.1).
///
/// Retry tokens and the tokens sent in NEW_TOKEN frames are sealed with it, so servers holding
/// the same key can read one another's, as can a server that keeps its key across a restart.
/// Reading a token is not accepting it: the address it was issued for, its lifetime and, for a
/// NEW_TOKEN token, whether it has been seen before all still decide. A server given no key
/// generates one. The same secrecy applies as for [`StatelessResetKey`].
///
/// The material is derived with HKDF-SHA256 whichever provider is compiled in.
#[derive(Clone)]
pub struct AddressTokenKey(Arc<dyn HandshakeTokenKey>);

impl AddressTokenKey {
    /// Construct a key from a seed of [`KEY_MATERIAL_SIZE`] bytes.
    #[must_use]
    pub fn from_seed(seed: &[u8; KEY_MATERIAL_SIZE]) -> Self {
        Self(Arc::new(
            hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(seed),
        ))
    }

    /// Construct a key from at least [`KEY_MATERIAL_SIZE`] bytes of secret material.
    ///
    /// Fails when the material is shorter than that.
    pub fn try_from_bytes(material: &[u8]) -> Result<Self, ConfigError> {
        if material.len() < KEY_MATERIAL_SIZE {
            return Err(ConfigError::KeyMaterialTooShort);
        }
        Ok(Self(Arc::new(
            hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(material),
        )))
    }

    pub(crate) fn into_key(self) -> Arc<dyn HandshakeTokenKey> {
        self.0
    }
}

impl fmt::Debug for AddressTokenKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AddressTokenKey")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        RESET_TOKEN_SIZE, crypto::AeadKey, shared::ConnectionId, token::ResetToken,
    };

    /// The material is the caller's; what these types keep is the provider's key. Neither the
    /// type nor its debug output carries the bytes.
    #[test]
    fn a_key_shows_nothing_of_its_material() {
        const MATERIAL: &[u8; KEY_MATERIAL_SIZE] = b"a seed no debug output may show!";
        let reset = format!("{:?}", StatelessResetKey::from_seed(MATERIAL));
        let token = format!("{:?}", AddressTokenKey::from_seed(MATERIAL));
        assert_eq!(reset, "StatelessResetKey");
        assert_eq!(token, "AddressTokenKey");
        for shown in [&reset, &token] {
            assert!(
                !shown.contains("seed"),
                "the material does not reach the output: {shown}"
            );
        }
    }

    /// Material shorter than a seed is refused rather than keyed with.
    #[test]
    fn material_shorter_than_a_seed_is_refused() {
        let short = [0x5a; KEY_MATERIAL_SIZE - 1];
        assert_eq!(
            StatelessResetKey::try_from_bytes(&short).unwrap_err(),
            ConfigError::KeyMaterialTooShort
        );
        assert_eq!(
            AddressTokenKey::try_from_bytes(&short).unwrap_err(),
            ConfigError::KeyMaterialTooShort
        );
        assert!(StatelessResetKey::try_from_bytes(&[0x5a; KEY_MATERIAL_SIZE]).is_ok());
        assert!(AddressTokenKey::try_from_bytes(&[0x5a; KEY_MATERIAL_SIZE]).is_ok());
        assert!(
            StatelessResetKey::try_from_bytes(&[0x5a; KEY_MATERIAL_SIZE * 2]).is_ok(),
            "longer material is taken as it is"
        );
    }

    /// The same material gives the same bytes whichever provider is compiled in, so endpoints
    /// sharing material need not share a provider. The answers are fixed here, so each
    /// provider is compared against the same values rather than against the other.
    #[test]
    fn the_derivation_is_the_same_on_every_provider() {
        const SEED: [u8; KEY_MATERIAL_SIZE] = [0x4b; KEY_MATERIAL_SIZE];
        let reset = StatelessResetKey::from_seed(&SEED).into_key();
        let token = ResetToken::new(&*reset, ConnectionId::new(&[0x01, 0x02, 0x03, 0x04]));
        assert_eq!(
            &token[..],
            &[
                0x5b, 0xbf, 0xb4, 0xfe, 0x26, 0xc5, 0x00, 0xc7, 0xf7, 0x7c, 0x44, 0x14, 0xe6, 0xda,
                0x51, 0xfd
            ],
            "HMAC-SHA256 over the connection ID, truncated to {RESET_TOKEN_SIZE} bytes"
        );

        let sealing = AddressTokenKey::from_seed(&SEED).into_key();
        let aead = sealing
            .aead_from_hkdf(&[0x11; 16])
            .expect("the provider expands the key");
        let mut sealed = b"a token payload".to_vec();
        aead.seal(&mut sealed, b"the associated data")
            .expect("it seals");
        assert_eq!(
            sealed,
            vec![
                0x8c, 0x99, 0x11, 0x9b, 0xa2, 0xbe, 0x77, 0x88, 0x57, 0x90, 0xc9, 0xec, 0x36, 0xeb,
                0x0e, 0x91, 0x30, 0x69, 0x85, 0x01, 0xe0, 0x68, 0x2f, 0xe5, 0xc4, 0x64, 0x74, 0x8a,
                0x9b, 0x6b, 0xe2
            ],
            "HKDF-SHA256 then AES-256-GCM under a zero nonce"
        );
    }
}
