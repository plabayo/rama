use super::{EchServerKey, EchServerKeys};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rama_core::error::{BoxError, BoxErrorExt as _, ErrorContext as _};
use rama_crypto::dep::zeroize::Zeroizing;
use serde::Deserialize;
use std::{io::Read, sync::Arc};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EncodedKey {
    config: String,
    private_key: Zeroizing<String>,
    retry: bool,
}

impl EchServerKeys {
    /// Load a bounded JSON array of ECH keys from a file or another reader.
    ///
    /// Each entry has `config` (base64 single ECHConfig, without the list prefix),
    /// `private_key` (base64 raw X25519 key), and `retry` (boolean). The complete
    /// set is validated before return. Temporary private buffers are cleared on
    /// drop, and parse errors do not include the input contents.
    ///
    /// This does not publish keys or change a provider. Pass the successful result
    /// to [`super::ReloadableEchServerKeys::replace`] for an atomic generation update.
    pub fn from_json_reader(
        reader: impl Read,
        maximum_bytes: usize,
    ) -> Result<Arc<Self>, BoxError> {
        let limit = u64::try_from(maximum_bytes)?
            .checked_add(1)
            .ok_or_else(|| BoxError::from_static_str("ECH input limit overflow"))?;
        let mut bytes = Zeroizing::new(Vec::new());
        reader
            .take(limit)
            .read_to_end(&mut bytes)
            .context("read ECH keys")?;
        if bytes.len() > maximum_bytes {
            return Err(BoxError::from_static_str(
                "ECH key input exceeds size limit",
            ));
        }
        let encoded: Vec<EncodedKey> = serde_json::from_slice(&bytes).map_err(|_error| {
            BoxError::from_static_str("invalid ECH keys: expected a JSON key list")
        })?;
        let decoded = encoded
            .iter()
            .map(|key| {
                let config = BASE64
                    .decode(&key.config)
                    .context("decode public ECHConfig")?;
                let mut private = Zeroizing::new(Vec::new());
                BASE64
                    .decode_vec(key.private_key.as_bytes(), &mut private)
                    .map_err(|_error| {
                        BoxError::from_static_str("invalid ECH private key encoding")
                    })?;
                Ok::<_, BoxError>((config, private, key.retry))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(
            decoded
                .iter()
                .map(|(config, private, retry)| EchServerKey::new(config, private, *retry)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::ech::tests::{SERVER_ECH_CONFIG, SERVER_ECH_KEY};
    use rama_utils::octets::kib;

    #[test]
    fn bounded_key_reader_validates_complete_sets_without_disclosing_input() {
        let input = serde_json::to_vec(&serde_json::json!([{
            "config": BASE64.encode(SERVER_ECH_CONFIG),
            "private_key": BASE64.encode(SERVER_ECH_KEY),
            "retry": true,
        }]))
        .unwrap();
        let keys = EchServerKeys::from_json_reader(input.as_slice(), input.len()).unwrap();
        assert_eq!(&keys.retry_configs()[2..], SERVER_ECH_CONFIG);
        EchServerKeys::from_json_reader(input.as_slice(), input.len() - 1).unwrap_err();
        for invalid in [
            b"private-key-canary".as_slice(),
            b"[]",
            b"[{\"private_key\":\"private-key-canary\"}]",
        ] {
            let error = EchServerKeys::from_json_reader(invalid, kib(1)).unwrap_err();
            assert!(!format!("{error:?}").contains("private-key-canary"));
        }
    }
}
