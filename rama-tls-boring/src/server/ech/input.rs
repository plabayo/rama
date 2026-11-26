use super::{EchServerKey, EchServerKeys};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rama_core::error::{BoxError, BoxErrorExt as _, ErrorContext as _};
use rama_crypto::dep::zeroize::Zeroizing;
use serde::Deserialize;
use std::{
    io::{ErrorKind, Read},
    sync::Arc,
};

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
    /// A buffer of `maximum_bytes + 1` bytes is reserved up front, so the
    /// private input is never moved by a reallocation that leaves a copy behind.
    ///
    /// Each entry has `config` (base64 single ECHConfig, without the list prefix),
    /// `private_key` (base64 raw X25519 key), and `retry` (boolean). The complete
    /// set is validated before return. Temporary private buffers are cleared on
    /// drop, and parse errors do not include the input contents. Input with JSON
    /// escape sequences is rejected.
    ///
    /// This does not publish keys or change a provider. Pass the successful result
    /// to [`super::ReloadableEchServerKeys::replace`] for an atomic generation update.
    pub fn from_json_reader(
        reader: impl Read,
        maximum_bytes: usize,
    ) -> Result<Arc<Self>, BoxError> {
        let bytes = read_bounded(reader, maximum_bytes)?;
        // The JSON decoder unescapes into a buffer that is never cleared; base64 needs no escapes.
        if bytes.contains(&b'\\') {
            return Err(BoxError::from_static_str(
                "invalid ECH keys: escape sequences are not accepted",
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

/// Read at most `maximum_bytes` into one zeroizing allocation that never grows.
fn read_bounded(
    mut reader: impl Read,
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, BoxError> {
    // One byte past the limit tells an oversized input from one that fits exactly.
    let capacity = maximum_bytes
        .checked_add(1)
        .ok_or_else(|| BoxError::from_static_str("ECH input limit overflow"))?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(capacity)
        .context("reserve ECH key input buffer")?;
    bytes.resize(capacity, 0);
    let mut filled = 0;
    while filled < capacity {
        match reader.read(&mut bytes[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => Err::<(), _>(error).context("read ECH keys")?,
        }
    }
    if filled > maximum_bytes {
        return Err(BoxError::from_static_str(
            "ECH key input exceeds size limit",
        ));
    }
    bytes.truncate(filled);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::ech::tests::{SERVER_ECH_CONFIG, SERVER_ECH_KEY};
    use rama_utils::octets::kib;
    use std::{io, ops::Range};

    /// Hands out its input one byte per read and records each target buffer.
    struct Trickle<'a> {
        input: &'a [u8],
        targets: Vec<Range<usize>>,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let start = buf.as_ptr() as usize;
            self.targets.push(start..start + buf.len());
            let Some((first, rest)) = self.input.split_first() else {
                return Ok(0);
            };
            buf[0] = *first;
            self.input = rest;
            Ok(1)
        }
    }

    #[test]
    fn bounded_read_fills_one_allocation() {
        let input = [7; 255];
        for maximum_bytes in [input.len(), input.len() + 1] {
            let mut reader = Trickle {
                input: &input,
                targets: Vec::new(),
            };
            let bytes = read_bounded(&mut reader, maximum_bytes).unwrap();
            assert_eq!(bytes.as_slice(), input);
            assert_eq!(bytes.capacity(), maximum_bytes + 1);
            let allocation = bytes.as_ptr() as usize..bytes.as_ptr() as usize + bytes.capacity();
            assert!(reader.targets.iter().all(|target| {
                allocation.contains(&target.start) && target.end <= allocation.end
            }));
        }
        let mut reader = Trickle {
            input: &input,
            targets: Vec::new(),
        };
        read_bounded(&mut reader, input.len() - 1).unwrap_err();
        read_bounded(io::empty(), usize::MAX).unwrap_err();
    }

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

    #[test]
    fn escaped_key_input_is_refused() {
        let key = BASE64.encode(SERVER_ECH_KEY);
        let (first, rest) = key.split_at(1);
        // A valid JSON spelling of the same key that only a decoding buffer could hold.
        let escaped = format!("\\u{:04x}{rest}", u32::from(first.as_bytes()[0]));
        let input = format!(
            r#"[{{"config":"{}","private_key":"{escaped}","retry":true}}]"#,
            BASE64.encode(SERVER_ECH_CONFIG)
        );
        let decoded: serde_json::Value = serde_json::from_str(&input).unwrap();
        assert_eq!(decoded[0]["private_key"], key);
        EchServerKeys::from_json_reader(input.as_bytes(), input.len()).unwrap_err();
    }
}
