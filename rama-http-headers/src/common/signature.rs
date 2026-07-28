//! `Signature` typed header (RFC 9421 §4.2).
//!
//! A Structured Fields Dictionary of label → byte-sequence signature values.

use rama_http_types::{HeaderName, HeaderValue};

use crate::util::structured_fields::{
    BareItem, Dictionary, DictionaryMember, Item, parse_dictionary, serialize_dictionary,
};
use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// The `Signature` header field (RFC 9421).
///
/// Contains one or more labeled signature values as byte sequences.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Signature {
    dict: Dictionary,
}

impl Signature {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a labeled signature value.
    pub fn insert(&mut self, label: impl Into<String>, signature: impl Into<Vec<u8>>) {
        self.dict.insert(
            label,
            DictionaryMember::Item(Item::byte_sequence(signature)),
        );
    }

    /// Get the signature bytes for a label.
    pub fn get(&self, label: &str) -> Option<&[u8]> {
        match self.dict.get(label)? {
            DictionaryMember::Item(item) => match &item.bare {
                BareItem::ByteSequence(bytes) => Some(bytes.as_slice()),
                _ => None,
            },
            DictionaryMember::InnerList(_) => None,
        }
    }

    /// Labels present in this header, in order.
    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.dict.keys()
    }

    /// Number of labeled signatures.
    #[must_use]
    pub fn len(&self) -> usize {
        self.dict.members.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.dict.members.is_empty()
    }

    /// Access the underlying Structured Fields dictionary.
    #[must_use]
    pub fn as_dictionary(&self) -> &Dictionary {
        &self.dict
    }
}

impl TypedHeader for Signature {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::SIGNATURE
    }
}

impl HeaderDecode for Signature {
    fn decode<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        let mut combined = Dictionary::new();
        let mut any = false;
        for value in values {
            any = true;
            let s = value.to_str().map_err(|_err| Error::invalid())?;
            let dict = parse_dictionary(s).map_err(|_err| Error::invalid())?;
            for (key, member) in dict.members {
                // Signature members must be byte-sequence items
                match &member {
                    DictionaryMember::Item(item)
                        if matches!(item.bare, BareItem::ByteSequence(_)) => {}
                    _ => return Err(Error::invalid()),
                }
                if combined.get(&key).is_some() {
                    return Err(Error::invalid());
                }
                combined.members.push((key, member));
            }
        }
        if !any {
            return Err(Error::invalid());
        }
        Ok(Self { dict: combined })
    }
}

impl HeaderEncode for Signature {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let s = serialize_dictionary(&self.dict);
        if let Ok(value) = HeaderValue::from_str(&s) {
            values.extend(std::iter::once(value));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{test_decode, test_encode};

    #[test]
    fn decode_single() {
        let sig = test_decode::<Signature>(&["sig1=:dGVzdA==:"]).unwrap();
        assert_eq!(sig.get("sig1"), Some(b"test".as_slice()));
    }

    #[test]
    fn round_trip() {
        let mut sig = Signature::new();
        sig.insert("sig1", b"hello".to_vec());
        sig.insert("proxy_sig", b"world".to_vec());
        let map = test_encode(sig.clone());
        let value = map.get(Signature::name()).unwrap().to_str().unwrap();
        let decoded = test_decode::<Signature>(&[value]).unwrap();
        assert_eq!(decoded.get("sig1"), Some(b"hello".as_slice()));
        assert_eq!(decoded.get("proxy_sig"), Some(b"world".as_slice()));
    }

    #[test]
    fn multi_label_rfc_example_shape() {
        // Shape from RFC 9421 §4.3 (truncated base64 for brevity in this unit test)
        let input = "sig1=:dGVzdA==:, proxy_sig=:d29ybGQ=:";
        let sig = test_decode::<Signature>(&[input]).unwrap();
        assert_eq!(sig.len(), 2);
        assert_eq!(sig.get("sig1"), Some(b"test".as_slice()));
        assert_eq!(sig.get("proxy_sig"), Some(b"world".as_slice()));
    }
}
