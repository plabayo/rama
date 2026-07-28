//! `Content-Digest` typed header (RFC 9530).
//!
//! A Structured Fields Dictionary of digest algorithm → byte-sequence.

use rama_http_types::{HeaderName, HeaderValue};
use sha2::{Digest as _, Sha256, Sha512};

use crate::util::structured_fields::{
    BareItem, Dictionary, DictionaryMember, Item, parse_dictionary, serialize_dictionary,
};
use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// Digest algorithms supported for `Content-Digest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    Sha256,
    Sha512,
}

impl DigestAlgorithm {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
            Self::Sha512 => "sha-512",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "sha-256" => Some(Self::Sha256),
            "sha-512" => Some(Self::Sha512),
            _ => None,
        }
    }
}

/// The `Content-Digest` header field (RFC 9530).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContentDigest {
    dict: Dictionary,
}

impl ContentDigest {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute and insert a digest of `body` using `alg`.
    pub fn insert_digest(&mut self, alg: DigestAlgorithm, body: &[u8]) {
        let digest = match alg {
            DigestAlgorithm::Sha256 => Sha256::digest(body).to_vec(),
            DigestAlgorithm::Sha512 => Sha512::digest(body).to_vec(),
        };
        self.insert(alg.as_str(), digest);
    }

    /// Build a `Content-Digest` containing a single algorithm digest of `body`.
    #[must_use]
    pub fn from_body(alg: DigestAlgorithm, body: &[u8]) -> Self {
        let mut cd = Self::new();
        cd.insert_digest(alg, body);
        cd
    }

    pub fn insert(&mut self, alg: impl Into<String>, digest: impl Into<Vec<u8>>) {
        self.dict
            .insert(alg, DictionaryMember::Item(Item::byte_sequence(digest)));
    }

    pub fn get(&self, alg: &str) -> Option<&[u8]> {
        match self.dict.get(alg)? {
            DictionaryMember::Item(item) => match &item.bare {
                BareItem::ByteSequence(b) => Some(b.as_slice()),
                _ => None,
            },
            DictionaryMember::InnerList(_) => None,
        }
    }

    /// Verify that the digest for `alg` matches `body`.
    pub fn verify(&self, alg: DigestAlgorithm, body: &[u8]) -> bool {
        let Some(expected) = self.get(alg.as_str()) else {
            return false;
        };
        let actual = match alg {
            DigestAlgorithm::Sha256 => Sha256::digest(body).to_vec(),
            DigestAlgorithm::Sha512 => Sha512::digest(body).to_vec(),
        };
        expected == actual.as_slice()
    }

    #[must_use]
    pub fn as_dictionary(&self) -> &Dictionary {
        &self.dict
    }
}

impl TypedHeader for ContentDigest {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::CONTENT_DIGEST
    }
}

impl HeaderDecode for ContentDigest {
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

impl HeaderEncode for ContentDigest {
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
    fn round_trip_sha256() {
        let body = b"{\"hello\": \"world\"}";
        let cd = ContentDigest::from_body(DigestAlgorithm::Sha256, body);
        assert!(cd.verify(DigestAlgorithm::Sha256, body));
        let map = test_encode(cd);
        let value = map.get(ContentDigest::name()).unwrap().to_str().unwrap();
        let decoded = test_decode::<ContentDigest>(&[value]).unwrap();
        assert!(decoded.verify(DigestAlgorithm::Sha256, body));
    }

    #[test]
    fn rfc_9530_sha512_example_shape() {
        // Body from RFC 9421 examples: {"hello": "world"}
        let body = b"{\"hello\": \"world\"}";
        let cd = ContentDigest::from_body(DigestAlgorithm::Sha512, body);
        let expected = Sha512::digest(body);
        assert_eq!(cd.get("sha-512"), Some(expected.as_slice()));
    }
}
