use crate::dep::aws_lc_rs::{
    digest::Digest,
    pkcs8,
    rand::SystemRandom,
    signature::{self, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
    signature::{KeyPair, Signature},
};
use aws_lc_rs::digest::{SHA256, digest};
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
use rama_core::error::{BoxError, ErrorContext, OpaqueError};
use serde::{Deserialize, Serialize, Serializer, de::DeserializeOwned, ser::SerializeStruct};
use std::{fmt::Debug, marker::PhantomData};

#[derive(Debug, Serialize, Deserialize)]
/// ProtectedHeader is the first part of the JWS that contains
/// all the metadata that is needed to guarantee the integrity and
/// authenticy of this request
pub struct ProtectedHeader<'a> {
    /// Algorithm that was used to sign the JWS
    pub alg: JWA,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// A nonce that was given by the server to use
    pub nonce: Option<&'a str>,
    /// Url of the endpoint to which we are making a request
    pub url: &'a str,
    #[serde(flatten)]
    /// JWK or KeyId which is used to identify this request
    pub key: ProtectedHeaderKey<'a>,
}

#[derive(Debug, Serialize, Deserialize, Copy, Clone, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
/// [`JWA`] or JSON Web Algorithms as defined in [`rfc7518`]
///
/// [`rfc7518`]: https://datatracker.ietf.org/doc/html/rfc7518
pub enum JWA {
    ES256,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// [`ProtectedHeaderKey`] send as key for [`ProtectedHeader`]
pub enum ProtectedHeaderKey<'a> {
    #[serde(rename = "JWK")]
    JWK(JWK),
    #[serde(rename = "kid")]
    KeyID(&'a str),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// [`JWK`] or JSON Web Key as defined in [`rfc7517`]
///
/// [`rfc7517`]: https://datatracker.ietf.org/doc/html/rfc7517
pub struct JWK {
    /// Intended algorithm to be used with this key
    alg: JWA,
    #[serde(flatten)]
    key_type: JWKType,
    #[serde(skip_serializing_if = "Option::is_none")]
    r#use: Option<JWKUse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_ops: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x5c: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x5t: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5t#S256")]
    x5t_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "kty")]
/// The "kty" (key type) parameter identifies the cryptographic algorithm family used with the key, such as "RSA" or "EC"
pub enum JWKType {
    RSA {
        n: String,
        e: String,
    },
    /// Elleptic curve
    EC {
        crv: String,
        x: String,
        y: String,
    },
    /// an octet sequence key, which represents a symmetric key
    OCT {
        k: String,
    },
}

impl Serialize for JWKType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Order here is important as this output will be used to generate jwk thumb
        match &self {
            JWKType::EC { crv, x, y } => {
                let mut state = serializer.serialize_struct("JWKType", 4)?;
                state.serialize_field("crv", crv)?;
                state.serialize_field("kty", "EC")?;
                state.serialize_field("x", x)?;
                state.serialize_field("y", y)?;
                state.end()
            }
            JWKType::RSA { n, e } => {
                let mut state = serializer.serialize_struct("JWKType", 3)?;
                state.serialize_field("e", e)?;
                state.serialize_field("kty", "RSA")?;
                state.serialize_field("n", n)?;
                state.end()
            }
            JWKType::OCT { k } => {
                let mut state = serializer.serialize_struct("JWKType", 2)?;
                state.serialize_field("k", k)?;
                state.serialize_field("kty", "OCT")?;
                state.end()
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// [`JWKUse`]) identifies the intended use of the public key
pub enum JWKUse {
    #[serde(rename = "sig")]
    Signature,
    #[serde(rename = "enc")]
    Encryption,
}

impl JWK {
    fn new_for_escdsa_keypair(key: &EcdsaKeyPair) -> Self {
        // 0x04 prefix + 32-byte X + 32-byte Y = 65-bytes
        let (x, y) = key.public_key().as_ref()[1..].split_at(32);
        Self {
            alg: JWA::ES256,
            key_type: JWKType::EC {
                crv: "P-256".into(),
                x: BASE64_URL_SAFE_NO_PAD.encode(x),
                y: BASE64_URL_SAFE_NO_PAD.encode(y),
            },
            r#use: Some(JWKUse::Signature),
            key_ops: None,
            x5c: None,
            x5t: None,
            x5t_sha256: None,
        }
    }

    /// [`JWKThumb`] as defined in [`rfc7638`] is url safe identifier for a [`JWK`]
    ///
    /// [`rfc7638`]: https://datatracker.ietf.org/doc/html/rfc7638
    pub fn thumb_sha256(&self) -> Result<Digest, OpaqueError> {
        Ok(digest(
            &SHA256,
            &serde_json::to_vec(&self.key_type).context("failed to serialise JWK")?,
        ))
    }

    pub fn unparsed_public_key(
        &self,
    ) -> Result<signature::UnparsedPublicKey<Vec<u8>>, OpaqueError> {
        match &self.key_type {
            JWKType::RSA { .. } => Err(OpaqueError::from_display("currently not supported")),
            JWKType::OCT { .. } => Err(OpaqueError::from_display("currently not supported")),
            JWKType::EC { crv: _, x, y } => {
                let x_bytes = BASE64_URL_SAFE_NO_PAD.decode(x).unwrap();
                let y_bytes = BASE64_URL_SAFE_NO_PAD.decode(y).unwrap();

                // 0x04 prefix + 32-byte X + 32-byte Y = 65-bytes
                let mut point_bytes = Vec::with_capacity(65);
                point_bytes.push(0x04);
                point_bytes.extend_from_slice(&x_bytes);
                point_bytes.extend_from_slice(&y_bytes);
                Ok(signature::UnparsedPublicKey::new(
                    &ECDSA_P256_SHA256_FIXED,
                    point_bytes,
                ))
            }
        }
    }
}

/// [`Key`] which is used to identify and authenticate our requests
pub struct Key {
    rng: SystemRandom,
    alg: JWA,
    inner: EcdsaKeyPair,
}

impl Key {
    /// Create a new [`Key`] from the given pkcs8 der key and the given rng
    ///
    /// WARNING: right now we only support an ECDSA key pair
    pub fn new(pkcs8_der: &[u8], rng: SystemRandom) -> Result<Self, OpaqueError> {
        // TODO support other algorithms
        let inner = Self::ecdsa_key_pair_from_pkcs8(pkcs8_der, &rng)?;

        Ok(Self {
            rng,
            alg: JWA::ES256,
            inner,
        })
    }

    /// Create a new [`Key`] from the given pkcs8 der key containing an ECDSA key pair
    fn ecdsa_key_pair_from_pkcs8(
        pkcs8: &[u8],
        _: &SystemRandom,
    ) -> Result<EcdsaKeyPair, OpaqueError> {
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8)
            .context("create EcdsaKeyPair from pkcs8")
    }

    /// Generate a new [`Key`] from a newly generated [`EcdsaKeyPair`]
    pub fn generate() -> Result<(Self, pkcs8::Document), OpaqueError> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .context("generate pkcs8")?;
        Self::new(pkcs8.as_ref(), rng).map(|key| (key, pkcs8))
    }

    /// Generate a new [`Key`] from the given pkcs8 der
    ///
    /// WARNING: right now we only support an ECDSA key pair
    pub fn from_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, OpaqueError> {
        Self::new(pkcs8_der, SystemRandom::new())
    }

    pub fn create_jwk(&self) -> JWK {
        JWK::new_for_escdsa_keypair(&self.inner)
    }
}

/// [`Signer`] implements all methods which are needed to sign our JWS requests
pub trait Signer {
    type Signature: AsRef<[u8]>;

    fn protected_header<'n, 'u: 'n, 's: 'u>(
        &'s self,
        nonce: Option<&'n str>,
        url: &'u str,
    ) -> ProtectedHeader<'n>;

    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, BoxError>;
}

impl Signer for Key {
    type Signature = Signature;

    fn protected_header<'n, 'u: 'n, 's: 'u>(
        &'s self,
        nonce: Option<&'n str>,
        url: &'u str,
    ) -> ProtectedHeader<'n> {
        ProtectedHeader {
            alg: self.alg,
            key: ProtectedHeaderKey::from_key(&self.inner),
            nonce,
            url,
        }
    }

    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, BoxError> {
        Ok(self.inner.sign(&self.rng, payload)?)
    }
}

impl ProtectedHeaderKey<'_> {
    /// Create a [`ProtectedHeaderKey`] with a JWK encoded [`EcdsaKeyPair`]
    pub fn from_key(key: &EcdsaKeyPair) -> ProtectedHeaderKey<'static> {
        ProtectedHeaderKey::JWK(JWK::new_for_escdsa_keypair(key))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// [`JWS`] combines [`ProtectedHeader`], payload, and signature into one
pub struct JWS<T> {
    protected: String,
    payload: String,
    signature: String,
    _phantom: PhantomData<fn() -> T>,
}

impl<T> JWS<T> {
    /// Create a JWS struct for the provided payload and protected header using the provided signer
    ///
    /// Important note: Some(&Emtpy) is different then None::<&Empty>. The first serializes to a
    /// JSON null value (= empty payload) while the later serializes to an empty string (= no payload)
    pub fn new(
        payload: Option<&T>,
        protected: &ProtectedHeader<'_>,
        signer: &impl Signer,
    ) -> Result<Self, OpaqueError>
    where
        T: Serialize,
    {
        let protected = BASE64_URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(protected).context("encode base64 protected header")?);
        let payload = match payload {
            Some(data) => BASE64_URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&data).context("encode base64 protected payload")?),

            None => String::new(),
        };

        let signing_input = format!("{protected}.{payload}");
        let signature = signer
            .sign(signing_input.as_bytes())
            .map_err(OpaqueError::from_boxed)
            .context("create signature over protected payload")?;

        Ok(Self {
            protected,
            payload,
            signature: BASE64_URL_SAFE_NO_PAD.encode(signature.as_ref()),
            _phantom: PhantomData,
        })
    }

    pub fn decode_without_key_id_support(&self) -> Result<DecodedJWS<T>, OpaqueError>
    where
        T: DeserializeOwned,
    {
        self.decode(&NoKeyIdStorage)
    }

    pub fn decode(
        &self,
        key_to_pub_key: &impl VerifyWithKeyId,
    ) -> Result<DecodedJWS<T>, OpaqueError>
    where
        T: DeserializeOwned,
    {
        let protected_data = BASE64_URL_SAFE_NO_PAD.decode(&self.protected).unwrap();
        let signature_data = BASE64_URL_SAFE_NO_PAD.decode(&self.signature).unwrap();

        let signing_input = format!("{}.{}", self.protected, self.payload);

        let decoded = DecodedJWS {
            _phantom: std::marker::PhantomData,
            protected_data,
            payload: if self.payload.is_empty() {
                None
            } else {
                let payload_data: Vec<u8> = BASE64_URL_SAFE_NO_PAD.decode(&self.payload).unwrap();
                Some(serde_json::from_slice(&payload_data).unwrap())
            },
        };

        let protected_header = decoded.protected().unwrap();

        match protected_header.key {
            ProtectedHeaderKey::JWK(jws) => {
                if protected_header.alg != jws.alg {
                    return Err(OpaqueError::from_display(
                        "protected header alg and JWK don't match",
                    ));
                }
                jws.unparsed_public_key()
                    .context("jws to unparsed public key")?
                    .verify(signing_input.as_bytes(), &signature_data)
                    .map_err(|_err| OpaqueError::from_display("verify failed"))
            }
            ProtectedHeaderKey::KeyID(id) => {
                key_to_pub_key.verify(id, |public_key| match public_key {
                    Some(key) => key
                        .verify(signing_input.as_bytes(), &signature_data)
                        .map_err(|_err| OpaqueError::from_display("verify failed")),
                    None => Err(OpaqueError::from_display(
                        "no public key found for given key id",
                    )),
                })
            }
        }?;

        Ok(decoded)
    }
}

pub trait VerifyWithKeyId {
    fn verify<F>(&self, key_id: &str, verify: F) -> Result<(), OpaqueError>
    where
        F: FnOnce(Option<&signature::UnparsedPublicKey<Vec<u8>>>) -> Result<(), OpaqueError>;
}

struct NoKeyIdStorage;

impl VerifyWithKeyId for NoKeyIdStorage {
    fn verify<F>(&self, _key_id: &str, verify: F) -> Result<(), OpaqueError>
    where
        F: FnOnce(Option<&signature::UnparsedPublicKey<Vec<u8>>>) -> Result<(), OpaqueError>,
    {
        (verify)(None)
    }
}

#[derive(Debug, Clone)]
pub struct DecodedJWS<T> {
    protected_data: Vec<u8>,
    payload: Option<T>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> DecodedJWS<T> {
    pub fn protected(&self) -> Result<ProtectedHeader<'_>, serde_json::Error> {
        serde_json::from_slice(&self.protected_data)
    }
}

impl<T: DeserializeOwned> DecodedJWS<T> {
    pub fn payload(&self) -> &Option<T> {
        &self.payload
    }

    pub fn into_payload(self) -> Option<T> {
        self.payload
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Empty;

pub const NO_PAYLOAD: Option<&Empty> = None::<&Empty>;
pub const EMPTY_PAYLOAD: Option<&Empty> = Some(&Empty);

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio_test::assert_err;

    #[test]
    fn jwk_thumb_order_is_correct() {
        let jwk_type = JWKType::EC {
            crv: "crv".into(),
            x: "x".into(),
            y: "y".into(),
        };
        let output = serde_json::to_string(&jwk_type).unwrap();
        let expected_output = r##"{"crv":"crv","kty":"EC","x":"x","y":"y"}"##;
        assert_eq!(&output, expected_output);

        let jwk_type = JWKType::RSA {
            n: "n".into(),
            e: "e".into(),
        };
        let output = serde_json::to_string(&jwk_type).unwrap();
        let expected_output = r##"{"e":"e","kty":"RSA","n":"n"}"##;
        assert_eq!(&output, expected_output);

        let jwk_type = JWKType::OCT { k: "k".into() };
        let output = serde_json::to_string(&jwk_type).unwrap();
        let expected_output = r##"{"k":"k","kty":"OCT"}"##;
        assert_eq!(&output, expected_output);
    }

    #[test]
    fn can_generate_and_reuse_keys() {
        let (generated_key, pkcs8_document) = Key::generate().unwrap();
        let recreated_key = Key::from_pkcs8_der(pkcs8_document.as_ref()).unwrap();

        assert_eq!(generated_key.create_jwk(), recreated_key.create_jwk())
    }

    #[test]
    fn can_encode_and_decode_jws_with_payload() {
        let (key, _) = Key::generate().unwrap();
        let nonce = "test_nonce";
        let url = "http://test.test";
        let payload = String::from("test_payload");
        let protected_header = key.protected_header(Some(nonce), url);
        let jws = JWS::new(Some(&payload), &protected_header, &key).unwrap();

        let decoded = jws.decode_without_key_id_support().unwrap();
        assert_eq!(decoded.payload(), &Some(String::from("test_payload")));
    }

    #[test]
    fn can_encode_and_decode_jws_without_payload() {
        let (key, _) = Key::generate().unwrap();
        let nonce = "test_nonce";
        let url = "http://test.test";
        let protected_header = key.protected_header(Some(nonce), url);
        let jws = JWS::new(NO_PAYLOAD, &protected_header, &key).unwrap();

        let decoded = jws.decode_without_key_id_support().unwrap();
        assert_eq!(decoded.payload(), &None);
    }

    #[test]
    fn can_encode_and_decode_jws_with_empty_payload() {
        let (key, _) = Key::generate().unwrap();
        let nonce = "test_nonce";
        let url = "http://test.test";
        let protected_header = key.protected_header(Some(nonce), url);
        let jws = JWS::new(EMPTY_PAYLOAD, &protected_header, &key).unwrap();
        let decoded = jws.decode_without_key_id_support().unwrap();
        assert_eq!(decoded.payload(), &Some(Empty));
    }

    #[test]
    fn should_serialize_correctly() {
        let (key, _) = Key::generate().unwrap();
        let nonce = "test_nonce";
        let url = "http://test.test";
        let protected_header = key.protected_header(Some(nonce), url);

        let jws = JWS::new(EMPTY_PAYLOAD, &protected_header, &key).unwrap();
        assert_eq!(jws.payload, "bnVsbA".to_owned());

        let jws = JWS::new(NO_PAYLOAD, &protected_header, &key).unwrap();
        assert_eq!(jws.payload, "".to_owned());
    }

    #[test]
    fn can_decode_with_key_id() {
        struct KeyId {
            key: Key,
            id: String,
        }

        impl Signer for KeyId {
            type Signature = <Key as Signer>::Signature;

            fn protected_header<'n, 'u: 'n, 's: 'u>(
                &'s self,
                nonce: Option<&'n str>,
                url: &'u str,
            ) -> ProtectedHeader<'n> {
                ProtectedHeader {
                    alg: self.key.alg,
                    key: ProtectedHeaderKey::KeyID(&self.id),
                    nonce,
                    url,
                }
            }

            fn sign(&self, payload: &[u8]) -> Result<Self::Signature, BoxError> {
                self.key.sign(payload)
            }
        }

        #[derive(Default)]
        struct DummyStorage(HashMap<String, signature::UnparsedPublicKey<Vec<u8>>>);

        impl VerifyWithKeyId for DummyStorage {
            fn verify<F>(&self, key_id: &str, verify: F) -> Result<(), OpaqueError>
            where
                F: FnOnce(
                    Option<&signature::UnparsedPublicKey<Vec<u8>>>,
                ) -> Result<(), OpaqueError>,
            {
                (verify)(self.0.get(key_id))
            }
        }

        let (key, _) = Key::generate().unwrap();
        let signer = KeyId {
            id: "test_id".into(),
            key,
        };
        let pub_key = JWK::new_for_escdsa_keypair(&signer.key.inner)
            .unparsed_public_key()
            .unwrap();

        let mut key_id_storage = DummyStorage::default();

        let nonce = "test_nonce";
        let url = "http://test.test";
        let payload = String::from("test_payload");
        let protected_header = signer.protected_header(Some(nonce), url);
        let jws = JWS::new(Some(&payload), &protected_header, &signer).unwrap();

        assert_err!(jws.decode_without_key_id_support());
        assert_err!(jws.decode(&key_id_storage));

        key_id_storage.0.insert("test_id".into(), pub_key);

        let decoded = jws.decode(&key_id_storage).unwrap();
        assert_eq!(decoded.payload(), &Some(String::from("test_payload")));
    }
}
