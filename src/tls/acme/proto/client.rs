use std::{fmt::Debug, marker::PhantomData};

use super::{common::Identifier, server::Challenge};
use aws_lc_rs::{
    digest::{Digest, SHA256, digest},
    error::{KeyRejected, Unspecified},
    pkcs8,
    rand::SystemRandom,
    signature::{self, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
    signature::{KeyPair, Signature},
};
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
use rama_core::error::{BoxError, ErrorContext, OpaqueError};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Options used to create a new account, or request an identifier for an existing account, defined in [rfc8555 section 7.3]
///
/// [rfc8555 section 7.3]: https://datatracker.ietf.org/doc/html/rfc8555/#section-7.3
pub struct CreateAccountOptions {
    pub contact: Option<Vec<String>>,
    pub terms_of_service_agreed: Option<bool>,
    pub only_return_existing: Option<bool>,
    /// TODO support binding external accounts to acme account
    pub external_account_binding: Option<()>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
/// List of [`Identifier`] for which we want to issue certificate(s), defined in [rfc8555 section 7.4]
///
/// [rfc8555 section 7.4]: https://datatracker.ietf.org/doc/html/rfc8555/#section-7.4
pub struct NewOrderPayload {
    /// Identifiers for which we want to issue certificate(s)
    pub identifiers: Vec<Identifier>,
    /// Requested value of not_before field in certificate
    pub not_before: Option<String>,
    /// Requested value of not_after field in certificate
    pub not_after: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// [`KeyAuthorization`] concatenates the token for a challenge with key fingerprint, defined in [rfc8555 section 8.1]
///
/// [rfc8555 section 8.1]: https://datatracker.ietf.org/doc/html/rfc8555/#section-8.1
pub struct KeyAuthorization(String);

impl KeyAuthorization {
    /// Create [`KeyAuthorization`] for the given challenge and key
    pub(crate) fn new(token: &str, key_thumb: &str) -> Self {
        Self(format!("{}.{}", token, key_thumb))
    }

    /// Encode [`KeyAuthorization`] for use in Http challenge
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Encode [`KeyAuthorization`] for use in tls alpn challenge
    pub fn digest(&self) -> impl AsRef<[u8]> {
        digest(&SHA256, self.0.as_bytes())
    }

    /// Encode [`KeyAuthorization`] for use in dns challenge
    pub fn dns_value(&self) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(self.digest())
    }
}

// TODO move common crypto logic such as JWK to rama-crypto and work it more out there

#[derive(Debug, Serialize, Deserialize)]
/// ProtectedHeader is the first part of the JWS that contains
/// all the metadata that is needed to guarantee the integrity and
/// authenticy of this request
pub(crate) struct ProtectedHeader<'a> {
    /// Algorithm that was used to sign the JWS
    pub(crate) alg: SigningAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Previous nonce that was given by the server to use
    pub(crate) nonce: Option<&'a str>,
    /// Url of the acme endpoint for which we are making a request
    pub(crate) url: &'a str,
    #[serde(flatten)]
    /// JWK or KeyId which is used to identify this request
    pub(crate) key: ProtectedHeaderKey<'a>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
/// Algorithm that was used to sign
pub(crate) enum SigningAlgorithm {
    ES256,
}

#[derive(Debug, Serialize, Deserialize)]
/// [`ProtectedHeaderKey`] send as key for [`ProtectedHeader`]
///
/// `JWK` is used for the first request to create an account, once we
/// have an account we use the `KeyID` instead
pub(crate) enum ProtectedHeaderKey<'a> {
    #[serde(rename = "jwk")]
    JWK(Jwk),
    #[serde(rename = "kid")]
    KeyID(&'a str),
}

#[derive(Debug, Serialize, Deserialize)]
/// [`Jwk`] or JSON Web Key used to create a new account
///
/// This key contains the public correspending to our
/// private key which will be using to sign requests
pub struct Jwk {
    alg: SigningAlgorithm,
    #[serde(skip_deserializing, default = "default_crv")]
    crv: &'static str,
    #[serde(skip_deserializing, default = "default_kty")]
    kty: &'static str,
    #[serde(skip_deserializing, default = "default_use")]
    r#use: &'static str,
    x: String,
    y: String,
}

fn default_crv() -> &'static str {
    "P-256"
}

fn default_kty() -> &'static str {
    "EC"
}

fn default_use() -> &'static str {
    "sig"
}

#[derive(Debug, Serialize)]
/// [`JwkThumb`] as defined in [`rfc7638`] is url safe identifier for a [`Jwk`]
///
/// [`rfc7638`]: https://datatracker.ietf.org/doc/html/rfc7638
struct JwkThumb<'a> {
    crv: &'a str,
    kty: &'a str,
    x: &'a str,
    y: &'a str,
}

#[derive(Debug)]
/// Failures that can happen when using Jwk
pub(crate) enum JwkFailure {
    /// Serde failed to serialize our key
    JwkThumbSerializationFailed,
    /// Key was rejected for some explained reason
    KeyRejected(&'static str),
    /// Key was rejected for an unknown reason
    Unspecified,
}

impl std::fmt::Display for JwkFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwkFailure::JwkThumbSerializationFailed => write!(f, "failed to serialize key"),
            JwkFailure::KeyRejected(error) => write!(f, "key rejected: {error}"),
            JwkFailure::Unspecified => write!(f, "key rejected for unknown reason"),
        }
    }
}

impl std::error::Error for JwkFailure {}

impl From<serde_json::Error> for JwkFailure {
    fn from(_value: serde_json::Error) -> Self {
        return Self::JwkThumbSerializationFailed;
    }
}

impl From<KeyRejected> for JwkFailure {
    fn from(value: KeyRejected) -> Self {
        return Self::KeyRejected(value.description_());
    }
}

impl From<Unspecified> for JwkFailure {
    fn from(_value: Unspecified) -> Self {
        return Self::Unspecified;
    }
}

impl Jwk {
    fn new(key: &EcdsaKeyPair) -> Self {
        // 0x04 prefix + 32-byte X + 32-byte Y = 65-bytes
        let (x, y) = key.public_key().as_ref()[1..].split_at(32);
        Self {
            alg: SigningAlgorithm::ES256,
            crv: "P-256",
            kty: "EC",
            r#use: "sig",
            x: BASE64_URL_SAFE_NO_PAD.encode(x),
            y: BASE64_URL_SAFE_NO_PAD.encode(y),
        }
    }

    // rfc7638
    pub fn thumb_sha256(&self) -> Result<Digest, JwkFailure> {
        Ok(digest(
            &SHA256,
            &serde_json::to_vec(&JwkThumb {
                crv: self.crv,
                kty: self.kty,
                x: &self.x,
                y: &self.y,
            })?,
        ))
    }

    pub(crate) fn unparsed_public_key(&self) -> signature::UnparsedPublicKey<Vec<u8>> {
        // 0x04 prefix + 32-byte X + 32-byte Y = 65-bytes
        let x_bytes = BASE64_URL_SAFE_NO_PAD.decode(&self.x).unwrap();
        let y_bytes = BASE64_URL_SAFE_NO_PAD.decode(&self.y).unwrap();

        // 0x04 prefix + 32-byte X + 32-byte Y = 65-bytes
        let mut point_bytes = Vec::with_capacity(65);
        point_bytes.push(0x04);
        point_bytes.extend_from_slice(&x_bytes);
        point_bytes.extend_from_slice(&y_bytes);
        signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point_bytes)
    }
}

/// [`Key`] which is used to identify and authenticate our requests
pub(crate) struct Key {
    rng: SystemRandom,
    pub(crate) signing_algorithm: SigningAlgorithm,
    inner: EcdsaKeyPair,
    pub thumb: String,
}

impl Key {
    /// Create a new [`Key`] from the given pkcs8 der key and the given rng
    ///
    /// WARNING: right now we only support an ECDSA key pair
    pub(crate) fn new(pkcs8_der: &[u8], rng: SystemRandom) -> Result<Self, JwkFailure> {
        // TODO support other algorithms
        let inner = Self::ecdsa_key_pair_from_pkcs8(pkcs8_der, &rng)?;
        let thumb_sha256 = Jwk::new(&inner).thumb_sha256()?;
        println!("thumb_sha256: {thumb_sha256:?}");
        let thumb = BASE64_URL_SAFE_NO_PAD.encode(thumb_sha256);
        Ok(Self {
            rng,
            signing_algorithm: SigningAlgorithm::ES256,
            inner,
            thumb,
        })
    }

    /// Create a new [`Key`] from the given pkcs8 der key containing an ECDSA key pair
    fn ecdsa_key_pair_from_pkcs8(
        pkcs8: &[u8],
        _: &SystemRandom,
    ) -> Result<EcdsaKeyPair, JwkFailure> {
        Ok(EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8,
        )?)
    }

    /// Generate a new [`Key`] from a newly generated [`EcdsaKeyPair`]
    pub(crate) fn generate() -> Result<(Self, pkcs8::Document), JwkFailure> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)?;
        Self::new(pkcs8.as_ref(), rng).map(|key| (key, pkcs8))
    }

    #[allow(dead_code)]
    /// Generate a new [`Key`] from the given pkcs8 der
    ///
    /// WARNING: right now we only support an ECDSA key pair
    pub(crate) fn from_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, JwkFailure> {
        Self::new(pkcs8_der, SystemRandom::new())
    }
}

/// [`Signer`] implements all methods which are needed to sign our JWS requests
pub(crate) trait Signer {
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
            alg: self.signing_algorithm,
            key: ProtectedHeaderKey::from_key(&self.inner),
            nonce,
            url,
        }
    }

    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, BoxError> {
        Ok(self.inner.sign(&self.rng, payload)?)
    }
}

impl<'a> ProtectedHeaderKey<'a> {
    /// Create a [`ProtectedHeaderKey`] with a JWK encoded [`EcdsaKeyPair`]
    pub(crate) fn from_key(key: &EcdsaKeyPair) -> ProtectedHeaderKey<'static> {
        ProtectedHeaderKey::JWK(Jwk::new(key))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// [`Jws`] combines [`ProtectedHeader`], payload, and signature into one
pub struct Jws<T = ()> {
    protected: String,
    payload: Option<String>,
    signature: String,
    _phantom: PhantomData<fn() -> T>,
}

// impl<T> DeserializeOwned for Jws<T> {}

impl<T> Jws<T> {
    /// Create a JWS struct for the provided payload and protected header using the provided signer
    ///
    /// Important note: Some(&Emtpy) is different then None::<&Empty>. The first serializes to an
    /// empty JSON struct (= empty payload) while the later serializes to an empty string (= no payload)
    pub(crate) fn new(
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
            Some(data) => Some(
                BASE64_URL_SAFE_NO_PAD
                    .encode(serde_json::to_vec(&data).context("encode base64 protected payload")?),
            ),
            None => None,
        };

        let signing_input = match &payload {
            Some(payload) => format!("{protected}.{payload}"),
            None => format!("{protected}."),
        };
        let signature = signer
            .sign(signing_input.as_bytes())
            .map_err(|err| OpaqueError::from_boxed(err))
            .context("create signature over protected payload")?;

        Ok(Self {
            protected,
            payload,
            signature: BASE64_URL_SAFE_NO_PAD.encode(signature.as_ref()),
            _phantom: PhantomData,
        })
    }

    pub fn decode_without_key_id_support(&self) -> Result<DecodedJws<T>, OpaqueError>
    where
        T: DeserializeOwned,
    {
        self.decode(&NoKeyIdStorage)
    }

    pub(crate) fn decode(
        &self,
        key_to_pub_key: &impl KeyIdToUnparsedPublicKey,
    ) -> Result<DecodedJws<T>, OpaqueError>
    where
        T: DeserializeOwned,
    {
        let protected_data = BASE64_URL_SAFE_NO_PAD.decode(&self.protected).unwrap();
        let signature_data = BASE64_URL_SAFE_NO_PAD.decode(&self.signature).unwrap();

        let signing_input = match &self.payload {
            Some(payload) => format!("{}.{}", self.protected, payload),
            None => format!("{}.", self.protected),
        };

        let decoded = DecodedJws {
            _phantom: std::marker::PhantomData,
            protected_data,
            payload: match &self.payload {
                Some(payload) => {
                    println!("decoding payload: {:?}", payload);
                    let payload_data = BASE64_URL_SAFE_NO_PAD.decode(payload).unwrap();
                    Some(serde_json::from_slice(&payload_data).unwrap())
                }
                None => None,
            },
        };

        let protected_header = decoded.protected().unwrap();

        match protected_header.key {
            ProtectedHeaderKey::JWK(jwk) => {
                if protected_header.alg != jwk.alg {
                    return Err(OpaqueError::from_display(
                        "protected header alg and jwk don't match",
                    ));
                }
                jwk.unparsed_public_key()
                    .verify(signing_input.as_bytes(), &signature_data)
                    .map_err(|_err| OpaqueError::from_display("verify failed"))
            }
            ProtectedHeaderKey::KeyID(id) => {
                println!("verifying keyid: {}", id);
                key_to_pub_key.verify(id, |public_key| match public_key {
                    Some(key) => key
                        .verify(signing_input.as_bytes(), &signature_data)
                        .map_err(|_err| OpaqueError::from_display("verify failed")),
                    None => {
                        return Err(OpaqueError::from_display(
                            "no public key found for given key id",
                        ));
                    }
                })
            }
        }?;

        Ok(decoded)
    }
}

pub trait KeyIdToUnparsedPublicKey {
    fn verify<F>(&self, key_id: &str, verify: F) -> Result<(), OpaqueError>
    where
        F: FnOnce(Option<&signature::UnparsedPublicKey<Vec<u8>>>) -> Result<(), OpaqueError>;
}

struct NoKeyIdStorage;

impl KeyIdToUnparsedPublicKey for NoKeyIdStorage {
    fn verify<F>(&self, _key_id: &str, verify: F) -> Result<(), OpaqueError>
    where
        F: FnOnce(Option<&signature::UnparsedPublicKey<Vec<u8>>>) -> Result<(), OpaqueError>,
    {
        (verify)(None)
    }
}

#[derive(Debug, Clone)]
pub struct DecodedJws<T> {
    protected_data: Vec<u8>,
    payload: Option<T>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> DecodedJws<T> {
    pub(crate) fn protected(&self) -> Result<ProtectedHeader<'_>, serde_json::Error> {
        serde_json::from_slice(&self.protected_data)
    }
}

impl<T: DeserializeOwned> DecodedJws<T> {
    pub fn payload(&self) -> &Option<T> {
        &self.payload
    }

    pub fn into_payload(self) -> Option<T> {
        self.payload
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tokio_test::assert_err;

    use crate::tls::acme::proto::common::{EMPTY_PAYLOAD, Empty, NO_PAYLOAD};

    use super::*;

    #[test]
    fn can_generate_and_reuse_keys() {
        let (generated_key, pkcs8_document) = Key::generate().unwrap();
        let recreated_key = Key::from_pkcs8_der(pkcs8_document.as_ref()).unwrap();
        assert_eq!(generated_key.thumb, recreated_key.thumb)
    }

    #[test]
    fn can_encode_and_decode_jws_with_payload() {
        let (key, _) = Key::generate().unwrap();
        let nonce = "test_nonce";
        let url = "http://test.test";
        let payload = String::from("test_payload");
        let protected_header = key.protected_header(Some(nonce), url);
        let jws = Jws::new(Some(&payload), &protected_header, &key).unwrap();

        let decoded = jws.decode_without_key_id_support().unwrap();
        assert_eq!(decoded.payload(), &Some(String::from("test_payload")));
    }

    #[test]
    fn can_encode_and_decode_jws_without_payload() {
        let (key, _) = Key::generate().unwrap();
        let nonce = "test_nonce";
        let url = "http://test.test";
        let protected_header = key.protected_header(Some(nonce), url);
        let jws = Jws::new(NO_PAYLOAD, &protected_header, &key).unwrap();

        let decoded = jws.decode_without_key_id_support().unwrap();
        assert_eq!(decoded.payload(), &None);
    }

    #[test]
    fn can_encode_and_decode_jws_with_empty_payload() {
        let (key, _) = Key::generate().unwrap();
        let nonce = "test_nonce";
        let url = "http://test.test";
        let protected_header = key.protected_header(Some(nonce), url);
        let jws = Jws::new(EMPTY_PAYLOAD, &protected_header, &key).unwrap();
        println!("jws: {:?}", jws);
        let decoded = jws.decode_without_key_id_support().unwrap();
        println!("decoded jws: {:?}", decoded);
        assert_eq!(decoded.payload(), &Some(Empty));
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
                    alg: self.key.signing_algorithm,
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

        impl KeyIdToUnparsedPublicKey for DummyStorage {
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
            key: key,
        };
        let pub_key = Jwk::new(&signer.key.inner).unparsed_public_key();

        let mut key_id_storage = DummyStorage::default();

        let nonce = "test_nonce";
        let url = "http://test.test";
        let payload = String::from("test_payload");
        let protected_header = signer.protected_header(Some(nonce), url);
        let jws = Jws::new(Some(&payload), &protected_header, &signer).unwrap();

        assert_err!(jws.decode_without_key_id_support());
        assert_err!(jws.decode(&key_id_storage));

        key_id_storage.0.insert("test_id".into(), pub_key);

        let decoded = jws.decode(&key_id_storage).unwrap();
        assert_eq!(decoded.payload(), &Some(String::from("test_payload")));
    }
}
