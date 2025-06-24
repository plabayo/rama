use crate::dep::aws_lc_rs::{
    digest::Digest,
    rand::SystemRandom,
    signature::{self, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
    signature::{KeyPair, Signature},
};
use aws_lc_rs::{
    digest::{SHA256, digest},
    pkcs8::Document,
    signature::{
        ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaSigningAlgorithm,
        EcdsaVerificationAlgorithm,
    },
};
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
    /// HMAC using SHA-256 (Required)
    HS256,
    /// HMAC using SHA-384 (Optional)
    HS384,
    /// HMAC using SHA-512 (Optional)
    HS512,
    /// RSASSA-PKCS1-v1_5 using SHA-256 (Recommended)
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384 (Optional)
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512 (Optional)
    RS512,
    /// ECDSA using P-256 and SHA-256 (Recommended+)
    ES256,
    /// ECDSA using P-384 and SHA-384 (Optional)
    ES384,
    /// ECDSA using P-521 and SHA-512 (Optional)
    ES512,
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (Optional)
    PS256,
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384 (Optional)
    PS384,
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512 (Optional)
    PS512,
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
        crv: JWKellipticCurves,
        x: String,
        y: String,
    },
    /// an octet sequence key, which represents a symmetric key
    OCT {
        k: String,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum JWKellipticCurves {
    #[serde(rename = "P-256")]
    P256,
    #[serde(rename = "P-384")]
    P384,
    #[serde(rename = "P-521")]
    P521,
}

impl From<JWKellipticCurves> for JWA {
    fn from(value: JWKellipticCurves) -> Self {
        match value {
            JWKellipticCurves::P256 => Self::ES256,
            JWKellipticCurves::P384 => Self::ES384,
            JWKellipticCurves::P521 => Self::ES512,
        }
    }
}

impl TryFrom<JWA> for JWKellipticCurves {
    type Error = OpaqueError;

    fn try_from(value: JWA) -> Result<Self, Self::Error> {
        match value {
            JWA::ES256 => Ok(JWKellipticCurves::P256),
            JWA::ES384 => Ok(JWKellipticCurves::P384),
            JWA::ES512 => Ok(JWKellipticCurves::P521),
            JWA::HS256 | JWA::HS384 | JWA::HS512 => Err(OpaqueError::from_display(
                "Hmac cannot be converted to elliptic curve",
            )),
            JWA::RS256 | JWA::RS384 | JWA::RS512 | JWA::PS256 | JWA::PS384 | JWA::PS512 => Err(
                OpaqueError::from_display("RSA cannot be converted to elliptic curve"),
            ),
        }
    }
}

impl TryFrom<JWA> for &'static EcdsaVerificationAlgorithm {
    type Error = OpaqueError;

    fn try_from(value: JWA) -> Result<Self, Self::Error> {
        match value {
            JWA::ES256 => Ok(&ECDSA_P256_SHA256_FIXED),
            JWA::ES384 => Ok(&ECDSA_P384_SHA384_FIXED),
            JWA::ES512 => Ok(&ECDSA_P256_SHA256_FIXED),
            JWA::HS256 | JWA::HS384 | JWA::HS512 => Err(OpaqueError::from_display(
                "Hmac cannot be converted to elliptic curve",
            )),
            JWA::RS256 | JWA::RS384 | JWA::RS512 | JWA::PS256 | JWA::PS384 | JWA::PS512 => Err(
                OpaqueError::from_display("RSA cannot be converted to elliptic curve"),
            ),
        }
    }
}

impl TryFrom<JWA> for &'static EcdsaSigningAlgorithm {
    type Error = OpaqueError;

    fn try_from(value: JWA) -> Result<Self, Self::Error> {
        match value {
            JWA::ES256 => Ok(&ECDSA_P256_SHA256_FIXED_SIGNING),
            JWA::ES384 => Ok(&ECDSA_P384_SHA384_FIXED_SIGNING),
            JWA::ES512 => Ok(&ECDSA_P256_SHA256_FIXED_SIGNING),
            JWA::HS256 | JWA::HS384 | JWA::HS512 => Err(OpaqueError::from_display(
                "Hmac cannot be converted to elliptic curve",
            )),
            JWA::RS256 | JWA::RS384 | JWA::RS512 | JWA::PS256 | JWA::PS384 | JWA::PS512 => Err(
                OpaqueError::from_display("RSA cannot be converted to elliptic curve"),
            ),
        }
    }
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
    fn new_for_escdsa_keypair(key: &EcdsaKeyPair, alg: JWA) -> Result<Self, OpaqueError> {
        let curve = alg.try_into()?;
        // 0x04 prefix + x + y
        let pub_key = key.public_key().as_ref();
        let middle = (pub_key.len() - 1) / 2;
        let (x, y) = key.public_key().as_ref()[1..].split_at(middle);

        Ok(Self {
            alg,
            key_type: JWKType::EC {
                crv: curve,
                x: BASE64_URL_SAFE_NO_PAD.encode(x),
                y: BASE64_URL_SAFE_NO_PAD.encode(y),
            },
            r#use: Some(JWKUse::Signature),
            key_ops: None,
            x5c: None,
            x5t: None,
            x5t_sha256: None,
        })
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

    /// Convert this [`JWK`] to an unparsed public key which can be used to verify signatures
    ///
    /// Warning no verification is done on this key until `.verify` is called
    pub fn unparsed_public_key(
        &self,
    ) -> Result<signature::UnparsedPublicKey<Vec<u8>>, OpaqueError> {
        match &self.key_type {
            JWKType::RSA { .. } => Err(OpaqueError::from_display("currently not supported")),
            JWKType::OCT { .. } => Err(OpaqueError::from_display(
                "Symmetric key cannot be converted to public key",
            )),
            JWKType::EC { crv, x, y } => {
                let alg: &'static EcdsaVerificationAlgorithm =
                    JWA::from(crv.to_owned()).try_into()?;

                let x_bytes = BASE64_URL_SAFE_NO_PAD.decode(x).unwrap();
                let y_bytes = BASE64_URL_SAFE_NO_PAD.decode(y).unwrap();

                let mut point_bytes = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
                point_bytes.push(0x04);
                point_bytes.extend_from_slice(&x_bytes);
                point_bytes.extend_from_slice(&y_bytes);

                Ok(signature::UnparsedPublicKey::new(alg, point_bytes))
            }
        }
    }
}

/// [`EcdsaKey`] which is used to identify and authenticate our requests
///
/// This contains the private and public key we will be using for JWS
pub struct EcdsaKey {
    rng: SystemRandom,
    alg: JWA,
    inner: EcdsaKeyPair,
}

impl EcdsaKey {
    /// Create a new [`EcdsaKey`] from the given EcdsaKeyPair
    pub fn new(key_pair: EcdsaKeyPair, alg: JWA, rng: SystemRandom) -> Result<Self, OpaqueError> {
        // Check if passed algorithm is a correct elliptic curve one
        let _curve = JWKellipticCurves::try_from(alg)?;
        Ok(Self {
            rng,
            alg,
            inner: key_pair,
        })
    }

    /// Generate a new [`Key`] from a newly generated [`EcdsaKeyPair`] using P-256 EC
    pub fn generate() -> Result<Self, OpaqueError> {
        let key_pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING)
            .context("generate EcdsaKeyPair")?;

        Self::new(key_pair, JWA::ES256, SystemRandom::new())
    }

    /// Generate a new [`Key`] from the given pkcs8 der
    pub fn from_pkcs8_der(
        pkcs8_der: &[u8],
        alg: JWA,
        rng: SystemRandom,
    ) -> Result<Self, OpaqueError> {
        let ec_alg: &'static EcdsaSigningAlgorithm = alg.try_into()?;
        let key_pair = EcdsaKeyPair::from_pkcs8(ec_alg, pkcs8_der)
            .context("create EcdsaKeyPair from pkcs8")?;

        Self::new(key_pair, alg, rng)
    }

    pub fn pkcs8_der(&self) -> Result<(JWA, Document), OpaqueError> {
        let doc = self
            .inner
            .to_pkcs8v1()
            .context("create pkcs8 der from keypair")?;
        Ok((self.alg, doc))
    }

    pub fn create_jwk(&self) -> JWK {
        // `expect` because `new_for_escdsa_keypair`` can only fail if curve is not elliptic but we also check that in `new`
        JWK::new_for_escdsa_keypair(&self.inner, self.alg).expect("create JWK from escdsa keypair")
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

impl Signer for EcdsaKey {
    type Signature = Signature;

    fn protected_header<'n, 'u: 'n, 's: 'u>(
        &'s self,
        nonce: Option<&'n str>,
        url: &'u str,
    ) -> ProtectedHeader<'n> {
        ProtectedHeader {
            alg: self.alg,
            key: ProtectedHeaderKey::JWK(self.create_jwk()),
            nonce,
            url,
        }
    }

    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, BoxError> {
        Ok(self.inner.sign(&self.rng, payload)?)
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
            crv: JWKellipticCurves::P256,
            x: "x".into(),
            y: "y".into(),
        };
        let output = serde_json::to_string(&jwk_type).unwrap();
        let expected_output = r##"{"crv":"P-256","kty":"EC","x":"x","y":"y"}"##;
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
        let key = EcdsaKey::generate().unwrap();
        let stored = key.pkcs8_der().unwrap();
        let recreated_key =
            EcdsaKey::from_pkcs8_der(stored.1.as_ref(), stored.0, SystemRandom::new()).unwrap();

        assert_eq!(key.create_jwk(), recreated_key.create_jwk())
    }

    #[test]
    fn can_encode_and_decode_jws_with_payload() {
        let key = EcdsaKey::generate().unwrap();
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
        let key = EcdsaKey::generate().unwrap();
        let nonce = "test_nonce";
        let url = "http://test.test";
        let protected_header = key.protected_header(Some(nonce), url);
        let jws = JWS::new(NO_PAYLOAD, &protected_header, &key).unwrap();

        let decoded = jws.decode_without_key_id_support().unwrap();
        assert_eq!(decoded.payload(), &None);
    }

    #[test]
    fn can_encode_and_decode_jws_with_empty_payload() {
        let key = EcdsaKey::generate().unwrap();
        let nonce = "test_nonce";
        let url = "http://test.test";
        let protected_header = key.protected_header(Some(nonce), url);
        let jws = JWS::new(EMPTY_PAYLOAD, &protected_header, &key).unwrap();
        let decoded = jws.decode_without_key_id_support().unwrap();
        assert_eq!(decoded.payload(), &Some(Empty));
    }

    #[test]
    fn should_serialize_correctly() {
        let key = EcdsaKey::generate().unwrap();
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
            key: EcdsaKey,
            id: String,
        }

        impl Signer for KeyId {
            type Signature = <EcdsaKey as Signer>::Signature;

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

        let key = EcdsaKey::generate().unwrap();
        let signer = KeyId {
            id: "test_id".into(),
            key,
        };
        let pub_key = JWK::new_for_escdsa_keypair(&signer.key.inner, JWA::ES256)
            .unwrap()
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
