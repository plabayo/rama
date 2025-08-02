use std::borrow::Cow;

use rama_crypto::jose::{JWA, JWK};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
/// Represent an identifier in an ACME order
pub enum Identifier {
    Dns(String),
}

impl From<Identifier> for String {
    fn from(identifier: Identifier) -> Self {
        match identifier {
            Identifier::Dns(value) => value,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
/// JWS protected header for acme requests, such as defined in [rfc8555 section 6.2]
///
/// [rfc8555 section 6.2]: https://datatracker.ietf.org/doc/html/rfc8555/#section-6.2
pub struct ProtectedHeader<'a> {
    #[serde(flatten)]
    pub crypto: ProtectedHeaderCrypto<'a>,
    #[serde(flatten)]
    pub acme: ProtectedHeaderAcme<'a>,
}

#[derive(Debug, Serialize, Deserialize)]
/// Cryptographic part of the [`ProtectedHeader`]
pub struct ProtectedHeaderCrypto<'a> {
    /// Algorithm that was used to sign the JWS
    pub alg: JWA,
    #[serde(flatten)]
    /// JWK or KeyId which is used to identify this request
    pub key: ProtectedHeaderKey<'a>,
}

#[derive(Debug, Serialize, Deserialize)]
/// Acme specific part of the [`ProtectedHeader`]
pub struct ProtectedHeaderAcme<'a> {
    /// Previous nonce that was given by the server to use
    pub nonce: Cow<'a, str>,
    /// Url of the acme endpoint for which we are making a request
    pub url: Cow<'a, str>,
}

#[derive(Debug, Serialize, Deserialize)]
/// [`ProtectedHeaderKey`] send as key for [`ProtectedHeader`]
///
/// `JWK` is used for the first request to create an account, once we
/// have an account we use the `KeyID` instead
pub enum ProtectedHeaderKey<'a> {
    #[serde(rename = "jwk")]
    Jwk(Cow<'a, JWK>),
    #[serde(rename = "kid")]
    KeyID(Cow<'a, str>),
}
