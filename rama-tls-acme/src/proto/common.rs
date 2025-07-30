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
pub(crate) struct ProtectedHeader<'a> {
    #[serde(flatten)]
    pub(crate) crypto: ProtectedHeaderCrypto,
    #[serde(flatten)]
    pub(crate) acme: ProtectedHeaderAcme<'a>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ProtectedHeaderCrypto {
    /// Algorithm that was used to sign the JWS
    pub(crate) alg: JWA,
    #[serde(flatten)]
    /// JWK or KeyId which is used to identify this request
    pub(crate) key: ProtectedHeaderKey,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ProtectedHeaderAcme<'a> {
    /// Previous nonce that was given by the server to use
    pub(crate) nonce: Cow<'a, str>,
    /// Url of the acme endpoint for which we are making a request
    pub(crate) url: Cow<'a, str>,
}

#[derive(Debug, Serialize, Deserialize)]
/// [`ProtectedHeaderKey`] send as key for [`ProtectedHeader`]
///
/// `JWK` is used for the first request to create an account, once we
/// have an account we use the `KeyID` instead
pub(crate) enum ProtectedHeaderKey {
    #[serde(rename = "jwk")]
    Jwk(JWK),
    #[serde(rename = "kid")]
    KeyID(String),
}
