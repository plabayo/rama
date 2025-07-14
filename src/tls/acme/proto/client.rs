use std::{fmt::Debug, marker::PhantomData};

use super::{common::Identifier, server::Challenge};
use crate::crypto::dep::aws_lc_rs::{
    digest::{Digest, SHA256, digest},
    error::{KeyRejected, Unspecified},
    pkcs8,
    rand::SystemRandom,
    signature::{self, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
    signature::{KeyPair, Signature},
};
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
use rama_core::error::{BoxError, ErrorContext, OpaqueError};
use rama_crypto::jose::JWK;
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
    pub(crate) fn new(token: &str, jwk: &JWK) -> Result<Self, OpaqueError> {
        let thumb = BASE64_URL_SAFE_NO_PAD.encode(jwk.thumb_sha256()?);
        Ok(Self(format!("{}.{}", token, thumb)))
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

#[derive(Default, Debug, Serialize, Deserialize)]
/// Payload to request the certificate, defined in [rfc8555 section 7.4]
///
/// [rfc8555 section 7.4]: https://datatracker.ietf.org/doc/html/rfc8555/#section-7.4
pub struct FinalizePayload {
    /// Certificate signing request
    pub csr: String,
}
