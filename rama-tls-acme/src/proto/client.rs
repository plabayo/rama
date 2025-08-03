use super::common::Identifier;
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
use rama_core::error::OpaqueError;
use rama_crypto::dep::aws_lc_rs::digest::{SHA256, digest};
use rama_crypto::jose::JWK;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Options used to create a new account, or request an identifier for an existing account, defined in [rfc8555 section 7.3]
///
/// [rfc8555 section 7.3]: https://datatracker.ietf.org/doc/html/rfc8555/#section-7.3
pub struct CreateAccountOptions {
    /// Contact URLs for the account (e.g., "mailto:")
    pub contact: Option<Vec<String>>,
    /// Indicates agreement with the terms of service
    pub terms_of_service_agreed: Option<bool>,
    /// If true, only return an existing account; do not create a new one
    pub only_return_existing: Option<bool>,
    /// Placeholder for external account binding (not yet supported)
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
        Ok(Self(format!("{token}.{thumb}")))
    }

    /// Encode [`KeyAuthorization`] for use in Http challenge
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Encode [`KeyAuthorization`] for use in tls alpn challenge
    #[must_use]
    pub fn digest(&self) -> impl AsRef<[u8]> {
        digest(&SHA256, self.0.as_bytes())
    }

    /// Encode [`KeyAuthorization`] for use in dns challenge
    #[must_use]
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
