use serde::{Deserialize, Serialize};

use super::common::Identifier;

pub const REPLAY_NONCE_HEADER: &str = "replay-nonce";
pub const LOCATION_HEADER: &str = "location";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Directory containing all endpoints needed by an acme client, defined in [rfc8555 section 7.1.1]
///
/// The directory is a JSON object that lists the URLs of the ACME server’s key endpoints.
/// This directory allows clients to dynamically discover where to send their requests,
/// enabling interoperability and flexibility without hardcoded URLs.
///
/// [rfc8555 section 7.1.1]: https://datatracker.ietf.org/doc/html/rfc8555/#section-7.1.1
pub struct Directory {
    /// URL for requesting a new nonce
    pub new_nonce: String,
    /// URL for creating a new account
    pub new_account: String,
    /// URL for creating a new order
    pub new_order: String,
    /// Optional URL for creating new authorization objects (not required by all CAs)
    ///
    /// new_authz is short for new authorization. We use the shorter name so we use
    /// the same naming as in the rfc
    pub new_authz: Option<String>,
    /// URL for revoking a certificate
    pub revoke_cert: String,
    /// URL for submitting a key change request
    pub key_change: String,
    /// Optional metadata provided by the CA
    pub meta: Option<DirectoryMeta>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Extra metadata that acme server can return
pub struct DirectoryMeta {
    /// URL to the CA’s terms of service, if any
    pub terms_of_service: Option<String>,
    /// URL to the CA’s website, if any
    pub website: Option<String>,
    /// List of CAA (Certification Authority Authorization) identities supported by the CA
    pub caa_identities: Option<Vec<String>>,
    /// Whether the CA requires external account binding
    pub external_account_required: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// [`Account`] info returned by the acme server, defined in [rfc8555 section 7.1.2]
///
/// [rfc8555 section 7.1.2]: https://datatracker.ietf.org/doc/html/rfc8555/#section-7.1.2
pub struct Account {
    /// Current status of this account
    pub status: AccountStatus,
    /// Contact info provided by this account
    pub contact: Option<Vec<String>>,
    /// Did account already agree to terms of service
    pub terms_of_service_agreed: Option<bool>,
    /// TODO
    pub external_account_binding: Option<()>,
    /// Url to fetch list of orders created by this account
    pub orders: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Current account status
pub enum AccountStatus {
    /// Valid account
    Valid,
    /// Client side initiated deactivation
    Deactivated,
    /// Server side initiated deactivation
    Revoked,
}

//

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// List of [`Order`]s currently opened by an account, defined in [rfc8555 section 7.1.2.1]
///
/// WARNING: TODO support incomplete response with link header
///
/// [rfc8555 section 7.1.2.1]: https://datatracker.ietf.org/doc/html/rfc8555/#section-7.1.2.1
pub struct OrdersList {
    // List of urls, each identifying an order belonging to the account
    pub orders: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// All info about a specific [`Order`], defined in [rfc8555 section 7.1.3]
///
/// [rfc8555 section 7.1.3]: https://datatracker.ietf.org/doc/html/rfc8555/#section-7.1.3
pub struct Order {
    /// Current status of this order
    pub status: OrderStatus,
    /// When this order will expire when status is pending or valid
    pub expires: Option<String>,
    /// [`Identifier`] linked to this request
    pub identifiers: Vec<Identifier>,
    /// Requested value of not_before field in certificate
    pub not_before: Option<String>,
    /// Requested value of not_after field in certificate
    pub not_after: Option<String>,
    /// Error if any occurred while processing this order
    pub error: Option<Problem>,
    /// List of authorization urls to get [`Authorization`] info
    ///
    /// For pending orders these are a list of authorizations that the clients
    /// needs to complete. For final (valid or invalid) orders this contains
    /// the list authorizations that were completed by the client
    pub authorizations: Vec<String>,
    /// URL where to post CSR once all authorizations have been completed
    pub finalize: String,
    /// URL of cert that has been issued if all went well
    pub certificate: Option<String>,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
/// Current status of an [`Order`]
pub enum OrderStatus {
    /// Default when created
    Pending,
    /// All authorizations are in valid state
    Ready,
    /// Submitted finalize url with CSR
    Processing,
    /// Certificate was succesfully issued
    Valid,
    /// Error happens during any other state, or it expired, or any of the
    /// authorizations moves to a final state which is not valid
    Invalid,
}

// 7.1.4 Authorization Objects
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// All info about a specific [`Authorization`], defined in [rfc8555 section 7.1.4]
///
/// [rfc8555 section 7.1.4]: https://datatracker.ietf.org/doc/html/rfc8555/#section-7.1.4
pub struct Authorization {
    pub identifier: Identifier,
    pub status: AuthorizationStatus,
    // Required for valid status
    pub expires: Option<String>,
    pub challenges: Vec<Challenge>,
    pub wildcard: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AuthorizationStatus {
    /// Default when created
    Pending,
    /// One challenge moves to valid
    Valid,
    /// Fails to validate or error when authorization pending
    Invalid,
    /// Deactivated by client itself
    Deactivated,
    /// Was valid but expired
    Expired,
    /// Revoked by server
    Revoked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// All info about a specific [`Challenge`], defined in [rfc8555 section 7.1.5]
///
/// [rfc8555 section 7.1.5]: https://datatracker.ietf.org/doc/html/rfc8555/#section-7.1.5
pub struct Challenge {
    /// Type of challenge
    pub r#type: ChallengeType,
    /// Challenge identifier
    pub url: String,
    /// Token for this challenge
    pub token: String,
    /// Current status
    pub status: ChallengeStatus,
    /// Potential error state
    pub error: Option<Problem>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
/// Type of acme challenge
pub enum ChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
    #[serde(untagged)]
    Unknown(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
/// Current status of a [`Challenge`]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
/// Problem response such as described in [rfc7808]
///
/// [rfc7808]: https://datatracker.ietf.org/doc/html/rfc7807
pub struct RawProblemResponse {
    pub r#type: String,
    pub detail: Option<String>,
}

impl std::fmt::Display for RawProblemResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.detail.as_ref() {
            Some(detail) => write!(f, "problem {}: {}", self.r#type, detail),
            None => write!(f, "problem {}", self.r#type),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "type", content = "detail")]
/// Problem types used by acme server, as described in [rfc8555 section 6.7]
///
/// [rfc8555 section 6.7]: https://datatracker.ietf.org/doc/html/rfc8555#section-6.7
pub enum Problem {
    /// The request specified an account that does not exist
    #[serde(rename = "urn:ietf:params:acme:error:accountDoesNotExist")]
    AccountDoesNotExist(String),
    /// The request specified a certificate to be revoked that has already been revoked
    #[serde(rename = "urn:ietf:params:acme:error:alreadyRevoked")]
    AlreadyRevoked(String),
    /// The CSR is unacceptable (e.g., due to a short key)
    #[serde(rename = "urn:ietf:params:acme:error:badCSR")]
    BadCSR(String),
    /// The client sent an unacceptable antireplay none
    #[serde(rename = "urn:ietf:params:acme:error:badNonce")]
    BadNonce(String),
    /// The JWS was signed by a public key the server does not support
    #[serde(rename = "urn:ietf:params:acme:error:badPublicKey")]
    BadPublicKey(String),
    /// The revocation reason provided is not allowed by the server
    #[serde(rename = "urn:ietf:params:acme:error:badRevocationReason")]
    BadRevocationReason(String),
    /// The JWS was signed with an algorithm the server does not support
    #[serde(rename = "urn:ietf:params:acme:error:badSignatureAlgorithm")]
    BadSignatureAlgorithm(String),
    /// Certification Authority Authorization (CAA) records forbid the CA from issuing a certificate
    #[serde(rename = "urn:ietf:params:acme:error:caa")]
    Caa(String),
    /// Specific error conditions are indicated in the "subproblems" array
    #[serde(rename = "urn:ietf:params:acme:error:compound")]
    Compound(String),
    /// The server could not connect to validation target
    #[serde(rename = "urn:ietf:params:acme:error:connection")]
    Connection(String),
    /// There was a problem with a DNS query during identifier validation
    #[serde(rename = "urn:ietf:params:acme:error:dns")]
    Dns(String),
    /// The request must include a value for the "externalAccountBinding" field
    #[serde(rename = "urn:ietf:params:acme:error:externalAccountRequired")]
    ExternalAccountRequired(String),
    /// Response received didn't match the challenge’s requirements
    #[serde(rename = "urn:ietf:params:acme:error:incorrectResponse")]
    IncorrectResponse(String),
    /// A contact URL for an account was invalid
    #[serde(rename = "urn:ietf:params:acme:error:invalidContact")]
    InvalidContact(String),
    /// The request message was malformed
    #[serde(rename = "urn:ietf:params:acme:error:malformed")]
    Malformed(String),
    /// The request attempted to finalize an order that is not ready to be finalized
    #[serde(rename = "urn:ietf:params:acme:error:orderNotReady")]
    OrderNotReady(String),
    /// The request exceeds a rate limit
    #[serde(rename = "urn:ietf:params:acme:error:rateLimited")]
    RateLimited(String),
    /// The server will not issue certificates for the identifier
    #[serde(rename = "urn:ietf:params:acme:error:rejectedIdentifier")]
    RejectedIdentifier(String),
    /// The server experienced an internal error
    #[serde(rename = "urn:ietf:params:acme:error:serverInternal")]
    ServerInternal(String),
    /// The server received a TLS error during validation
    #[serde(rename = "urn:ietf:params:acme:error:tls")]
    Tls(String),
    /// The client lacks sufficient authorization
    #[serde(rename = "urn:ietf:params:acme:error:unauthorized")]
    Unauthorized(String),
    /// A contact URL for an account used an unsupported protocol scheme
    #[serde(rename = "urn:ietf:params:acme:error:unsupportedContact")]
    UnsupportedContact(String),
    /// An identifier is of an unsupported type
    #[serde(rename = "urn:ietf:params:acme:error:unsupportIdentifier")]
    UnsupportIdentifier(String),
    /// Visit the "instance" URL and take actions specified there
    #[serde(rename = "urn:ietf:params:acme:error:userActionRequired")]
    UserActionRequired(String),
    /// Other errors are possible since list in rfc in non exhaustive
    #[serde(untagged)]
    Other(RawProblemResponse),
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::AccountDoesNotExist(detail) => write!(f, "account does not exist: {detail}"),
            Self::AlreadyRevoked(detail) => write!(f, "already revoked: {detail}"),
            Self::BadCSR(detail) => write!(f, "bad csr: {detail}"),
            Self::BadNonce(detail) => write!(f, "bad nonce: {detail}"),
            Self::BadPublicKey(detail) => write!(f, "bad public key: {detail}"),
            Self::BadRevocationReason(detail) => write!(f, "bad revocation reason: {detail}"),
            Self::BadSignatureAlgorithm(detail) => {
                write!(f, "bad signature algorithm: {detail}")
            }
            Self::Caa(detail) => write!(f, "caa forbids requests: {detail}"),
            Self::Compound(detail) => write!(f, "compound issue: {detail}"),
            Self::Connection(detail) => write!(f, "connection issue: {detail}"),
            Self::Dns(detail) => write!(f, "dns issue: {detail}"),
            Self::ExternalAccountRequired(detail) => {
                write!(f, "external account required: {detail}")
            }
            Self::IncorrectResponse(detail) => write!(f, "incorrect response: {detail}"),
            Self::InvalidContact(detail) => write!(f, "invalid contact: {detail}"),
            Self::Malformed(detail) => write!(f, "malformed data: {detail}"),
            Self::OrderNotReady(detail) => write!(f, "order not ready: {detail}"),
            Self::RateLimited(detail) => write!(f, "rate limited: {detail}"),
            Self::RejectedIdentifier(detail) => write!(f, "rejected identifier: {detail}"),
            Self::ServerInternal(detail) => write!(f, "server internal error: {detail}"),
            Self::Tls(detail) => write!(f, "tls issue: {detail}"),
            Self::Unauthorized(detail) => write!(f, "unauthorized: {detail}"),
            Self::UnsupportedContact(detail) => write!(f, "unsupported contact: {detail}"),
            Self::UnsupportIdentifier(detail) => write!(f, "unsupport identifier: {detail}"),
            Self::UserActionRequired(detail) => write!(f, "user action required: {detail}"),
            Self::Other(raw_problem_response) => raw_problem_response.fmt(f),
        }
    }
}

impl std::error::Error for Problem {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // https://datatracker.ietf.org/doc/html/rfc8555#section-7.4
    fn order() {
        const EXAMPLE: &str = r#"{
            "status": "pending",
            "expires": "2016-01-05T14:09:07.99Z",

            "notBefore": "2016-01-01T00:00:00Z",
            "notAfter": "2016-01-08T00:00:00Z",

            "identifiers": [
                { "type": "dns", "value": "www.example.org" },
                { "type": "dns", "value": "example.org" }
            ],

            "authorizations": [
                "https://example.com/acme/authz/PAniVnsZcis",
                "https://example.com/acme/authz/r4HqLzrSrpI"
            ],

            "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
        }"#;

        let obj = serde_json::from_str::<Order>(EXAMPLE).unwrap();
        assert_eq!(obj.status, OrderStatus::Pending);
        assert_eq!(obj.identifiers.len(), 2);
        assert_eq!(obj.authorizations.len(), 2);
        assert_eq!(
            obj.finalize,
            "https://example.com/acme/order/TOlocE8rfgo/finalize"
        );
    }

    // https://datatracker.ietf.org/doc/html/rfc8555#section-7.5.1
    #[test]
    fn authorization() {
        const EXAMPLE: &str = r#"{
          "status": "valid",
          "expires": "2018-09-09T14:09:01.13Z",

          "identifier": {
            "type": "dns",
            "value": "www.example.org"
          },

          "challenges": [
            {
              "type": "http-01",
              "url": "https://example.com/acme/chall/prV_B7yEyA4",
              "status": "valid",
              "validated": "2014-12-01T12:05:13.72Z",
              "token": "IlirfxKKXAsHtmzK29Pj8A"
            }
          ]
        }"#;

        let obj = serde_json::from_str::<Authorization>(EXAMPLE).unwrap();
        assert_eq!(obj.status, AuthorizationStatus::Valid);
        assert_eq!(obj.identifier, Identifier::Dns("www.example.org".into()));
        assert_eq!(obj.challenges.len(), 1);
        assert_eq!(obj.challenges[0].r#type, ChallengeType::Http01);
        assert_eq!(obj.challenges[0].status, ChallengeStatus::Valid);
        assert_eq!(obj.challenges[0].token, "IlirfxKKXAsHtmzK29Pj8A");
    }

    // https://datatracker.ietf.org/doc/html/rfc8555#section-8.4
    #[test]
    fn challenge() {
        const EXAMPLE: &str = r#"{
          "type": "dns-01",
          "url": "https://example.com/acme/chall/Rg5dV14Gh1Q",
          "status": "pending",
          "token": "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"
        }"#;

        let obj = serde_json::from_str::<Challenge>(EXAMPLE).unwrap();
        assert_eq!(obj.r#type, ChallengeType::Dns01);
        assert_eq!(obj.url, "https://example.com/acme/chall/Rg5dV14Gh1Q");
        assert_eq!(obj.status, ChallengeStatus::Pending);
        assert_eq!(obj.token, "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA");
    }

    // https://datatracker.ietf.org/doc/html/rfc8555#section-7.6
    #[test]
    fn handle_expected_problem() {
        const EXAMPLE: &str = r#"{
          "type": "urn:ietf:params:acme:error:unauthorized",
          "detail": "No authorization provided for name example.org"
        }"#;

        let problem = serde_json::from_str::<Problem>(EXAMPLE).unwrap();

        match problem {
            Problem::Unauthorized(detail) => assert_eq!(
                detail,
                String::from("No authorization provided for name example.org")
            ),
            _ => assert!(matches!(problem, Problem::Unauthorized { .. })),
        }
    }

    #[test]
    fn handle_unexpected_problem() {
        const EXAMPLE: &str = r#"{
          "type": "not:known:error",
          "detail": "something special that is not mentioned in rfc"
        }"#;

        let problem = serde_json::from_str::<Problem>(EXAMPLE).unwrap();

        match problem {
            Problem::Other(raw_problem) => {
                assert_eq!(raw_problem.r#type, String::from("not:known:error"));
                assert_eq!(
                    raw_problem.detail,
                    Some(String::from(
                        "something special that is not mentioned in rfc"
                    ))
                )
            }
            _ => assert!(matches!(problem, Problem::Other { .. })),
        }
    }
}
