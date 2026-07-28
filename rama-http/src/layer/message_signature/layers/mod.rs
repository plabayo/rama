//! Sign/verify/proxy layers for HTTP Message Signatures (feature `message-signature`).

mod config;
mod proxy;
mod sign;
mod util;
mod verify;

#[cfg(test)]
mod tests;

pub use config::{KeyidVerifierMap, SignConfig, StaticVerifier, VerifyConfig, VerifyKeyResolver};
pub use proxy::{
    AddProxyResponseSignature, AddProxyResponseSignatureLayer, AddProxySignature,
    AddProxySignatureLayer, ProxySignaturePolicy, ProxyVerifyAction,
};
pub use sign::{SignRequest, SignRequestLayer, SignResponse, SignResponseLayer};
pub use util::{default_request_components, default_response_components};
pub use verify::{VerifyRequest, VerifyRequestLayer, VerifyResponse, VerifyResponseLayer};
