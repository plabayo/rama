//! Sign/verify layers for HTTP Message Signatures (feature `message-signature`).

mod config;
mod sign;
mod util;
mod verify;

#[cfg(test)]
mod tests;

pub use config::{KeyidVerifierMap, SignConfig, StaticVerifier, VerifyConfig, VerifyKeyResolver};
pub use sign::{SignRequest, SignRequestLayer, SignResponse, SignResponseLayer};
pub use util::default_request_components;
pub use verify::{
    VerifyRequest, VerifyRequestLayer, VerifyResponse, VerifyResponseLayer,
};
