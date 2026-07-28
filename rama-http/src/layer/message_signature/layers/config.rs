//! Shared configuration for HTTP Message Signature layers.

use rama_crypto::http_message_signature::{HttpMessageSigner, HttpMessageVerifier};
use rama_http_headers::signature_input::ComponentIdentifier;
use std::sync::Arc;
use std::time::Duration;

/// Configuration for signing an HTTP message.
#[derive(Clone)]
pub struct SignConfig {
    pub signer: Arc<dyn HttpMessageSigner>,
    pub keyid: Option<String>,
    pub label: String,
    pub components: Vec<ComponentIdentifier>,
    pub include_created: bool,
    pub expires_after: Option<Duration>,
    pub tag: Option<String>,
    pub include_alg: bool,
}

impl SignConfig {
    pub fn new(signer: Arc<dyn HttpMessageSigner>, components: Vec<ComponentIdentifier>) -> Self {
        Self {
            signer,
            keyid: None,
            label: "sig".into(),
            components,
            include_created: true,
            expires_after: None,
            tag: None,
            include_alg: true,
        }
    }

    #[must_use]
    pub fn with_keyid(mut self, keyid: impl Into<String>) -> Self {
        self.keyid = Some(keyid.into());
        self
    }

    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    #[must_use]
    pub fn with_expires_after(mut self, d: Duration) -> Self {
        self.expires_after = Some(d);
        self
    }

    #[must_use]
    pub fn without_created(mut self) -> Self {
        self.include_created = false;
        self
    }

    #[must_use]
    pub fn without_alg(mut self) -> Self {
        self.include_alg = false;
        self
    }
}

/// Resolve a verifier for a given `keyid` (and optional `alg`).
pub trait VerifyKeyResolver: Send + Sync {
    fn resolve(
        &self,
        keyid: Option<&str>,
        alg: Option<&str>,
    ) -> Option<Arc<dyn HttpMessageVerifier>>;
}

/// Always returns the same verifier (ignores keyid/alg).
#[derive(Clone)]
pub struct StaticVerifier {
    verifier: Arc<dyn HttpMessageVerifier>,
}

impl StaticVerifier {
    pub fn new(verifier: Arc<dyn HttpMessageVerifier>) -> Self {
        Self { verifier }
    }
}

impl VerifyKeyResolver for StaticVerifier {
    fn resolve(
        &self,
        _keyid: Option<&str>,
        _alg: Option<&str>,
    ) -> Option<Arc<dyn HttpMessageVerifier>> {
        Some(self.verifier.clone())
    }
}

/// Map of keyid → verifier.
#[derive(Clone, Default)]
pub struct KeyidVerifierMap {
    map: Arc<ahash::HashMap<String, Arc<dyn HttpMessageVerifier>>>,
    /// Fallback when keyid is missing or unknown.
    fallback: Option<Arc<dyn HttpMessageVerifier>>,
}

impl KeyidVerifierMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(
        mut self,
        keyid: impl Into<String>,
        verifier: Arc<dyn HttpMessageVerifier>,
    ) -> Self {
        Arc::make_mut(&mut self.map).insert(keyid.into(), verifier);
        self
    }

    #[must_use]
    pub fn with_fallback(mut self, verifier: Arc<dyn HttpMessageVerifier>) -> Self {
        self.fallback = Some(verifier);
        self
    }
}

impl VerifyKeyResolver for KeyidVerifierMap {
    fn resolve(
        &self,
        keyid: Option<&str>,
        _alg: Option<&str>,
    ) -> Option<Arc<dyn HttpMessageVerifier>> {
        if let Some(id) = keyid
            && let Some(v) = self.map.get(id)
        {
            return Some(v.clone());
        }
        self.fallback.clone()
    }
}

/// Configuration for verifying an HTTP message signature.
#[derive(Clone)]
pub struct VerifyConfig {
    pub resolver: Arc<dyn VerifyKeyResolver>,
    /// Label to verify; if `None`, verify the first / only label present.
    pub label: Option<String>,
    pub max_age: Option<Duration>,
    pub clock_skew: Duration,
    pub require_created: bool,
}

impl VerifyConfig {
    pub fn new(resolver: Arc<dyn VerifyKeyResolver>) -> Self {
        Self {
            resolver,
            label: None,
            max_age: Some(Duration::from_secs(300)),
            clock_skew: Duration::from_secs(60),
            require_created: true,
        }
    }

    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    #[must_use]
    pub fn with_max_age(mut self, d: Option<Duration>) -> Self {
        self.max_age = d;
        self
    }

    #[must_use]
    pub fn with_clock_skew(mut self, d: Duration) -> Self {
        self.clock_skew = d;
        self
    }
}
