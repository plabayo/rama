//! Protocol-owned observations attach through typed extensions. The HTTP inspector
//! never needs to import the observing protocol or know its metadata representation.
use rama_inspect::Observations;
use std::fmt;

/// Distinct ownership scopes for captured protocol observations.
#[derive(Debug, Clone, Default)]
pub struct CaptureMetadata {
    /// Observations shared by exchanges on the same downstream connection.
    pub connection: Observations,
    /// Observations belonging to this HTTP exchange.
    pub exchange: Observations,
    /// Observations of the upstream connection used for the response.
    pub upstream: Observations,
}

/// Optional enrichment at HTTP head boundaries. Protocol owners supply typed
/// observations through `CaptureMetadata`; no protocol-specific fields are required.
pub trait CaptureObserver: fmt::Debug + Send + Sync + 'static {
    fn request(&self, parts: &crate::request::Parts, metadata: &CaptureMetadata);
    fn response(&self, parts: &crate::response::Parts, metadata: &CaptureMetadata);
    /// Match protocol-owned observations without serializing them to an intermediate string.
    fn matches_search(&self, _metadata: &CaptureMetadata, _query: &str) -> bool {
        false
    }
}
impl CaptureObserver for () {
    fn request(&self, _: &crate::request::Parts, _: &CaptureMetadata) {}
    fn response(&self, _: &crate::response::Parts, _: &CaptureMetadata) {}
}

#[derive(Debug, Clone, rama_core::extensions::Extension)]
pub struct CaptureProtocol(pub rama_net::Protocol);
