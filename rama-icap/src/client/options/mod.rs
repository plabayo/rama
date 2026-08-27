//! Typed ICAP OPTIONS discovery and caching.

mod cache;
mod capabilities;
mod service;

pub use cache::{OptionsCache, OptionsCacheConfig, OptionsCacheHandle, OptionsCacheLayer};
pub use capabilities::{
    AllowedFeatures, CapabilitiesError, MethodSupport, ServiceCapabilities, SupportedMethods,
    TransferDisposition, TransferRules,
};
pub use service::{
    DEFAULT_MAX_OPTIONS_BODY_BYTES, OptionsCachePartition, OptionsRequest, OptionsRequestError,
    OptionsService,
};

/// Semantic validation applied after safe wire framing is decoded.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OptionsValidation {
    /// Preserve usable metadata and disable only malformed capabilities.
    #[default]
    Compatible,
    /// Require mandatory fields and reject inconsistent typed capabilities.
    Strict,
}
