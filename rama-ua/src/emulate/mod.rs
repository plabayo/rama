mod provider;
pub use provider::{UserAgentProvider, UserAgentSelectFallback};

mod layer;
pub use layer::UserAgentEmulateLayer;

mod service;
pub use service::{
    UserAgentEmulateHttpConnectModifier, UserAgentEmulateHttpRequestModifier,
    UserAgentEmulateService,
};
