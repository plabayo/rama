//! Emulate user agent (UA) profiles.
//!
//! This module contains the profiles for the User Agent (UA) that are used for emulation.
//!
//! Learn more about User Agents (UA) and why Rama supports it
//! at <https://ramaproxy.org/book/intro/user_agent.html>.
//!

mod provider;
pub use provider::{SelectedUserAgentProfile, UserAgentProvider, UserAgentSelectFallback};

mod layer;
pub use layer::UserAgentEmulateLayer;

mod service;
pub use service::{
    UserAgentEmulateHttpConnectModifier, UserAgentEmulateHttpRequestModifier,
    UserAgentEmulateService,
};
