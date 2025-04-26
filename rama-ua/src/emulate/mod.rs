//! Emulate user agent (UA) profiles.
//!
//! This module contains the profiles for the User Agent (UA) that are used for emulation.
//!
//! Learn more about User Agents (UA) and why Rama supports it
//! at <https://ramaproxy.org/book/intro/user_agent.html>.
//!
//! ## Ethics
//!
//! At [Plabayo](https://plabayo.tech), we support the principle that
//! [information wants to be free](https://en.wikipedia.org/wiki/Information_wants_to_be_free),
//! provided it is pursued ethically and within the bounds of applicable law.
//!
//! We do not endorse or support any malicious use of our technology.
//! We advocate for the programmatic retrieval of publicly available data
//! only when conducted responsibly — in a manner that is respectful,
//! does not impose an undue burden on servers, and avoids causing
//! disruption, harm, or degradation to third-party services.

mod provider;
pub use provider::{SelectedUserAgentProfile, UserAgentProvider, UserAgentSelectFallback};

mod layer;
pub use layer::UserAgentEmulateLayer;

mod service;
pub use service::{
    UserAgentEmulateHttpConnectModifier, UserAgentEmulateHttpRequestModifier,
    UserAgentEmulateService,
};
