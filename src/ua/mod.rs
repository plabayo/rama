//! User Agent (UA) parser and types.
//!
//! Learn more about User Agents (UA)
//! at <https://ramaproxy.org/book/intro/user_agent.html>.

mod info;
pub use info::{DeviceKind, HttpAgent, PlatformKind, TlsAgent, UserAgent, UserAgentKind};

mod parse;
use parse::parse_http_user_agent;
pub use parse::UserAgentParseError;

mod layer;
pub use layer::{UserAgentClassifier, UserAgentClassifierLayer};

#[cfg(test)]
mod parse_tests;
