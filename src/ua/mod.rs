//! User Agent (UA) parser and types.
//!
//! Learn more about User Agents (UA)
//! at <https://ramaproxy.org/book/intro/user_agent.html>.

mod info;
pub use info::{HttpAgent, PlatformKind, TlsAgent, UserAgent, UserAgentKind};

mod parse;
use parse::parse_http_user_agent;
pub use parse::UserAgentParseError;

#[cfg(test)]
mod tests;
