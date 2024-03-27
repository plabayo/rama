//! User agent modules for Rama.

mod info;
pub use info::{HttpAgent, Platform, TlsAgent, UserAgentInfo, UserAgentKind};

mod parse;
pub use parse::{parse_http_user_agent, UserAgentParseError};

#[derive(Debug)]
#[non_exhaustive]
/// User agent
///
/// TODO: develop first version of this struct
pub struct UserAgent;
