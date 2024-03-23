//! User agent modules for Rama.

mod info;
pub use info::{HttpAgent, Platform, TlsAgent, UserAgentInfo, UserAgentKind};

#[derive(Debug)]
#[non_exhaustive]
/// User agent
///
/// TODO: develop first version of this struct
pub struct UserAgent;
