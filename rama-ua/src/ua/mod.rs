use serde::{Deserialize, Serialize};

mod info;
pub use info::{
    DeviceKind, HttpAgent, PlatformKind, TlsAgent, UserAgent, UserAgentInfo, UserAgentKind,
};

mod parse;
use parse::parse_http_user_agent_header;

/// Information that can be used to overwrite the [`UserAgent`] of an http request.
///
/// Used by the `UserAgentClassifier` (see `rama-http`) to overwrite the specified
/// information duing the classification of the [`UserAgent`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserAgentOverwrites {
    /// Overwrite the [`UserAgent`] of the http `Request` with a custom value.
    ///
    /// This value will be used instead of
    /// the 'User-Agent' http (header) value.
    ///
    /// This is useful in case you cannot set the User-Agent header in your request.
    pub ua: Option<String>,
    /// Overwrite the [`HttpAgent`] of the http `Request` with a custom value.
    pub http: Option<HttpAgent>,
    /// Overwrite the [`TlsAgent`] of the http `Request` with a custom value.
    pub tls: Option<TlsAgent>,
    /// Preserve the original [`UserAgent`] header of the http `Request`.
    pub preserve_ua: Option<bool>,
}

#[cfg(test)]
mod parse_tests;
