use rama_http_types::header::USER_AGENT;
use serde::{Deserialize, Serialize};

use crate::{PlatformKind, UserAgentKind};

#[derive(Debug, Clone, Deserialize, Serialize)]
/// The main profile for the user-agent.
///
/// It contains:
///
/// - identification information about the [`crate::UserAgent`]:
///   - [`UserAgentKind`]: indicating the user-agent "engine" (e.g. all chromium-based user-agents
///     will be [`UserAgentKind::Chromium`])
///   - Version of the user-agent (`ua_version`)
///   - [`PlatformKind`]: indicating the platform of the user-agent
/// - http requests headers fingerprint info and settings ([`HttpProfile`])
/// - client tls configuration ([`TlsProfile`])
/// - javascript (web APIs) information ([`JsProfile`])
///
/// [`HttpProfile`]: crate::profile::HttpProfile
/// [`TlsProfile`]: crate::profile::TlsProfile
/// [`JsProfile`]: crate::profile::JsProfile
pub struct UserAgentProfile {
    /// The kind of [`crate::UserAgent`]
    pub ua_kind: UserAgentKind,
    /// The version of the [`crate::UserAgent`]
    pub ua_version: Option<usize>,
    /// The platform the [`crate::UserAgent`] is running on.
    pub platform: Option<PlatformKind>,

    /// The profile information regarding the http implementation of the [`crate::UserAgent`].
    pub http: super::HttpProfile,

    #[cfg(feature = "tls")]
    /// The profile information regarding the tls implementation of the [`crate::UserAgent`].
    pub tls: super::TlsProfile,

    /// The information provivided by the js implementation of the [`crate::UserAgent`].
    pub js: Option<super::JsProfile>,
}

impl UserAgentProfile {
    /// Get the user-agent string of the [`crate::UserAgent`].
    ///
    /// Extracts the user-agent string from the http headers of the [`crate::UserAgent`].
    pub fn ua_str(&self) -> Option<&str> {
        if let Some(ua) = self
            .http
            .h1
            .headers
            .navigate
            .get(USER_AGENT)
            .and_then(|v| v.to_str().ok())
        {
            Some(ua)
        } else if let Some(ua) = self
            .http
            .h2
            .headers
            .navigate
            .get(USER_AGENT)
            .and_then(|v| v.to_str().ok())
        {
            Some(ua)
        } else {
            None
        }
    }
}
