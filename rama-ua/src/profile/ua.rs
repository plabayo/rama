use std::sync::Arc;

use rama_http::header::USER_AGENT;
use serde::{Deserialize, Serialize};

use crate::{PlatformKind, UserAgentKind};

use super::JsProfile;

#[derive(Debug, Clone)]
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
    #[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
    /// The profile information regarding the tls implementation of the [`crate::UserAgent`].
    pub tls: super::TlsProfile,

    /// Runtime (meta) info about the [`crate::UserAgent`].
    pub runtime: Option<Arc<UserAgentRuntimeProfile>>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Runtime (meta) info about the UA profile.
///
/// This information is not taken into account for UA Emulation on the network layer,
/// but that is none the less useful in the bigger picture.
pub struct UserAgentRuntimeProfile {
    /// Source information injected by fingerprinting service.
    pub source_info: Option<UserAgentSourceInfo>,
    /// Javascript information for a user-agent which supports Javascript and Web APIs.
    pub js_info: Option<JsProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Source information injected by fingerprinting service.
pub struct UserAgentSourceInfo {
    /// Name of the device.
    #[serde(alias = "deviceName")]
    pub device_name: Option<String>,
    /// Name of the operating system.
    #[serde(alias = "os")]
    pub os: Option<String>,
    /// Version of the operating system.
    #[serde(alias = "osVersion")]
    pub os_version: Option<String>,
    /// Name of the browser.
    #[serde(alias = "browserName")]
    pub browser_name: Option<String>,
    /// Version of the browser.
    #[serde(alias = "browserVersion")]
    pub browser_version: Option<String>,
}
