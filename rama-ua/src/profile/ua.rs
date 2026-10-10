use std::sync::Arc;

use rama_http::header::USER_AGENT;
use serde::{Deserialize, Serialize};

use crate::{PlatformKind, UserAgent, UserAgentKind};

use super::{AnalyzedProfile, HttpProfile, JsProfile, ProfileKey};

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
    pub key: ProfileKey,
    /// Validated counted observations, including optional H3 and QUIC components.
    pub captured: Option<Arc<AnalyzedProfile>>,
    /// The kind of [`crate::UserAgent`]
    pub ua_kind: Option<UserAgentKind>,
    /// The version of the [`crate::UserAgent`]
    pub ua_version: Option<usize>,
    /// The platform the [`crate::UserAgent`] is running on.
    pub platform: Option<PlatformKind>,

    /// The profile information regarding the http implementation of the [`crate::UserAgent`].
    pub http: Option<Arc<HttpProfile>>,

    #[cfg(feature = "tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
    /// The profile information regarding the tls implementation of the [`crate::UserAgent`].
    pub tls: Option<Arc<super::TlsProfile>>,

    /// Runtime (meta) info about the [`crate::UserAgent`].
    pub runtime: Option<Arc<UserAgentRuntimeProfile>>,
}

impl UserAgentProfile {
    pub fn new(key: ProfileKey) -> Self {
        let ua = key.user_agent.as_deref().map(UserAgent::new);
        Self {
            ua_kind: ua.as_ref().and_then(UserAgent::ua_kind),
            ua_version: ua.as_ref().and_then(UserAgent::ua_version),
            platform: key.platform,
            key,
            captured: None,
            http: None,
            #[cfg(feature = "tls")]
            tls: None,
            runtime: None,
        }
    }

    pub fn from_captured(captured: AnalyzedProfile) -> Self {
        let mut profile = Self::new(captured.key.clone());
        profile.captured = Some(Arc::new(captured));
        profile
    }

    /// The exact observed User-Agent, when present.
    pub fn ua_str(&self) -> Option<&str> {
        self.key.user_agent.as_deref().or_else(|| {
            let http = self.http.as_ref()?;
            http.h1
                .as_ref()
                .and_then(|h1| h1.headers.navigate.as_ref())
                .or_else(|| http.h2.as_ref().and_then(|h2| h2.headers.navigate.as_ref()))
                .and_then(|headers| headers.get(USER_AGENT))
                .and_then(|value| value.to_str().ok())
        })
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
