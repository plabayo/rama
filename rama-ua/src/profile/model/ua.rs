use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{PlatformKind, UserAgent, UserAgentKind};

use crate::profile::{
    analysis::profile::AnalyzedProfile,
    model::{identity::ProfileKey, js::JsProfile},
};

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
/// - the counted HTTP, TLS and QUIC observations used for emulation ([`AnalyzedProfile`])
/// - javascript (web APIs) information ([`JsProfile`])
///
/// [`JsProfile`]: crate::profile::model::js::JsProfile
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
        self.key.user_agent.as_deref()
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
