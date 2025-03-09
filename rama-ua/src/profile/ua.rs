use rama_http_types::header::USER_AGENT;
use serde::{Deserialize, Serialize};

use crate::{PlatformKind, UserAgentKind};

#[derive(Debug, Clone, Deserialize, Serialize)]
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
