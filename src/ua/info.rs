use std::str::FromStr;

use super::{parse_http_user_agent, UserAgentParseError};

/// Information about the [`UserAgent`]
///
/// [`UserAgent`]: crate::ua::UserAgent
#[derive(Debug, Clone)]
pub struct UserAgent {
    /// The 'User-Agent' http header value used by the [`UserAgent`].
    ///
    /// [`UserAgent`]: crate::ua::UserAgent
    pub(super) http_user_agent: String,

    /// The kind of [`UserAgent`]
    ///
    /// [`UserAgent`]: crate::ua::UserAgent
    pub(super) kind: Option<UserAgentKind>,
    /// The major version of the [`UserAgent`]
    ///
    /// [`UserAgent`]: crate::ua::UserAgent
    pub(super) version: Option<usize>,

    /// The PlatformKind used by the [`UserAgent`]
    ///
    /// [`UserAgent`]: crate::ua::UserAgent
    pub(super) platform: Option<PlatformKind>,

    /// The major platform version used by the [`UserAgent`]
    ///
    /// Optional as not all platforms expose their version,
    /// especially in modern UA distros this is no longer exposed for privacy reasons.
    ///
    /// [`UserAgent`]: crate::ua::UserAgent
    pub(super) platform_version: Option<usize>,
}

impl FromStr for UserAgent {
    type Err = UserAgentParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_http_user_agent(s)
    }
}

impl UserAgent {
    /// returns the 'User-Agent' http header value used by the [`UserAgent`].
    pub fn header_str(&self) -> &str {
        &self.http_user_agent
    }

    /// returns the kind of [`UserAgent`], if known.
    pub fn kind(&self) -> Option<UserAgentKind> {
        self.kind
    }

    /// returns the major version of the [`UserAgent`], if known.
    ///
    /// This is the version of the distribution, not the version a component such as the rendering engine.
    pub fn version(&self) -> Option<usize> {
        self.version
    }

    /// returns the [`PlatformKind`] used by the [`UserAgent`], if known.
    ///
    /// This is the platform the UA is running on.
    pub fn platform(&self) -> Option<PlatformKind> {
        self.platform
    }

    /// returns the major version of the platform used by the [`UserAgent`], if known.
    pub fn platform_version(&self) -> Option<usize> {
        self.platform_version
    }

    /// returns the [`HttpAgent`] used by the [`UserAgent`].
    ///
    /// [`UserAgent`]: crate::ua::UserAgent
    pub fn http_agent(&self) -> HttpAgent {
        self.kind
            .map(|kind| match kind {
                UserAgentKind::Chrome | UserAgentKind::Chromium | UserAgentKind::Edge => {
                    HttpAgent::Chromium
                }
                UserAgentKind::Firefox => HttpAgent::Firefox,
                UserAgentKind::Safari => HttpAgent::Safari,
            })
            .unwrap_or(HttpAgent::Chromium)
    }

    /// returns the [`TlsAgent`] used by the [`UserAgent`].
    ///
    /// [`UserAgent`]: crate::ua::UserAgent
    pub fn tls_agent(&self) -> TlsAgent {
        self.kind
            .map(|kind| match kind {
                UserAgentKind::Chrome | UserAgentKind::Chromium | UserAgentKind::Edge => {
                    TlsAgent::Boringssl
                }
                UserAgentKind::Firefox | UserAgentKind::Safari => TlsAgent::Rustls,
            })
            .unwrap_or(TlsAgent::Rustls)
    }
}

/// The kind of [`UserAgent`]
///
/// [`UserAgent`]: crate::ua::UserAgent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserAgentKind {
    /// Google's Chrome Browser
    Chrome,
    /// Chromium or a derivative of that is not Chrome or Edge
    Chromium,
    /// Firefox Browser
    Firefox,
    /// Safari Browser
    Safari,
    /// Edge Browser
    Edge,
}

/// PlatformKind used by the [`UserAgent`]
///
/// [`UserAgent`]: crate::ua::UserAgent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlatformKind {
    /// Windows Platform (desktop)
    Windows,
    /// MacOS Platform (desktop)
    MacOS,
    /// Linux Platform (desktop)
    Linux,
    /// Android Platform (mobile)
    Android,
    /// iOS Platform (mobile)
    IOS,
}

/// Http implementation used by the [`UserAgent`]
///
/// [`UserAgent`]: crate::ua::UserAgent
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HttpAgent {
    /// Chromium based browsers share the same http implementation
    Chromium,
    /// Firefox has its own http implementation
    Firefox,
    /// Safari also has its own http implementation
    Safari,
}

/// Tls implementation used by the [`UserAgent`]
///
/// [`UserAgent`]: crate::ua::UserAgent
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TlsAgent {
    /// Rustls is used as a fallback for all user agents,
    /// that are not chromium based.
    Rustls,
    /// Boringssl is used for Chromium based user agents.
    Boringssl,
    /// NSS is used for Firefox
    Nss,
}
