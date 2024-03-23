/// Information about the [`UserAgent`]
///
/// [`UserAgent`]: crate::ua::UserAgent
#[derive(Debug, Clone)]
pub struct UserAgentInfo {
    /// The 'User-Agent' http header values known to be used by the [`UserAgent`].
    /// 
    /// [`UserAgent`]: crate::ua::UserAgent
    pub http_user_agents: Vec<String>,

    /// The kind of [`UserAgent`]
    ///
    /// [`UserAgent`]: crate::ua::UserAgent
    pub kind: UserAgentKind,
    /// The version of the [`UserAgent`]
    ///
    /// [`UserAgent`]: crate::ua::UserAgent
    pub version: usize,

    /// The platform used by the [`UserAgent`]
    ///
    /// [`UserAgent`]: crate::ua::UserAgent
    pub platform: Platform,

    /// The platform version used by the [`UserAgent`]
    ///
    /// [`UserAgent`]: crate::ua::UserAgent
    pub platform_version: usize,
}

impl UserAgentInfo {
    /// returns the [`HttpAgent`] used by the [`UserAgent`].
    ///
    /// [`UserAgent`]: crate::ua::UserAgent
    pub fn http_agent(&self) -> HttpAgent {
        match self.kind {
            UserAgentKind::Chrome | UserAgentKind::Chromium | UserAgentKind::Edge => {
                HttpAgent::Chromium
            }
            UserAgentKind::Firefox => HttpAgent::Firefox,
            UserAgentKind::Safari => HttpAgent::Safari,
            UserAgentKind::Unknown => HttpAgent::Chromium,
        }
    }

    /// returns the [`TlsAgent`] used by the [`UserAgent`].
    ///
    /// [`UserAgent`]: crate::ua::UserAgent
    pub fn tls_agent(&self) -> TlsAgent {
        match self.kind {
            UserAgentKind::Chrome | UserAgentKind::Chromium | UserAgentKind::Edge => {
                TlsAgent::Boringssl
            }
            UserAgentKind::Firefox | UserAgentKind::Safari | UserAgentKind::Unknown => {
                TlsAgent::Rustls
            }
        }
    }
}

/// The kind of [`UserAgent`]
///
/// [`UserAgent`]: crate::ua::UserAgent
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    /// A browser that is not recognised
    Unknown,
}

/// Platform used by the [`UserAgent`]
///
/// [`UserAgent`]: crate::ua::UserAgent
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Platform {
    /// Windows platform (desktop)
    Windows,
    /// MacOS platform (desktop)
    MacOS,
    /// Linux platform (desktop)
    Linux,
    /// Android platform (mobile)
    Android,
    /// iOS platform (mobile)
    IOS,
    /// Unknown platform
    Unknown,
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
