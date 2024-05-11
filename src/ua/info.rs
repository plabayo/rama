use serde::{Deserialize, Deserializer, Serialize};

use super::parse_http_user_agent_header;
use std::fmt;

/// User Agent (UA) information.
///
/// See [the module level documentation](crate::ua) for more information.
#[derive(Debug, Clone)]
pub struct UserAgent {
    pub(super) header: String,
    pub(super) data: UserAgentData,
    pub(super) http_agent_overwrite: Option<HttpAgent>,
    pub(super) tls_agent_overwrite: Option<TlsAgent>,
}

/// internal representation of the [`UserAgent`]
#[derive(Debug, Clone)]
pub(super) enum UserAgentData {
    Standard {
        info: UserAgentInfo,
        platform: Option<PlatformKind>,
    },
    Platform(PlatformKind),
    Device(DeviceKind),
    Unknown,
}

/// Information about the [`UserAgent`]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UserAgentInfo {
    /// The kind of [`UserAgent`]
    pub kind: UserAgentKind,
    /// The version of the [`UserAgent`]
    pub version: Option<usize>,
}

impl UserAgent {
    /// Create a new [`UserAgent`] from a [`User-Agent` header](crate::http::headers::UserAgent) value.
    pub fn new(header: impl Into<String>) -> Self {
        parse_http_user_agent_header(header.into())
    }

    /// Overwrite the [`HttpAgent`] advertised by the [`UserAgent`].
    pub fn with_http_agent(&mut self, http_agent: HttpAgent) -> &mut Self {
        self.http_agent_overwrite = Some(http_agent);
        self
    }

    /// Overwrite the [`TlsAgent`] advertised by the [`UserAgent`].
    pub fn with_tls_agent(&mut self, tls_agent: TlsAgent) -> &mut Self {
        self.tls_agent_overwrite = Some(tls_agent);
        self
    }

    /// returns [the 'User-Agent' http header](crate::http::headers::UserAgent) value used by the [`UserAgent`].
    pub fn header_str(&self) -> &str {
        &self.header
    }

    /// returns the device kind of the [`UserAgent`].
    pub fn device(&self) -> DeviceKind {
        match &self.data {
            UserAgentData::Standard { platform, .. } => match platform {
                Some(PlatformKind::Windows | PlatformKind::MacOS | PlatformKind::Linux) | None => {
                    DeviceKind::Desktop
                }
                Some(PlatformKind::Android | PlatformKind::IOS) => DeviceKind::Mobile,
            },
            UserAgentData::Platform(platform) => match platform {
                PlatformKind::Windows | PlatformKind::MacOS | PlatformKind::Linux => {
                    DeviceKind::Desktop
                }
                PlatformKind::Android | PlatformKind::IOS => DeviceKind::Mobile,
            },
            UserAgentData::Device(kind) => *kind,
            UserAgentData::Unknown => DeviceKind::Desktop,
        }
    }

    /// returns the [`UserAgent`] information, containing
    /// the [`UserAgentKind`] and version if known.
    pub fn info(&self) -> Option<UserAgentInfo> {
        if let UserAgentData::Standard { info, .. } = &self.data {
            Some(info.clone())
        } else {
            None
        }
    }

    /// returns the [`PlatformKind`] used by the [`UserAgent`], if known.
    ///
    /// This is the platform the [`UserAgent`] is running on.
    pub fn platform(&self) -> Option<PlatformKind> {
        match &self.data {
            UserAgentData::Standard { platform, .. } => *platform,
            UserAgentData::Platform(platform) => Some(*platform),
            _ => None,
        }
    }

    /// returns the [`HttpAgent`] used by the [`UserAgent`].
    ///
    /// [`UserAgent`]: crate::ua::UserAgent
    pub fn http_agent(&self) -> HttpAgent {
        match &self.http_agent_overwrite {
            Some(agent) => agent.clone(),
            None => match &self.data {
                UserAgentData::Standard { info, .. } => match info.kind {
                    UserAgentKind::Chromium => HttpAgent::Chromium,
                    UserAgentKind::Firefox => HttpAgent::Firefox,
                    UserAgentKind::Safari => HttpAgent::Safari,
                },
                UserAgentData::Device(_) | UserAgentData::Platform(_) | UserAgentData::Unknown => {
                    HttpAgent::Chromium
                }
            },
        }
    }

    /// returns the [`TlsAgent`] used by the [`UserAgent`].
    ///
    /// [`UserAgent`]: crate::ua::UserAgent
    pub fn tls_agent(&self) -> TlsAgent {
        match &self.tls_agent_overwrite {
            Some(agent) => agent.clone(),
            None => match &self.data {
                UserAgentData::Standard { info, .. } => match info.kind {
                    UserAgentKind::Chromium => TlsAgent::Boringssl,
                    UserAgentKind::Firefox => TlsAgent::Nss,
                    UserAgentKind::Safari => TlsAgent::Rustls,
                },
                UserAgentData::Device(_) | UserAgentData::Platform(_) | UserAgentData::Unknown => {
                    TlsAgent::Rustls
                }
            },
        }
    }
}

/// The kind of [`UserAgent`]
///
/// [`UserAgent`]: crate::ua::UserAgent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserAgentKind {
    /// Chromium Browser
    Chromium,
    /// Firefox Browser
    Firefox,
    /// Safari Browser
    Safari,
}

impl fmt::Display for UserAgentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserAgentKind::Chromium => write!(f, "Chromium"),
            UserAgentKind::Firefox => write!(f, "Firefox"),
            UserAgentKind::Safari => write!(f, "Safari"),
        }
    }
}

/// Device on which the [`UserAgent`] operates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceKind {
    /// Personal Computers
    Desktop,
    /// Phones, Tablets and other mobile devices
    Mobile,
}

impl fmt::Display for DeviceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceKind::Desktop => write!(f, "Desktop"),
            DeviceKind::Mobile => write!(f, "Mobile"),
        }
    }
}

/// Platform within the [`UserAgent`] operates.
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

impl fmt::Display for PlatformKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlatformKind::Windows => write!(f, "Windows"),
            PlatformKind::MacOS => write!(f, "MacOS"),
            PlatformKind::Linux => write!(f, "Linux"),
            PlatformKind::Android => write!(f, "Android"),
            PlatformKind::IOS => write!(f, "iOS"),
        }
    }
}

/// Http implementation used by the [`UserAgent`]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HttpAgent {
    /// Chromium based browsers share the same http implementation
    Chromium,
    /// Firefox has its own http implementation
    Firefox,
    /// Safari also has its own http implementation
    Safari,
}

impl Serialize for HttpAgent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        match self {
            HttpAgent::Chromium => serializer.serialize_str("Chromium"),
            HttpAgent::Firefox => serializer.serialize_str("Firefox"),
            HttpAgent::Safari => serializer.serialize_str("Safari"),
        }
    }
}

impl<'de> Deserialize<'de> for HttpAgent {
    fn deserialize<D>(deserializer: D) -> Result<HttpAgent, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match_ignore_ascii_case_str! {
            match (s.as_str()) {
                "" | "chrome" | "chromium" => Ok(HttpAgent::Chromium),
                "Firefox" => Ok(HttpAgent::Firefox),
                "Safari" => Ok(HttpAgent::Safari),
                _ => Err(serde::de::Error::custom("invalid http agent")),
            }
        }
    }
}

impl fmt::Display for HttpAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpAgent::Chromium => write!(f, "Chromium"),
            HttpAgent::Firefox => write!(f, "Firefox"),
            HttpAgent::Safari => write!(f, "Safari"),
        }
    }
}

/// Tls implementation used by the [`UserAgent`]
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

impl fmt::Display for TlsAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsAgent::Rustls => write!(f, "Rustls"),
            TlsAgent::Boringssl => write!(f, "Boringssl"),
            TlsAgent::Nss => write!(f, "NSS"),
        }
    }
}

impl Serialize for TlsAgent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        match self {
            TlsAgent::Rustls => serializer.serialize_str("Rustls"),
            TlsAgent::Boringssl => serializer.serialize_str("Boringssl"),
            TlsAgent::Nss => serializer.serialize_str("NSS"),
        }
    }
}

impl<'de> Deserialize<'de> for TlsAgent {
    fn deserialize<D>(deserializer: D) -> Result<TlsAgent, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match_ignore_ascii_case_str! {
            match (s.as_str()) {
                "" | "tls" | "rustls" | "std" | "standard" | "default" => Ok(TlsAgent::Rustls),
                "boring" | "boringssl" => Ok(TlsAgent::Boringssl),
                "nss" => Ok(TlsAgent::Nss),
                _ => Err(serde::de::Error::custom("invalid tls agent")),
            }
        }
    }
}
