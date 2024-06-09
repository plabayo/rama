use super::parse_http_user_agent_header;
use crate::error::{error, OpaqueError};
use serde::{Deserialize, Deserializer, Serialize};
use std::{convert::Infallible, fmt, str::FromStr};

/// User Agent (UA) information.
///
/// See [the module level documentation](crate::ua) for more information.
#[derive(Debug, Clone)]
pub struct UserAgent {
    pub(super) header: String,
    pub(super) data: UserAgentData,
    pub(super) http_agent_overwrite: Option<HttpAgent>,
    pub(super) tls_agent_overwrite: Option<TlsAgent>,
    pub(super) preserve_ua_header: bool,
}

impl fmt::Display for UserAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.header)
    }
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

    /// Preserve the incoming [`User-Agent` header](crate::http::headers::UserAgent) value.
    ///
    /// This is used to indicate to emulators that they should respect the User-Agent header
    /// attached to this [`UserAgent`], if possible.
    pub fn with_preserve_ua_header(&mut self, preserve: bool) -> &mut Self {
        self.preserve_ua_header = preserve;
        self
    }

    /// returns whether the [`UserAgent`] consumer should try to preserve
    /// the [`UserAgent::header_str`] value if possible.
    pub fn preserve_ua_header(&self) -> bool {
        self.preserve_ua_header
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

impl FromStr for UserAgent {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(UserAgent::new(s))
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
    /// Windows Platform ([`Desktop`](DeviceKind::Desktop))
    Windows,
    /// MacOS Platform ([`Desktop`](DeviceKind::Desktop))
    MacOS,
    /// Linux Platform ([`Desktop`](DeviceKind::Desktop))
    Linux,
    /// Android Platform ([`Mobile`](DeviceKind::Mobile))
    Android,
    /// iOS Platform ([`Mobile`](DeviceKind::Mobile))
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
    /// Preserve the incoming Http Agent as much as possible.
    ///
    /// For emulators this means that emulators will aim to have a
    /// hands-off approach to the incoming http request.
    Preserve,
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
            HttpAgent::Preserve => serializer.serialize_str("Preserve"),
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
                "chrome" | "chromium" => Ok(HttpAgent::Chromium),
                "Firefox" => Ok(HttpAgent::Firefox),
                "Safari" => Ok(HttpAgent::Safari),
                "preserve" => Ok(HttpAgent::Preserve),
                _ => Err(serde::de::Error::custom("invalid http agent")),
            }
        }
    }
}

impl FromStr for HttpAgent {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match_ignore_ascii_case_str! {
            match (s) {
                "chrome" | "chromium" => Ok(HttpAgent::Chromium),
                "Firefox" => Ok(HttpAgent::Firefox),
                "Safari" => Ok(HttpAgent::Safari),
                "preserve" => Ok(HttpAgent::Preserve),
                _ => Err(error!("invalid http agent: {}", s)),
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
            HttpAgent::Preserve => write!(f, "Preserve"),
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
    /// Preserve the incoming TlsAgent as much as possible.
    ///
    /// For this Tls this means that emulators can try to
    /// preserve details of the incoming Tls connection
    /// such as the (Tls) Client Hello.
    Preserve,
}

impl fmt::Display for TlsAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsAgent::Rustls => write!(f, "Rustls"),
            TlsAgent::Boringssl => write!(f, "Boringssl"),
            TlsAgent::Nss => write!(f, "NSS"),
            TlsAgent::Preserve => write!(f, "Preserve"),
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
            TlsAgent::Preserve => serializer.serialize_str("Preserve"),
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
                "rustls" => Ok(TlsAgent::Rustls),
                "boring" | "boringssl" => Ok(TlsAgent::Boringssl),
                "nss" => Ok(TlsAgent::Nss),
                "preserve" => Ok(TlsAgent::Preserve),
                _ => Err(serde::de::Error::custom("invalid tls agent")),
            }
        }
    }
}

impl FromStr for TlsAgent {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match_ignore_ascii_case_str! {
            match (s) {
                "rustls" => Ok(TlsAgent::Rustls),
                "boring" | "boringssl" => Ok(TlsAgent::Boringssl),
                "nss" => Ok(TlsAgent::Nss),
                "preserve" => Ok(TlsAgent::Preserve),
                _ => Err(error!("invalid tls agent: {}", s)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_agent_new() {
        let ua = UserAgent::new("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36".to_owned());
        assert_eq!(ua.header_str(), "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");
        assert_eq!(
            ua.info(),
            Some(UserAgentInfo {
                kind: UserAgentKind::Chromium,
                version: Some(124)
            })
        );
        assert_eq!(ua.platform(), Some(PlatformKind::MacOS));
        assert_eq!(ua.device(), DeviceKind::Desktop);
        assert_eq!(ua.http_agent(), HttpAgent::Chromium);
        assert_eq!(ua.tls_agent(), TlsAgent::Boringssl);
    }

    #[test]
    fn test_user_agent_parse() {
        let ua: UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36".parse().unwrap();
        assert_eq!(ua.header_str(), "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");
        assert_eq!(
            ua.info(),
            Some(UserAgentInfo {
                kind: UserAgentKind::Chromium,
                version: Some(124)
            })
        );
        assert_eq!(ua.platform(), Some(PlatformKind::MacOS));
        assert_eq!(ua.device(), DeviceKind::Desktop);
        assert_eq!(ua.http_agent(), HttpAgent::Chromium);
        assert_eq!(ua.tls_agent(), TlsAgent::Boringssl);
    }

    #[test]
    fn test_user_agent_display() {
        let ua: UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36".parse().unwrap();
        assert_eq!(ua.to_string(), "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");
    }

    #[test]
    fn test_tls_agent_parse() {
        assert_eq!("rustls".parse::<TlsAgent>().unwrap(), TlsAgent::Rustls);
        assert_eq!("rUsTlS".parse::<TlsAgent>().unwrap(), TlsAgent::Rustls);

        assert_eq!("boring".parse::<TlsAgent>().unwrap(), TlsAgent::Boringssl);
        assert_eq!("BoRiNg".parse::<TlsAgent>().unwrap(), TlsAgent::Boringssl);

        assert_eq!("nss".parse::<TlsAgent>().unwrap(), TlsAgent::Nss);
        assert_eq!("NSS".parse::<TlsAgent>().unwrap(), TlsAgent::Nss);

        assert_eq!("preserve".parse::<TlsAgent>().unwrap(), TlsAgent::Preserve);
        assert_eq!("Preserve".parse::<TlsAgent>().unwrap(), TlsAgent::Preserve);

        assert!("".parse::<TlsAgent>().is_err());
        assert!("invalid".parse::<TlsAgent>().is_err());
    }

    #[test]
    fn test_tls_agent_deserialize() {
        assert_eq!(
            serde_json::from_str::<TlsAgent>(r#""rustls""#).unwrap(),
            TlsAgent::Rustls
        );
        assert_eq!(
            serde_json::from_str::<TlsAgent>(r#""RuStLs""#).unwrap(),
            TlsAgent::Rustls
        );

        assert_eq!(
            serde_json::from_str::<TlsAgent>(r#""boringssl""#).unwrap(),
            TlsAgent::Boringssl
        );
        assert_eq!(
            serde_json::from_str::<TlsAgent>(r#""BoringSSL""#).unwrap(),
            TlsAgent::Boringssl
        );

        assert_eq!(
            serde_json::from_str::<TlsAgent>(r#""nss""#).unwrap(),
            TlsAgent::Nss
        );
        assert_eq!(
            serde_json::from_str::<TlsAgent>(r#""NsS""#).unwrap(),
            TlsAgent::Nss
        );

        assert_eq!(
            serde_json::from_str::<TlsAgent>(r#""preserve""#).unwrap(),
            TlsAgent::Preserve
        );
        assert_eq!(
            serde_json::from_str::<TlsAgent>(r#""PreSeRvE""#).unwrap(),
            TlsAgent::Preserve
        );

        assert!(serde_json::from_str::<TlsAgent>(r#""invalid""#).is_err());
        assert!(serde_json::from_str::<TlsAgent>(r#""""#).is_err());
        assert!(serde_json::from_str::<TlsAgent>("1").is_err());
    }

    #[test]
    fn test_http_agent_parse() {
        assert_eq!("chrome".parse::<HttpAgent>().unwrap(), HttpAgent::Chromium);
        assert_eq!("ChRoMe".parse::<HttpAgent>().unwrap(), HttpAgent::Chromium);

        assert_eq!("firefox".parse::<HttpAgent>().unwrap(), HttpAgent::Firefox);
        assert_eq!("FiRefoX".parse::<HttpAgent>().unwrap(), HttpAgent::Firefox);

        assert_eq!("safari".parse::<HttpAgent>().unwrap(), HttpAgent::Safari);
        assert_eq!("SaFaRi".parse::<HttpAgent>().unwrap(), HttpAgent::Safari);

        assert_eq!(
            "preserve".parse::<HttpAgent>().unwrap(),
            HttpAgent::Preserve
        );
        assert_eq!(
            "Preserve".parse::<HttpAgent>().unwrap(),
            HttpAgent::Preserve
        );

        assert!("".parse::<HttpAgent>().is_err());
        assert!("invalid".parse::<HttpAgent>().is_err());
    }

    #[test]
    fn test_http_agent_deserialize() {
        assert_eq!(
            serde_json::from_str::<HttpAgent>(r#""chrome""#).unwrap(),
            HttpAgent::Chromium
        );
        assert_eq!(
            serde_json::from_str::<HttpAgent>(r#""ChRoMe""#).unwrap(),
            HttpAgent::Chromium
        );

        assert_eq!(
            serde_json::from_str::<HttpAgent>(r#""firefox""#).unwrap(),
            HttpAgent::Firefox
        );
        assert_eq!(
            serde_json::from_str::<HttpAgent>(r#""FirEfOx""#).unwrap(),
            HttpAgent::Firefox
        );

        assert_eq!(
            serde_json::from_str::<HttpAgent>(r#""safari""#).unwrap(),
            HttpAgent::Safari
        );
        assert_eq!(
            serde_json::from_str::<HttpAgent>(r#""SafArI""#).unwrap(),
            HttpAgent::Safari
        );

        assert_eq!(
            serde_json::from_str::<HttpAgent>(r#""preserve""#).unwrap(),
            HttpAgent::Preserve
        );
        assert_eq!(
            serde_json::from_str::<HttpAgent>(r#""PreSeRve""#).unwrap(),
            HttpAgent::Preserve
        );

        assert!(serde_json::from_str::<HttpAgent>("1").is_err());
        assert!(serde_json::from_str::<HttpAgent>(r#""""#).is_err());
        assert!(serde_json::from_str::<HttpAgent>(r#""invalid""#).is_err());
    }
}
