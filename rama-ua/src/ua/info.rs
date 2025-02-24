use super::{RequestInitiator, parse_http_user_agent_header};
use rama_core::error::OpaqueError;
use rama_http_types::headers::ClientHint;
use rama_utils::macros::match_ignore_ascii_case_str;
use serde::{Deserialize, Deserializer, Serialize};
use std::{convert::Infallible, fmt, str::FromStr, sync::Arc};

/// User Agent (UA) information.
///
/// See [the module level documentation](crate) for more information.
#[derive(Debug, Clone)]
pub struct UserAgent {
    pub(super) header: Arc<str>,
    pub(super) data: UserAgentData,
    pub(super) http_agent_overwrite: Option<HttpAgent>,
    pub(super) tls_agent_overwrite: Option<TlsAgent>,
    pub(super) preserve_ua_header: bool,
    pub(super) request_initiator: Option<RequestInitiator>,
    pub(super) requested_client_hints: Option<Vec<ClientHint>>,
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
        platform_like: Option<PlatformLike>,
    },
    Platform(PlatformKind),
    Device(DeviceKind),
    Unknown,
}

#[derive(Debug, Clone)]
pub(super) enum PlatformLike {
    Platform(PlatformKind),
    Device(DeviceKind),
}

impl PlatformLike {
    pub(super) fn device(&self) -> DeviceKind {
        match self {
            PlatformLike::Platform(platform_kind) => platform_kind.device(),
            PlatformLike::Device(device_kind) => *device_kind,
        }
    }
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
    /// Create a new [`UserAgent`] from a `User-Agent` (header) value.
    pub fn new(header: impl Into<Arc<str>>) -> Self {
        parse_http_user_agent_header(header.into())
    }

    /// Overwrite the [`HttpAgent`] advertised by the [`UserAgent`].
    pub fn with_http_agent(mut self, http_agent: HttpAgent) -> Self {
        self.http_agent_overwrite = Some(http_agent);
        self
    }

    /// Overwrite the [`HttpAgent`] advertised by the [`UserAgent`].
    pub fn set_http_agent(&mut self, http_agent: HttpAgent) -> &mut Self {
        self.http_agent_overwrite = Some(http_agent);
        self
    }

    /// Overwrite the [`TlsAgent`] advertised by the [`UserAgent`].
    pub fn with_tls_agent(mut self, tls_agent: TlsAgent) -> Self {
        self.tls_agent_overwrite = Some(tls_agent);
        self
    }

    /// Overwrite the [`TlsAgent`] advertised by the [`UserAgent`].
    pub fn set_tls_agent(&mut self, tls_agent: TlsAgent) -> &mut Self {
        self.tls_agent_overwrite = Some(tls_agent);
        self
    }

    /// Preserve the incoming `User-Agent` (header) value.
    ///
    /// This is used to indicate to emulators that they should respect the User-Agent header
    /// attached to this [`UserAgent`], if possible.
    pub fn with_preserve_ua_header(mut self, preserve: bool) -> Self {
        self.preserve_ua_header = preserve;
        self
    }

    /// Preserve the incoming `User-Agent` (header) value.
    ///
    /// This is used to indicate to emulators that they should respect the User-Agent header
    /// attached to this [`UserAgent`], if possible.
    pub fn set_preserve_ua_header(&mut self, preserve: bool) -> &mut Self {
        self.preserve_ua_header = preserve;
        self
    }

    /// returns whether the [`UserAgent`] consumer should try to preserve
    /// the [`UserAgent::header_str`] value if possible.
    pub fn preserve_ua_header(&self) -> bool {
        self.preserve_ua_header
    }

    /// Define the [`RequestInitiator`] hint.
    pub fn with_request_initiator(mut self, req_init: RequestInitiator) -> Self {
        self.request_initiator = Some(req_init);
        self
    }

    /// Define the [`RequestInitiator`] hint.
    pub fn set_request_initiator(&mut self, req_init: RequestInitiator) -> &mut Self {
        self.request_initiator = Some(req_init);
        self
    }

    /// returns the [`RequestInitiator`] hint if available.
    pub fn request_initiator(&self) -> Option<RequestInitiator> {
        self.request_initiator
    }

    /// Define the requested (High-Entropy) Client Hints.
    pub fn with_requested_client_hints(mut self, req_client_hints: Vec<ClientHint>) -> Self {
        self.requested_client_hints = Some(req_client_hints);
        self
    }

    /// Define the requested (High-Entropy) Client Hints.
    pub fn set_requested_client_hints(&mut self, req_client_hints: Vec<ClientHint>) -> &mut Self {
        self.requested_client_hints = Some(req_client_hints);
        self
    }

    /// Append a requested (High-Entropy) Client Hint.
    pub fn append_requested_client_hint(&mut self, hint: ClientHint) -> &mut Self {
        self.requested_client_hints
            .get_or_insert_default()
            .push(hint);
        self
    }

    /// Extend the requested (High-Entropy) Client Hints.
    pub fn extend_requested_client_hints(
        &mut self,
        hints: impl IntoIterator<Item = ClientHint>,
    ) -> &mut Self {
        self.requested_client_hints
            .get_or_insert_default()
            .extend(hints);
        self
    }

    /// returns the requested (High-Entropy) Client Hints.
    pub fn requested_client_hints(&self) -> impl Iterator<Item = &ClientHint> {
        self.requested_client_hints.iter().flatten()
    }

    /// returns the `User-Agent` (header) value used by the [`UserAgent`].
    pub fn header_str(&self) -> &str {
        &self.header
    }

    /// returns the device kind of the [`UserAgent`].
    pub fn device(&self) -> Option<DeviceKind> {
        match &self.data {
            UserAgentData::Standard { platform_like, .. } => {
                platform_like.as_ref().map(|p| p.device())
            }
            UserAgentData::Platform(platform) => Some(platform.device()),
            UserAgentData::Device(kind) => Some(*kind),
            UserAgentData::Unknown => None,
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

    /// returns the [`UserAgentKind`] used by the [`UserAgent`], if known.
    pub fn ua_kind(&self) -> Option<UserAgentKind> {
        match self.http_agent_overwrite {
            Some(HttpAgent::Chromium) => Some(UserAgentKind::Chromium),
            Some(HttpAgent::Safari) => Some(UserAgentKind::Safari),
            Some(HttpAgent::Firefox) => Some(UserAgentKind::Firefox),
            Some(HttpAgent::Preserve) => None,
            None => match &self.data {
                UserAgentData::Standard {
                    info: UserAgentInfo { kind, .. },
                    ..
                } => Some(*kind),
                _ => None,
            },
        }
    }

    /// returns the version of the [`UserAgent`], if known.
    pub fn ua_version(&self) -> Option<usize> {
        match &self.data {
            UserAgentData::Standard { info, .. } => info.version,
            _ => None,
        }
    }

    /// returns the [`PlatformKind`] used by the [`UserAgent`], if known.
    ///
    /// This is the platform the [`UserAgent`] is running on.
    pub fn platform(&self) -> Option<PlatformKind> {
        match &self.data {
            UserAgentData::Standard { platform_like, .. } => match platform_like {
                Some(PlatformLike::Platform(platform)) => Some(*platform),
                None | Some(PlatformLike::Device(_)) => None,
            },
            UserAgentData::Platform(platform) => Some(*platform),
            _ => None,
        }
    }

    /// returns the [`HttpAgent`] used by the [`UserAgent`].
    ///
    /// [`UserAgent`]: super::UserAgent
    pub fn http_agent(&self) -> Option<HttpAgent> {
        match self.http_agent_overwrite {
            Some(agent) => Some(agent),
            None => match &self.data {
                UserAgentData::Standard { info, .. } => Some(match info.kind {
                    UserAgentKind::Chromium => HttpAgent::Chromium,
                    UserAgentKind::Firefox => HttpAgent::Firefox,
                    UserAgentKind::Safari => HttpAgent::Safari,
                }),
                UserAgentData::Platform(_) | UserAgentData::Device(_) | UserAgentData::Unknown => {
                    None
                }
            },
        }
    }

    /// returns the [`TlsAgent`] used by the [`UserAgent`].
    ///
    /// [`UserAgent`]: super::UserAgent
    pub fn tls_agent(&self) -> Option<TlsAgent> {
        match self.tls_agent_overwrite {
            Some(agent) => Some(agent),
            None => match &self.data {
                UserAgentData::Standard { info, .. } => Some(match info.kind {
                    UserAgentKind::Chromium => TlsAgent::Boringssl,
                    UserAgentKind::Firefox => TlsAgent::Nss,
                    UserAgentKind::Safari => TlsAgent::Rustls,
                }),
                UserAgentData::Device(_) | UserAgentData::Platform(_) | UserAgentData::Unknown => {
                    None
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserAgentKind {
    /// Chromium Browser
    Chromium,
    /// Firefox Browser
    Firefox,
    /// Safari Browser
    Safari,
}

impl UserAgentKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            UserAgentKind::Chromium => "Chromium",
            UserAgentKind::Firefox => "Firefox",
            UserAgentKind::Safari => "Safari",
        }
    }
}

impl fmt::Display for UserAgentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for UserAgentKind {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match_ignore_ascii_case_str! {
            match (s) {
                "chromium" => Ok(UserAgentKind::Chromium),
                "firefox" => Ok(UserAgentKind::Firefox),
                "safari" => Ok(UserAgentKind::Safari),
                _ => Err(OpaqueError::from_display(format!("invalid user agent kind: {}", s))),
            }
        }
    }
}

impl Serialize for UserAgentKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for UserAgentKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        s.parse::<UserAgentKind>().map_err(serde::de::Error::custom)
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

impl DeviceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceKind::Desktop => "Desktop",
            DeviceKind::Mobile => "Mobile",
        }
    }
}

impl fmt::Display for DeviceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
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

impl PlatformKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PlatformKind::Windows => "Windows",
            PlatformKind::MacOS => "MacOS",
            PlatformKind::Linux => "Linux",
            PlatformKind::Android => "Android",
            PlatformKind::IOS => "iOS",
        }
    }

    pub fn device(&self) -> DeviceKind {
        match self {
            PlatformKind::Windows | PlatformKind::MacOS | PlatformKind::Linux => {
                DeviceKind::Desktop
            }
            PlatformKind::Android | PlatformKind::IOS => DeviceKind::Mobile,
        }
    }
}

impl FromStr for PlatformKind {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match_ignore_ascii_case_str! {
            match (s) {
                "windows" => Ok(PlatformKind::Windows),
                "macos" => Ok(PlatformKind::MacOS),
                "linux" => Ok(PlatformKind::Linux),
                "android" => Ok(PlatformKind::Android),
                "ios" => Ok(PlatformKind::IOS),
                _ => Err(OpaqueError::from_display(format!("invalid platform: {}", s))),
            }
        }
    }
}

impl Serialize for PlatformKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PlatformKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        s.parse::<PlatformKind>().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for PlatformKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Http implementation used by the [`UserAgent`]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

impl HttpAgent {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpAgent::Chromium => "Chromium",
            HttpAgent::Firefox => "Firefox",
            HttpAgent::Safari => "Safari",
            HttpAgent::Preserve => "Preserve",
        }
    }
}

impl fmt::Display for HttpAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for HttpAgent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HttpAgent {
    fn deserialize<D>(deserializer: D) -> Result<HttpAgent, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        s.parse::<HttpAgent>().map_err(serde::de::Error::custom)
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
                _ => Err(OpaqueError::from_display(format!("invalid http agent: {}", s))),
            }
        }
    }
}

/// Tls implementation used by the [`UserAgent`]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

impl TlsAgent {
    pub fn as_str(&self) -> &'static str {
        match self {
            TlsAgent::Rustls => "Rustls",
            TlsAgent::Boringssl => "Boringssl",
            TlsAgent::Nss => "NSS",
            TlsAgent::Preserve => "Preserve",
        }
    }
}

impl fmt::Display for TlsAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for TlsAgent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TlsAgent {
    fn deserialize<D>(deserializer: D) -> Result<TlsAgent, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        s.parse::<TlsAgent>().map_err(serde::de::Error::custom)
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
                _ => Err(OpaqueError::from_display(format!("invalid tls agent: {}", s))),
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
        assert_eq!(
            ua.header_str(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        );
        assert_eq!(
            ua.info(),
            Some(UserAgentInfo {
                kind: UserAgentKind::Chromium,
                version: Some(124)
            })
        );
        assert_eq!(ua.platform(), Some(PlatformKind::MacOS));
        assert_eq!(ua.device(), Some(DeviceKind::Desktop));
        assert_eq!(ua.http_agent(), Some(HttpAgent::Chromium));
        assert_eq!(ua.tls_agent(), Some(TlsAgent::Boringssl));
    }

    #[test]
    fn test_user_agent_parse() {
        let ua: UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36".parse().unwrap();
        assert_eq!(
            ua.header_str(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        );
        assert_eq!(
            ua.info(),
            Some(UserAgentInfo {
                kind: UserAgentKind::Chromium,
                version: Some(124)
            })
        );
        assert_eq!(ua.platform(), Some(PlatformKind::MacOS));
        assert_eq!(ua.device(), Some(DeviceKind::Desktop));
        assert_eq!(ua.http_agent(), Some(HttpAgent::Chromium));
        assert_eq!(ua.tls_agent(), Some(TlsAgent::Boringssl));
    }

    #[test]
    fn test_user_agent_display() {
        let ua: UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36".parse().unwrap();
        assert_eq!(
            ua.to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        );
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
