use std::time::Duration;

use rama_http_types::{HeaderName, HeaderValue};

use crate::util::{self, IterExt};
use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

macro_rules! client_hint {
    (
        #[doc = $ch_doc:literal]
        pub enum ClientHint {
            $(
                #[doc = $doc:literal]
                $name:ident($($str:literal),*),
            )+
        }
    ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum ClientHint {
            $(
                #[doc = $doc]
                $name,
            )+
        }

        impl ClientHint {
            #[doc = "Checks if the client hint is low entropy, meaning that it will be send by default."]
            #[must_use] pub fn is_low_entropy(&self) -> bool {
                matches!(self, Self::SaveData | Self::Ua | Self::Mobile | Self::Platform)
            }

            #[inline]
            #[doc = "Attempts to convert a `HeaderName` to a `ClientHint`."]
            pub fn match_header_name(name: &::rama_http_types::HeaderName) -> Option<Self> {
                name.try_into().ok()
            }

            #[doc = "Return an iterator of all header names for this client hint."]
            pub fn iter_header_names(&self) -> impl Iterator<Item = ::rama_http_types::HeaderName> {
                match self {
                    $(
                        Self::$name => vec![$(::rama_http_types::HeaderName::from_static($str),)+].into_iter(),
                    )+
                }
            }

            #[doc = "Returns the preferred string representation of the client hint."]
            #[must_use] pub fn as_str(&self) -> &'static str {
                match self {
                    $(
                        Self::$name => {
                            const VARIANTS: &'static [&'static str] = &[$($str,)+];
                            VARIANTS[0]
                        },
                    )+
                }
            }
        }

        rama_utils::macros::error::static_str_error! {
            /// Client Hint Parsing Error
            pub struct ClientHintParsingError;
        }

        impl TryFrom<&str> for ClientHint {
            type Error = ClientHintParsingError;

            fn try_from(name: &str) -> Result<Self, Self::Error> {
                rama_utils::macros::match_ignore_ascii_case_str! {
                    match (name) {
                        $(
                            $($str)|+ => Ok(Self::$name),
                        )+
                        _ => Err(ClientHintParsingError),
                    }
                }
            }
        }

        impl TryFrom<String> for ClientHint {
            type Error = ClientHintParsingError;

            fn try_from(name: String) -> Result<Self, Self::Error> {
                Self::try_from(name.as_str())
            }
        }

        impl TryFrom<::rama_http_types::HeaderName> for ClientHint {
            type Error = ClientHintParsingError;

            fn try_from(name: ::rama_http_types::HeaderName) -> Result<Self, Self::Error> {
                Self::try_from(name.as_str())
            }
        }

        impl TryFrom<&::rama_http_types::HeaderName> for ClientHint {
            type Error = ClientHintParsingError;

            fn try_from(name: &::rama_http_types::HeaderName) -> Result<Self, Self::Error> {
                Self::try_from(name.as_str())
            }
        }

        impl std::str::FromStr for ClientHint {
            type Err = ClientHintParsingError;

            #[inline]
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::try_from(s)
            }
        }

        impl std::fmt::Display for ClientHint {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.as_str())
            }
        }

        impl serde::Serialize for ClientHint {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> serde::Deserialize<'de> for ClientHint {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                use serde::de::Error;
                let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
                Self::try_from(s.as_ref()).map_err(D::Error::custom)
            }
        }

        #[doc = "Returns an iterator over all client hints."]
        pub fn all_client_hints() -> impl Iterator<Item = ClientHint> {
            [
                $(
                    ClientHint::$name,
                )+
            ].into_iter()
        }

        #[doc = "Returns an iterator over all client hint header name strings."]
        pub fn all_client_hint_header_name_strings() -> impl Iterator<Item = &'static str> {
            [
                $(
                    $($str,)+
                )+
            ].into_iter()
        }

        #[doc = "Returns an iterator over all client hint header names."]
        pub fn all_client_hint_header_names() -> impl Iterator<Item = ::rama_http_types::HeaderName> {
            all_client_hint_header_name_strings().map(::rama_http_types::HeaderName::from_static)
        }
    };
}

// NOTE: we are open to contributions to this module,
// e.g. in case you wish typed headers for each or some of these client hint headers,
// we gladly mentor and guide you in the process.

client_hint! {
    #[doc = "Client Hints are a set of HTTP Headers and a JavaScript API that allow web browsers to send detailed information about the client device and browser to web servers. They are designed to be a successor to User-Agent, and provide a standardized way for web servers to optimize content for the client without relying on unreliable user-agent string-based detection or browser fingerprinting techniques."]
    pub enum ClientHint {
        /// Sec-CH-UA represents a user agent's branding and version.
        Ua("sec-ch-ua"),
        /// Sec-CH-UA-Full-Version represents the user agent's full version.
        FullVersion("sec-ch-ua-full-version"),
        /// Sec-CH-UA-Full-Version-List represents the full version for each brand in its brands list.
        FullVersionList("sec-ch-ua-full-version-list"),
        /// Sec-CH-UA-Platform represents the platform on which a given user agent is executing.
        Platform("sec-ch-ua-platform"),
        /// Sec-CH-UA-Platform-Version represents the platform version on which a given user agent is executing.
        PlatformVersion("sec-ch-ua-platform-version"),
        /// Sec-CH-UA-Arch represents the architecture of the platform on which a given user agent is executing.
        Arch("sec-ch-ua-arch"),
        /// Sec-CH-UA-Bitness represents the bitness of the architecture of the platform on which a given user agent is executing.
        Bitness("sec-ch-ua-bitness"),
        /// Sec-CH-UA-WoW64 is used to detect whether or not a user agent binary is running in 32-bit mode on 64-bit Windows.
        Wow64("sec-ch-ua-wow64"),
        /// Sec-CH-UA-Model represents the device on which a given user agent is executing.
        Model("sec-ch-ua-model"),
        /// Sec-CH-UA-Mobile is used to detect whether or not a user agent prefers a «mobile» user experience.
        Mobile("sec-ch-ua-mobile"),
        /// Sec-CH-UA-Form-Factors represents the form-factors of a device, historically represented as a `<deviceCompat>` token in the User-Agent string.
        FormFactor("sec-ch-ua-form-factors"),
        /// Sec-CH-Lang  (or Lang) represents the user's language preference.
        Lang("sec-ch-lang", "lang"),
        /// Sec-CH-Save-Data (or Save-Data) represents the user agent's preference for reduced data usage.
        SaveData("sec-ch-save-data", "save-data"),
        /// Sec-CH-Width gives a server the layout width of the image.
        Width("sec-ch-width"),
        /// Sec-CH-Viewport-Width (or Viewport-Width) is the width of the user's viewport in CSS pixels.
        ViewportWidth("sec-ch-viewport-width", "viewport-width"),
        /// Sec-CH-Viewport-Height represents the user-agent's current viewport height.
        ViewportHeight("sec-ch-viewport-height"),
        /// Sec-CH-DPR (or DPR) reports the ratio of physical pixels to CSS pixels of the user's screen.
        Dpr("sec-ch-dpr", "dpr"),
        /// Sec-CH-Device-Memory (or Device-Memory) reveals the approximate amount of memory the current device has in GiB. Because this information could be used to fingerprint users, the value of Device-Memory is intentionally coarse. Valid values are 0.25, 0.5, 1, 2, 4, and 8.
        DeviceMemory("sec-ch-device-memory", "device-memory"),
        /// Sec-CH-RTT (or RTT) provides the approximate Round Trip Time, in milliseconds, on the application layer. The RTT hint, unlike transport layer RTT, includes server processing time. The value of RTT is rounded to the nearest 25 milliseconds to prevent fingerprinting.
        Rtt("sec-ch-rtt", "rtt"),
        /// Sec-CH-Downlink (or Downlink) expressed in megabits per second (Mbps), reveals the approximate downstream speed of the user's connection. The value is rounded to the nearest multiple of 25 kilobits per second. Because again, fingerprinting.
        Downlink("sec-ch-downlink", "downlink"),
        /// Sec-CH-ECT (or ECT) stands for Effective Connection Type. Its value is one of an enumerated list of connection types, each of which describes a connection within specified ranges of both RTT and Downlink values. Valid values for ECT are 4g, 3g, 2g, and slow-2g.
        Ect("sec-ch-ect", "ect"),
        /// Sec-CH-Prefers-Color-Scheme represents the user's preferred color scheme.
        PrefersColorScheme("sec-ch-prefers-color-scheme"),
        /// Sec-CH-Prefers-Reduced-Motion is used to detect if the user has requested the system minimize the amount of animation or motion it uses.
        PrefersReducedMotion("sec-ch-prefers-reduced-motion"),
        /// Sec-CH-Prefers-Reduced-Transparency is used to detect if the user has requested the system minimize the amount of transparent or translucent layer effects it uses.
        PrefersReducedTransparency("sec-ch-prefers-reduced-transparency"),
        /// Sec-CH-Prefers-Contrast is used to detect if the user has requested that the web content is presented with a higher (or lower) contrast.
        PrefersContrast("sec-ch-prefers-contrast"),
        /// Sec-CH-Forced-Colors is used to detect if the user agent has enabled a forced colors mode where it enforces a user-chosen limited color palette on the page.
        ForcedColors("sec-ch-forced-colors"),
    }
}

// ---------------------------------------------------------------------------
// Client-hint negotiation headers: a server advertises which [`ClientHint`]s
// it wants (`Accept-CH`) and which of those are critical (`Critical-CH`).
// Both are flat comma-separated lists of client-hint header names, encoded
// using each hint's preferred (`Sec-CH-` prefixed) form.
// ---------------------------------------------------------------------------

derive_non_empty_flat_csv_header! {
    #[header(name = ACCEPT_CH, sep = Comma)]
    #[derive(Clone, Debug, PartialEq, Eq)]
    /// `Accept-CH` header, defined in [RFC8942](https://datatracker.ietf.org/doc/html/rfc8942#section-3.1).
    ///
    /// Sent by a server to advertise the set of [`ClientHint`]s it would like
    /// the user agent to send on subsequent requests to the same origin. Each
    /// entry is encoded using the hint's preferred (`Sec-CH-` prefixed) header
    /// name; entries that do not map to a known [`ClientHint`] are rejected on
    /// decode.
    ///
    /// # ABNF
    ///
    /// ```text
    /// Accept-CH = #client-hint-name
    /// ```
    ///
    /// # Example
    ///
    /// ```
    /// use rama_utils::collections::non_empty_smallvec;
    /// use rama_http_headers::{AcceptCh, ClientHint};
    ///
    /// let accept_ch = AcceptCh(
    ///     non_empty_smallvec![ClientHint::Ua, ClientHint::Platform, ClientHint::Mobile; 16],
    /// );
    /// ```
    pub struct AcceptCh(pub NonEmptySmallVec<16, ClientHint>);
}

derive_non_empty_flat_csv_header! {
    #[header(name = CRITICAL_CH, sep = Comma)]
    #[derive(Clone, Debug, PartialEq, Eq)]
    /// `Critical-CH` header, defined by the
    /// [Client Hints Infrastructure](https://wicg.github.io/client-hints-infrastructure/#critical-ch).
    ///
    /// Sent alongside [`AcceptCh`] to mark a subset of the advertised
    /// [`ClientHint`]s as *critical*: if the original request was not sent with
    /// these hints, a conforming user agent retries the request before handing
    /// the response to the page. Same wire format as `Accept-CH`.
    ///
    /// # ABNF
    ///
    /// ```text
    /// Critical-CH = #client-hint-name
    /// ```
    ///
    /// # Example
    ///
    /// ```
    /// use rama_utils::collections::non_empty_smallvec;
    /// use rama_http_headers::{ClientHint, CriticalCh};
    ///
    /// let critical_ch = CriticalCh(
    ///     non_empty_smallvec![ClientHint::Ua, ClientHint::Platform; 16],
    /// );
    /// ```
    pub struct CriticalCh(pub NonEmptySmallVec<16, ClientHint>);
}

// ---------------------------------------------------------------------------
// Typed value parsers for a subset of the client hints above.
//
// Each parses a single header value with a strict spec, following the same
// typed-header shape rama uses for `Cache-Control`, `Age`, etc. The canonical
// header name matches the preferred (`Sec-CH-` prefixed) form of the matching
// [`ClientHint`] variant, sourced from `rama_http_types::header`.
// ---------------------------------------------------------------------------

/// `Save-Data` client hint: the user agent's preference for reduced data usage.
///
/// Defined by the [Save Data API](https://wicg.github.io/savedata/). The header
/// is sent with the value `on` when the user has opted in to data savings; the
/// canonical "off" state is the *absence* of the header, though an explicit
/// `off` is also accepted on decode (both matched ASCII case-insensitively).
///
/// Corresponds to [`ClientHint::SaveData`]; encoded as `Sec-CH-Save-Data`.
///
/// # Example
///
/// ```
/// use rama_http_headers::SaveData;
///
/// let save_data = SaveData::on();
/// assert!(save_data.is_on());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SaveData(bool);

impl SaveData {
    /// The [`ClientHint`] this typed value parser corresponds to.
    pub const HINT: ClientHint = ClientHint::SaveData;

    /// Create a [`SaveData`] hint from a boolean preference.
    #[must_use]
    pub const fn new(enabled: bool) -> Self {
        Self(enabled)
    }

    /// Create a [`SaveData`] hint requesting reduced data usage (`on`).
    #[must_use]
    pub const fn on() -> Self {
        Self(true)
    }

    /// Create a [`SaveData`] hint with data savings disabled (`off`).
    #[must_use]
    pub const fn off() -> Self {
        Self(false)
    }

    /// Returns `true` if reduced data usage is requested.
    #[must_use]
    pub const fn is_on(self) -> bool {
        self.0
    }
}

impl From<bool> for SaveData {
    fn from(enabled: bool) -> Self {
        Self(enabled)
    }
}

impl From<SaveData> for bool {
    fn from(value: SaveData) -> Self {
        value.0
    }
}

impl TypedHeader for SaveData {
    fn name() -> &'static HeaderName {
        &rama_http_types::header::SEC_CH_SAVE_DATA
    }
}

impl HeaderDecode for SaveData {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        let value = values
            .just_one()
            .and_then(|value| value.to_str().ok())
            .ok_or_else(Error::invalid)?;
        if value.eq_ignore_ascii_case("on") {
            Ok(Self(true))
        } else if value.eq_ignore_ascii_case("off") {
            Ok(Self(false))
        } else {
            Err(Error::invalid())
        }
    }
}

impl HeaderEncode for SaveData {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let value = if self.0 {
            HeaderValue::from_static("on")
        } else {
            HeaderValue::from_static("off")
        };
        values.extend(std::iter::once(value));
    }
}

/// `Sec-CH-ECT` (Effective Connection Type) client hint.
///
/// Describes the measured network performance as one of an enumerated set of
/// connection profiles, each covering a range of [`Rtt`] and [`Downlink`]
/// values. See the
/// [Network Information API](https://wicg.github.io/netinfo/#dom-effectiveconnectiontype).
///
/// Corresponds to [`ClientHint::Ect`]; encoded as `Sec-CH-ECT`.
///
/// # Example
///
/// ```
/// use rama_http_headers::Ect;
///
/// assert_eq!(Ect::Type4g.as_str(), "4g");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ect {
    /// `slow-2g`
    Slow2g,
    /// `2g`
    Type2g,
    /// `3g`
    Type3g,
    /// `4g`
    Type4g,
}

impl Ect {
    /// The [`ClientHint`] this typed value parser corresponds to.
    pub const HINT: ClientHint = ClientHint::Ect;

    /// Returns the canonical wire representation of this connection type.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Slow2g => "slow-2g",
            Self::Type2g => "2g",
            Self::Type3g => "3g",
            Self::Type4g => "4g",
        }
    }
}

impl std::fmt::Display for Ect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TypedHeader for Ect {
    fn name() -> &'static HeaderName {
        &rama_http_types::header::SEC_CH_ECT
    }
}

impl HeaderDecode for Ect {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        let value = values
            .just_one()
            .and_then(|value| value.to_str().ok())
            .ok_or_else(Error::invalid)?;
        rama_utils::macros::match_ignore_ascii_case_str! {
            match (value) {
                "slow-2g" => Ok(Self::Slow2g),
                "2g" => Ok(Self::Type2g),
                "3g" => Ok(Self::Type3g),
                "4g" => Ok(Self::Type4g),
                _ => Err(Error::invalid()),
            }
        }
    }
}

impl HeaderEncode for Ect {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(std::iter::once(HeaderValue::from_static(self.as_str())));
    }
}

/// `Sec-CH-RTT` client hint: the approximate round-trip time on the application
/// layer, modelled as a [`Duration`].
///
/// Unlike transport-layer RTT this includes server processing time. The value
/// is rounded to the nearest 25 ms to limit fingerprinting. See the
/// [Network Information API](https://wicg.github.io/netinfo/#dom-networkinformation-rtt).
///
/// Corresponds to [`ClientHint::Rtt`]; encoded as `Sec-CH-RTT`.
///
/// # Example
///
/// ```
/// use std::time::Duration;
/// use rama_http_headers::Rtt;
///
/// let rtt = Rtt::from_millis(100);
/// assert_eq!(Duration::from(rtt), Duration::from_millis(100));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rtt(u64);

impl Rtt {
    /// The [`ClientHint`] this typed value parser corresponds to.
    pub const HINT: ClientHint = ClientHint::Rtt;

    /// Create an [`Rtt`] hint from a round-trip time in milliseconds.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// Returns the round-trip time in milliseconds.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Returns the round-trip time as a [`Duration`].
    #[must_use]
    pub const fn as_duration(self) -> Duration {
        Duration::from_millis(self.0)
    }
}

impl From<Rtt> for Duration {
    fn from(rtt: Rtt) -> Self {
        rtt.as_duration()
    }
}

impl TypedHeader for Rtt {
    fn name() -> &'static HeaderName {
        &rama_http_types::header::SEC_CH_RTT
    }
}

impl HeaderDecode for Rtt {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        values
            .just_one()
            .and_then(|value| value.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .map(Self)
            .ok_or_else(Error::invalid)
    }
}

impl HeaderEncode for Rtt {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(std::iter::once(self.0.into()));
    }
}

/// `Sec-CH-Downlink` client hint: the approximate downstream speed of the
/// user's connection, in megabits per second (Mbps).
///
/// The value is rounded to the nearest 25 kbps to limit fingerprinting. See the
/// [Network Information API](https://wicg.github.io/netinfo/#dom-networkinformation-downlink).
///
/// Corresponds to [`ClientHint::Downlink`]; encoded as `Sec-CH-Downlink`.
///
/// # Example
///
/// ```
/// use rama_http_headers::Downlink;
///
/// let downlink = Downlink::new(1.6);
/// assert_eq!(downlink.as_mbps(), 1.6);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Downlink(f64);

impl Downlink {
    /// The [`ClientHint`] this typed value parser corresponds to.
    pub const HINT: ClientHint = ClientHint::Downlink;

    /// Create a [`Downlink`] hint from a speed in megabits per second.
    #[must_use]
    pub const fn new(mbps: f64) -> Self {
        Self(mbps)
    }

    /// Returns the downstream speed in megabits per second.
    #[must_use]
    pub const fn as_mbps(self) -> f64 {
        self.0
    }
}

impl From<Downlink> for f64 {
    fn from(downlink: Downlink) -> Self {
        downlink.0
    }
}

impl TypedHeader for Downlink {
    fn name() -> &'static HeaderName {
        &rama_http_types::header::SEC_CH_DOWNLINK
    }
}

impl HeaderDecode for Downlink {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        values
            .just_one()
            .and_then(|value| value.to_str().ok())
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|mbps| mbps.is_finite() && *mbps >= 0.0)
            .map(Self)
            .ok_or_else(Error::invalid)
    }
}

impl HeaderEncode for Downlink {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(std::iter::once(util::fmt(self.0)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hint_ua_from_str() {
        let hint = ClientHint::try_from("Sec-CH-UA").unwrap();
        assert_eq!(hint, ClientHint::Ua);
    }

    #[test]
    fn test_client_hint_ua_from_str_lowercase() {
        let hint = ClientHint::try_from("sec-ch-ua").unwrap();
        assert_eq!(hint, ClientHint::Ua);
    }

    #[test]
    fn test_client_hint_ua_from_str_uppercase() {
        let hint = ClientHint::try_from("SEC-CH-UA").unwrap();
        assert_eq!(hint, ClientHint::Ua);
    }

    #[test]
    fn test_client_hint_ua_from_str_mixedcase() {
        let hint = ClientHint::try_from("Sec-CH-UA").unwrap();
        assert_eq!(hint, ClientHint::Ua);
    }

    #[test]
    fn test_client_hint_low_entropy() {
        let hints = [
            "Sec-CH-UA",
            "Sec-CH-UA-Mobile",
            "Sec-CH-UA-Platform",
            "Save-Data",
            "Sec-CH-Save-Data",
        ];

        for hint in hints {
            let hint = ClientHint::try_from(hint).expect(hint);
            assert!(hint.is_low_entropy());
        }
    }

    #[test]
    fn test_client_hint_high_entropy() {
        let hints = [
            "Sec-CH-UA-Full-Version",
            "Sec-CH-UA-Full-Version-List",
            "Sec-CH-UA-Platform-Version",
            "Sec-CH-UA-Arch",
            "Sec-CH-UA-Bitness",
            "Sec-CH-UA-WoW64",
            "Sec-CH-UA-Model",
            "Sec-CH-UA-Form-Factors",
            "Sec-CH-Width",
            "Sec-CH-Viewport-Width",
            "Sec-CH-Viewport-Height",
            "Sec-CH-DPR",
            "Sec-CH-Device-Memory",
            "Sec-CH-RTT",
            "Sec-CH-Downlink",
            "Sec-CH-ECT",
            "Sec-CH-Prefers-Color-Scheme",
            "Sec-CH-Prefers-Reduced-Motion",
            "Sec-CH-Prefers-Reduced-Transparency",
            "Sec-CH-Prefers-Contrast",
            "Sec-CH-Forced-Colors",
        ];

        for hint in hints {
            let hint = ClientHint::try_from(hint).expect(hint);
            assert!(!hint.is_low_entropy());
        }
    }

    #[test]
    fn test_all_client_hint_header_name_strings_contains_some_hints() {
        let strings = all_client_hint_header_name_strings().collect::<Vec<_>>();
        assert!(strings.contains(&"sec-ch-ua"), "{strings:?}");
    }

    #[test]
    fn test_all_client_hint_header_names() {
        let names = all_client_hint_header_names().collect::<Vec<_>>();
        let strings = all_client_hint_header_name_strings().collect::<Vec<_>>();
        assert_eq!(names.len(), strings.len());
        for (name, string) in names.iter().zip(strings.iter()) {
            assert_eq!(name.as_str(), *string);
        }
    }

    fn decode<T: HeaderDecode>(values: &[&str]) -> Option<T> {
        use crate::HeaderMapExt;
        let mut map = rama_http_types::HeaderMap::new();
        for value in values {
            map.append(T::name(), value.parse().unwrap());
        }
        map.typed_get()
    }

    fn encode<T: HeaderEncode>(header: T) -> String {
        use crate::HeaderMapExt;
        let mut map = rama_http_types::HeaderMap::new();
        map.typed_insert(header);
        map.get(T::name())
            .expect("header set")
            .to_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn test_save_data_decode() {
        assert_eq!(decode::<SaveData>(&["on"]), Some(SaveData::on()));
        assert_eq!(decode::<SaveData>(&["ON"]), Some(SaveData::on()));
        assert_eq!(decode::<SaveData>(&["off"]), Some(SaveData::off()));
        assert!(decode::<SaveData>(&["1"]).is_none());
        assert!(decode::<SaveData>(&[""]).is_none());
        assert!(decode::<SaveData>(&["on", "off"]).is_none());
    }

    #[test]
    fn test_save_data_round_trip() {
        assert_eq!(encode(SaveData::on()), "on");
        assert_eq!(encode(SaveData::off()), "off");
        assert_eq!(
            decode::<SaveData>(&[encode(SaveData::on()).as_str()]),
            Some(SaveData::on())
        );
    }

    #[test]
    fn test_ect_decode() {
        assert_eq!(decode::<Ect>(&["slow-2g"]), Some(Ect::Slow2g));
        assert_eq!(decode::<Ect>(&["2g"]), Some(Ect::Type2g));
        assert_eq!(decode::<Ect>(&["3g"]), Some(Ect::Type3g));
        assert_eq!(decode::<Ect>(&["4g"]), Some(Ect::Type4g));
        assert_eq!(decode::<Ect>(&["SLOW-2G"]), Some(Ect::Slow2g));
        assert!(decode::<Ect>(&["5g"]).is_none());
        assert!(decode::<Ect>(&[""]).is_none());
    }

    #[test]
    fn test_ect_round_trip() {
        for ect in [Ect::Slow2g, Ect::Type2g, Ect::Type3g, Ect::Type4g] {
            assert_eq!(decode::<Ect>(&[encode(ect).as_str()]), Some(ect));
        }
    }

    #[test]
    fn test_rtt_decode() {
        assert_eq!(
            decode::<Rtt>(&["100"]).map(Duration::from),
            Some(Duration::from_millis(100)),
        );
        assert_eq!(decode::<Rtt>(&["0"]), Some(Rtt::from_millis(0)));
        assert!(decode::<Rtt>(&["-25"]).is_none());
        assert!(decode::<Rtt>(&["1.5"]).is_none());
        assert!(decode::<Rtt>(&["fast"]).is_none());
    }

    #[test]
    fn test_rtt_round_trip() {
        assert_eq!(encode(Rtt::from_millis(125)), "125");
        assert_eq!(decode::<Rtt>(&["125"]), Some(Rtt::from_millis(125)));
    }

    #[test]
    fn test_downlink_decode() {
        assert_eq!(decode::<Downlink>(&["1.5"]), Some(Downlink::new(1.5)));
        assert_eq!(decode::<Downlink>(&["100"]), Some(Downlink::new(100.0)));
        assert_eq!(decode::<Downlink>(&["0"]), Some(Downlink::new(0.0)));
        assert!(decode::<Downlink>(&["-1"]).is_none());
        assert!(decode::<Downlink>(&["inf"]).is_none());
        assert!(decode::<Downlink>(&["fast"]).is_none());
    }

    #[test]
    fn test_downlink_round_trip() {
        assert_eq!(encode(Downlink::new(1.5)), "1.5");
        assert_eq!(encode(Downlink::new(100.0)), "100");
        assert_eq!(decode::<Downlink>(&["1.5"]), Some(Downlink::new(1.5)));
    }

    #[test]
    fn test_accept_ch_decode() {
        use rama_utils::collections::non_empty_smallvec;

        assert_eq!(
            decode::<AcceptCh>(&["sec-ch-ua, sec-ch-ua-platform, sec-ch-ua-mobile"]),
            Some(AcceptCh(non_empty_smallvec![
                ClientHint::Ua,
                ClientHint::Platform,
                ClientHint::Mobile; 16
            ])),
        );
        // case-insensitive and legacy aliases both map onto the canonical hint
        assert_eq!(
            decode::<AcceptCh>(&["DPR, save-data"]),
            Some(AcceptCh(non_empty_smallvec![
                ClientHint::Dpr,
                ClientHint::SaveData; 16
            ])),
        );
        // multiple header lines fold into a single list
        assert_eq!(
            decode::<AcceptCh>(&["sec-ch-ua", "sec-ch-ua-platform"]),
            Some(AcceptCh(non_empty_smallvec![
                ClientHint::Ua,
                ClientHint::Platform; 16
            ])),
        );
        // an unknown hint poisons the whole list
        assert!(decode::<AcceptCh>(&["sec-ch-ua, not-a-hint"]).is_none());
        assert!(decode::<AcceptCh>(&[""]).is_none());
        assert!(decode::<AcceptCh>(&[]).is_none());
    }

    #[test]
    fn test_accept_ch_round_trip() {
        use rama_utils::collections::non_empty_smallvec;

        let header = AcceptCh(non_empty_smallvec![
            ClientHint::Ua,
            ClientHint::Platform,
            ClientHint::Mobile; 16
        ]);
        assert_eq!(
            encode(header.clone()),
            "sec-ch-ua, sec-ch-ua-platform, sec-ch-ua-mobile",
        );
        assert_eq!(
            decode::<AcceptCh>(&[encode(header.clone()).as_str()]),
            Some(header)
        );
    }

    #[test]
    fn test_critical_ch_round_trip() {
        use rama_utils::collections::non_empty_smallvec;

        let header = CriticalCh(non_empty_smallvec![ClientHint::Ua, ClientHint::Platform; 16]);
        assert_eq!(encode(header.clone()), "sec-ch-ua, sec-ch-ua-platform");
        assert_eq!(
            decode::<CriticalCh>(&[encode(header.clone()).as_str()]),
            Some(header),
        );
    }

    #[test]
    fn test_typed_value_parsers_match_their_client_hint() {
        assert_eq!(SaveData::HINT, ClientHint::SaveData);
        assert_eq!(Ect::HINT, ClientHint::Ect);
        assert_eq!(Rtt::HINT, ClientHint::Rtt);
        assert_eq!(Downlink::HINT, ClientHint::Downlink);

        // the typed header name must agree with the hint's preferred name
        assert_eq!(SaveData::name().as_str(), SaveData::HINT.as_str());
        assert_eq!(Ect::name().as_str(), Ect::HINT.as_str());
        assert_eq!(Rtt::name().as_str(), Rtt::HINT.as_str());
        assert_eq!(Downlink::name().as_str(), Downlink::HINT.as_str());
    }
}
