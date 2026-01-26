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
}
