use itertools::Itertools as _;
use rand::seq::IndexedRandom as _;
use std::collections::HashMap;

use crate::{DeviceKind, PlatformKind, UserAgent, UserAgentKind, profile::UserAgentProfile};

#[derive(Debug, Default)]
pub struct UserAgentDatabase {
    profiles: Vec<UserAgentProfile>,

    map_ua_string: HashMap<String, usize>,

    map_ua_kind: HashMap<UserAgentKind, Vec<usize>>,
    map_platform: HashMap<(UserAgentKind, PlatformKind), Vec<usize>>,
    map_device: HashMap<(UserAgentKind, DeviceKind), Vec<usize>>,
}

impl UserAgentDatabase {
    /// Load the profiles embedded with the rama-ua crate.
    ///
    /// This function is only available if the `embed-profiles` feature is enabled.
    #[cfg(feature = "embed-profiles")]
    pub fn embedded() -> Self {
        let profiles = crate::profile::load_embedded_profiles();
        Self::from_iter(profiles)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    pub fn iter_ua_str(&self) -> impl Iterator<Item = &str> {
        self.map_ua_string.keys().map(|s| s.as_str())
    }

    pub fn iter_ua_kind(&self) -> impl Iterator<Item = &UserAgentKind> {
        self.map_ua_kind.keys()
    }

    pub fn iter_platform(&self) -> impl Iterator<Item = &PlatformKind> {
        self.map_platform
            .keys()
            .map(|(_, platform)| platform)
            .dedup()
    }

    pub fn iter_device(&self) -> impl Iterator<Item = &DeviceKind> {
        self.map_device.keys().map(|(_, device)| device).dedup()
    }

    pub fn insert(&mut self, profile: UserAgentProfile) {
        let index = self.profiles.len();
        if let Some(ua_header) = profile.ua_str() {
            self.map_ua_string.insert(ua_header.to_owned(), index);
        }

        self.map_ua_kind
            .entry(profile.ua_kind)
            .or_default()
            .push(index);

        if let Some(platform) = profile.platform {
            self.map_platform
                .entry((profile.ua_kind, platform))
                .or_default()
                .push(index);
            self.map_device
                .entry((profile.ua_kind, platform.device()))
                .or_default()
                .push(index);
        }

        self.profiles.push(profile);
    }

    pub fn rnd(&self) -> Option<&UserAgentProfile> {
        let ua_kind = self.market_rnd_ua_kind();
        self.map_ua_kind
            .get(&ua_kind)
            .and_then(|v| v.choose(&mut rand::rng()))
            .and_then(|idx| self.profiles.get(*idx))
    }

    pub fn get(&self, ua: &UserAgent) -> Option<&UserAgentProfile> {
        if let Some(profile) = self
            .map_ua_string
            .get(ua.header_str())
            .and_then(|idx| self.profiles.get(*idx))
        {
            return Some(profile);
        }

        match (ua.ua_kind(), ua.platform(), ua.device()) {
            (Some(ua_kind), Some(platform), _) => {
                // UA + Platform Match (e.g. chrome windows)
                self.map_platform
                    .get(&(ua_kind, platform))
                    .and_then(|v| v.choose(&mut rand::rng()))
                    .and_then(|idx| self.profiles.get(*idx))
            }
            (Some(ua_kind), None, Some(device)) => {
                // UA + Device match (e.g. firefox desktop)
                self.map_device
                    .get(&(ua_kind, device))
                    .and_then(|v| v.choose(&mut rand::rng()))
                    .and_then(|idx| self.profiles.get(*idx))
            }
            (Some(ua_kind), None, None) => {
                // random profile for this UA
                self.map_ua_kind
                    .get(&ua_kind)
                    .and_then(|v| v.choose(&mut rand::rng()))
                    .and_then(|idx| self.profiles.get(*idx))
            }
            (None, Some(platform), _) => {
                // NOTE: I guestimated these numbers... Feel free to help improve these
                let ua_kind = match platform {
                    PlatformKind::Windows => self.market_rnd_ua_kind_with_shares(7, 0),
                    PlatformKind::MacOS => self.market_rnd_ua_kind_with_shares(9, 35),
                    PlatformKind::Linux => self.market_rnd_ua_kind_with_shares(22, 0),
                    PlatformKind::Android => self.market_rnd_ua_kind_with_shares(3, 0),
                    PlatformKind::IOS => self.market_rnd_ua_kind_with_shares(5, 42),
                };
                self.map_platform
                    .get(&(ua_kind, platform))
                    .and_then(|v| v.choose(&mut rand::rng()))
                    .and_then(|idx| self.profiles.get(*idx))
            }
            (None, None, device) => {
                // random ua kind matching with device or not
                match device {
                    Some(device) => {
                        let ua_kind = match device {
                            // https://gs.statcounter.com/browser-market-share/desktop/worldwide (feb 2025)
                            DeviceKind::Desktop => self.market_rnd_ua_kind_with_shares(7, 9),
                            // https://gs.statcounter.com/browser-market-share/mobile/worldwide (feb 2025)
                            DeviceKind::Mobile => self.market_rnd_ua_kind_with_shares(1, 23),
                        };
                        self.map_device
                            .get(&(ua_kind, device))
                            .and_then(|v| v.choose(&mut rand::rng()))
                            .and_then(|idx| self.profiles.get(*idx))
                    }
                    None => {
                        let ua_kind = self.market_rnd_ua_kind();
                        self.map_ua_kind
                            .get(&ua_kind)
                            .and_then(|v| v.choose(&mut rand::rng()))
                            .and_then(|idx| self.profiles.get(*idx))
                    }
                }
            }
        }
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &UserAgentProfile> {
        self.profiles.iter()
    }

    fn market_rnd_ua_kind(&self) -> UserAgentKind {
        // https://gs.statcounter.com/browser-market-share/mobile/worldwide (feb 2025)
        self.market_rnd_ua_kind_with_shares(3, 18)
    }

    fn market_rnd_ua_kind_with_shares(&self, firefox: i32, safari: i32) -> UserAgentKind {
        let r = rand::random_range(0..=100);
        if r < firefox && self.map_ua_kind.contains_key(&UserAgentKind::Firefox) {
            UserAgentKind::Firefox
        } else if r < safari + firefox && self.map_ua_kind.contains_key(&UserAgentKind::Safari) {
            UserAgentKind::Safari
        } else {
            UserAgentKind::Chromium
        }
    }
}

impl FromIterator<UserAgentProfile> for UserAgentDatabase {
    fn from_iter<T: IntoIterator<Item = UserAgentProfile>>(iter: T) -> Self {
        let iter = iter.into_iter();
        let (lb, _) = iter.size_hint();
        assert!(lb < usize::MAX);

        let mut db = UserAgentDatabase {
            profiles: Vec::with_capacity(lb),
            ..Default::default()
        };

        for profile in iter {
            db.insert(profile);
        }

        db
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rama_http_types::{HeaderValue, header::USER_AGENT, proto::h1::Http1HeaderMap};

    use super::*;

    #[test]
    fn test_ua_db_empty() {
        let db = UserAgentDatabase::default();
        assert_eq!(db.iter().count(), 0);
        assert!(db.get(&UserAgent::new("")).is_none());
        assert!(db.get(&UserAgent::new("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")).is_none());

        let rnd = db.rnd();
        assert!(rnd.is_none());

        assert!(db.iter_ua_str().next().is_none());
        assert!(db.iter_ua_kind().next().is_none());
        assert!(db.iter_platform().next().is_none());
        assert!(db.iter_device().next().is_none());
    }

    #[test]
    fn test_ua_db_get_by_ua_str() {
        let db = get_dummy_ua_db();

        let profile = db.get(&UserAgent::new("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0")).unwrap();
        assert_eq!(profile.ua_kind, UserAgentKind::Chromium);
        assert_eq!(profile.ua_version, Some(120));
        assert_eq!(profile.platform, Some(PlatformKind::Windows));
        assert_eq!(
            profile
                .http
                .h1
                .headers
                .navigate
                .get(USER_AGENT)
                .unwrap()
                .to_str()
                .unwrap(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
        );
        assert_eq!(
            profile
                .http
                .h2
                .headers
                .navigate
                .get(USER_AGENT)
                .unwrap()
                .to_str()
                .unwrap(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
        );
    }

    #[test]
    fn test_ua_db_get_by_ua_kind_and_device() {
        let db = get_dummy_ua_db();
        let test_cases = [
            (
                "Chrome Desktop",
                UserAgentKind::Chromium,
                DeviceKind::Desktop,
            ),
            ("Chrome Mobile", UserAgentKind::Chromium, DeviceKind::Mobile),
            (
                "Desktop Firefox",
                UserAgentKind::Firefox,
                DeviceKind::Desktop,
            ),
            (
                "Mobile with Firefox",
                UserAgentKind::Firefox,
                DeviceKind::Mobile,
            ),
            (
                "Safari on Desktop",
                UserAgentKind::Safari,
                DeviceKind::Desktop,
            ),
            ("mobile&safari", UserAgentKind::Safari, DeviceKind::Mobile),
        ];

        for (ua_str, ua_kind, device) in test_cases {
            let profile = db.get(&UserAgent::new(ua_str)).expect(ua_str);
            assert_eq!(profile.ua_kind, ua_kind);
            assert!(
                profile
                    .platform
                    .map(|p| p.device() == device)
                    .unwrap_or_default()
            );
        }
    }

    #[test]
    fn test_ua_db_get_by_ua_kind_and_platform() {
        let db = get_dummy_ua_db();
        let test_cases = [
            (
                "Chrome Windows",
                UserAgentKind::Chromium,
                PlatformKind::Windows,
            ),
            ("MacOS Chrome", UserAgentKind::Chromium, PlatformKind::MacOS),
            (
                "Chrome&Windows",
                UserAgentKind::Chromium,
                PlatformKind::Windows,
            ),
            (
                "Firefox on Windows",
                UserAgentKind::Firefox,
                PlatformKind::Windows,
            ),
            (
                "MacOS with Firefox",
                UserAgentKind::Firefox,
                PlatformKind::MacOS,
            ),
            (
                "Firefox + Linux",
                UserAgentKind::Firefox,
                PlatformKind::Linux,
            ),
        ];

        for (ua_str, ua_kind, platform) in test_cases {
            let profile = db.get(&UserAgent::new(ua_str)).expect(ua_str);
            assert_eq!(profile.ua_kind, ua_kind);
            assert_eq!(profile.platform, Some(platform));
        }
    }

    #[test]
    fn test_ua_db_get_by_ua_kind() {
        let db = get_dummy_ua_db();
        let test_cases = [
            ("Firefox", UserAgentKind::Firefox),
            ("Safari", UserAgentKind::Safari),
            ("Chrome", UserAgentKind::Chromium),
            ("Chromium", UserAgentKind::Chromium),
        ];

        for (ua_str, ua_kind) in test_cases {
            let profile = db.get(&UserAgent::new(ua_str)).expect(ua_str);
            assert_eq!(profile.ua_kind, ua_kind, "ua_str: {}", ua_str);
        }
    }

    #[test]
    fn test_ua_db_get_by_device() {
        let db = get_dummy_ua_db();
        let test_cases = [
            ("Desktop", DeviceKind::Desktop),
            ("DESKTOP", DeviceKind::Desktop),
            ("desktop", DeviceKind::Desktop),
            ("Mobile", DeviceKind::Mobile),
            ("MOBILE", DeviceKind::Mobile),
            ("mobile", DeviceKind::Mobile),
        ];

        for (ua_str, device) in test_cases {
            let profile = db.get(&UserAgent::new(ua_str)).expect(ua_str);
            assert_eq!(
                profile.platform.map(|p| p.device() == device),
                Some(true),
                "ua_str: {}",
                ua_str
            );
        }
    }

    #[test]
    fn test_ua_db_rnd() {
        let db = get_dummy_ua_db();

        let mut set = std::collections::HashSet::new();
        for _ in 0..db.len() * 1000 {
            let rnd = db.rnd().unwrap();
            set.insert(
                rnd.http
                    .h1
                    .headers
                    .navigate
                    .get(USER_AGENT)
                    .expect("ua header")
                    .to_str()
                    .expect("utf-8 ua header value")
                    .to_owned(),
            );
        }

        assert_eq!(set.len(), db.len());
    }

    fn dummy_ua_profile_from_str(s: &str) -> UserAgentProfile {
        let ua = UserAgent::new(s);
        UserAgentProfile {
            ua_kind: ua.ua_kind().unwrap(),
            ua_version: ua.ua_version(),
            platform: ua.platform(),
            http: crate::profile::HttpProfile {
                h1: Arc::new(crate::profile::Http1Profile {
                    headers: crate::profile::HttpHeadersProfile {
                        navigate: Http1HeaderMap::new(
                            [(USER_AGENT, HeaderValue::from_str(s).unwrap())]
                                .into_iter()
                                .collect(),
                            None,
                        ),
                        fetch: None,
                        xhr: None,
                        form: None,
                    },
                    settings: crate::profile::Http1Settings::default(),
                }),
                h2: Arc::new(crate::profile::Http2Profile {
                    headers: crate::profile::HttpHeadersProfile {
                        navigate: Http1HeaderMap::new(
                            [(USER_AGENT, HeaderValue::from_str(s).unwrap())]
                                .into_iter()
                                .collect(),
                            None,
                        ),
                        fetch: None,
                        xhr: None,
                        form: None,
                    },
                    settings: crate::profile::Http2Settings::default(),
                }),
            },
            #[cfg(feature = "tls")]
            tls: crate::profile::TlsProfile {
                client_config: std::sync::Arc::new(rama_net::tls::client::ClientConfig::default()),
            },
            js: None,
        }
    }

    fn get_dummy_ua_db() -> UserAgentDatabase {
        let mut db = UserAgentDatabase::default();

        db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"));
        db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"));
        db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"));
        db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"));
        db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (Linux; Android 10; HD1913) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 EdgA/120.0.0.0"));
        db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 EdgiOS/120.0.0.0 Mobile/15E148 Safari/605.1.15"));
        db.insert(dummy_ua_profile_from_str(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        ));
        db.insert(dummy_ua_profile_from_str(
            "Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        ));
        db.insert(dummy_ua_profile_from_str(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
        ));
        db.insert(dummy_ua_profile_from_str(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.1; rv:120.0) Gecko/20100101 Firefox/120.0",
        ));
        db.insert(dummy_ua_profile_from_str(
            "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        ));
        db.insert(dummy_ua_profile_from_str(
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        ));
        db.insert(dummy_ua_profile_from_str(
            "Mozilla/5.0 (Android 14; Mobile; rv:120.0) Gecko/120.0 Firefox/120.0",
        ));
        db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/120.0 Mobile/15E148 Safari/605.1.15"));
        db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"));
        db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"));
        db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"));
        db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (iPad; CPU OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"));
        db.insert(dummy_ua_profile_from_str("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"));

        db
    }

    #[cfg(feature = "embed-profiles")]
    #[test]
    fn test_ua_db_embedded() {
        let db = UserAgentDatabase::embedded();
        assert!(!db.is_empty());
    }
}
