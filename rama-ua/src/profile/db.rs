use itertools::Itertools as _;
use rand::seq::IndexedRandom as _;
use std::collections::HashMap;

use crate::{DeviceKind, PlatformKind, UserAgent, UserAgentKind, UserAgentProfile};

#[derive(Debug, Default)]
pub struct UserAgentDatabase {
    profiles: Vec<UserAgentProfile>,

    map_ua_string: HashMap<String, usize>,

    map_ua_kind: HashMap<UserAgentKind, Vec<usize>>,
    map_platform: HashMap<(UserAgentKind, PlatformKind), Vec<usize>>,
    map_device: HashMap<(UserAgentKind, DeviceKind), Vec<usize>>,
}

impl UserAgentDatabase {
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
