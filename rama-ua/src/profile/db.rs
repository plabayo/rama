use rand::seq::IndexedRandom as _;
use std::collections::HashMap;

use crate::{DeviceKind, PlatformKind, UserAgent, UserAgentKind, UserAgentProfile};

#[derive(Debug, Default)]
pub struct UserAgentDatabase {
    profiles: Vec<UserAgentProfile>,

    map_ua_string: HashMap<String, usize>,

    map_platform: HashMap<(UserAgentKind, PlatformKind), Vec<usize>>,
    map_device: HashMap<(UserAgentKind, DeviceKind), Vec<usize>>,
}

impl UserAgentDatabase {
    pub fn insert(&mut self, profile: UserAgentProfile) {
        let index = self.profiles.len();
        if let Some(ua_header) = profile.ua_str() {
            self.map_ua_string.insert(ua_header.to_string(), index);
        }

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

    pub fn get(&self, ua: &UserAgent) -> Option<&UserAgentProfile> {
        if let Some(profile) = self
            .map_ua_string
            .get(ua.header_str())
            .and_then(|idx| self.profiles.get(*idx))
        {
            return Some(profile);
        }

        match ua.ua_kind() {
            Some(ua_kind) => match ua.platform() {
                // UA + Platform Match (e.g. chrome windows)
                Some(platform) => self
                    .map_platform
                    .get(&(ua_kind, platform))
                    .and_then(|v| v.choose(&mut rand::rng()))
                    .and_then(|idx| self.profiles.get(*idx)),
                // UA + Device match (e.g. firefox desktop)
                None => {
                    let device = ua.device();
                    self.map_device
                        .get(&(ua_kind, device))
                        .and_then(|v| v.choose(&mut rand::rng()))
                        .and_then(|idx| self.profiles.get(*idx))
                }
            },
            // Market-share Kind + Device match (e.g. chrome desktop)
            None => {
                let device = ua.device();

                // market share from
                // https://gs.statcounter.com/browser-market-share/mobile/worldwide (feb 2025)
                let r = rand::random_range(0..=100);
                let ua_kind = if r < 3
                    && self
                        .map_device
                        .contains_key(&(UserAgentKind::Firefox, device))
                {
                    UserAgentKind::Firefox
                } else if r < 18
                    && self
                        .map_device
                        .contains_key(&(UserAgentKind::Safari, device))
                {
                    UserAgentKind::Safari
                } else {
                    // ~79% x-x
                    UserAgentKind::Chromium
                };

                self.map_device
                    .get(&(ua_kind, device))
                    .and_then(|v| v.choose(&mut rand::rng()))
                    .and_then(|idx| self.profiles.get(*idx))
            }
        }
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &UserAgentProfile> {
        self.profiles.iter()
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
