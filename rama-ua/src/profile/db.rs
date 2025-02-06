use rand::{
    distr::{weighted::WeightedIndex, Distribution as _},
    seq::{IndexedRandom as _, IteratorRandom as _},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{Initiator, PlatformKind, UserAgentKind};

#[derive(Debug, Default)]
pub struct UserAgentDatabase {
    profiles: HashMap<UserAgentProfileKey, UserAgentProfile>,

    http_profiles: HashMap<u64, crate::HttpProfile>,

    #[cfg(feature = "tls")]
    tls_profiles: HashMap<u64, crate::TlsProfile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UserAgentProfileKey {
    pub ua_kind: UserAgentKind,
    pub ua_kind_version: usize,
    pub platform_kind: PlatformKind,
}

#[derive(Debug)]
struct UserAgentProfile {
    pub ua_kind: UserAgentKind,
    pub platform_kind: PlatformKind,
    pub http_profiles: Vec<u64>,

    #[cfg(feature = "tls")]
    pub tls_profiles: Vec<u64>,
}

impl UserAgentProfile {
    fn match_filters(&self, kind_mask: u8, platform_mask: u8) -> bool {
        if self.http_profiles.is_empty() {
            return false;
        }

        #[cfg(feature = "tls")]
        if self.tls_profiles.is_empty() {
            return false;
        }

        self.ua_kind as u8 & kind_mask != 0 && self.platform_kind as u8 & platform_mask != 0
    }
}

impl UserAgentDatabase {
    /// Create a new user agent database.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct UserAgentFilter {
    pub kind: u8,
    pub platform: u8,
    pub initiator: Option<Initiator>,
}

#[derive(Debug, Clone)]
pub struct UserAgentProfileQueryResult<'a> {
    pub http: &'a crate::HttpProfile,

    #[cfg(feature = "tls")]
    pub tls: &'a crate::TlsProfile,
}

#[derive(Serialize, Deserialize)]
struct UserAgentFilterSerde {
    kind: Option<Vec<UserAgentKind>>,
    platform: Option<Vec<PlatformKind>>,
    initiator: Option<Initiator>,
}

impl Serialize for UserAgentFilter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut kinds = Vec::new();
        if self.kind | UserAgentKind::Chromium as u8 != 0 {
            kinds.push(UserAgentKind::Chromium);
        }
        if self.kind | UserAgentKind::Firefox as u8 != 0 {
            kinds.push(UserAgentKind::Firefox);
        }
        if self.kind | UserAgentKind::Safari as u8 != 0 {
            kinds.push(UserAgentKind::Safari);
        }

        let mut platforms = Vec::new();
        if self.platform | PlatformKind::Windows as u8 != 0 {
            platforms.push(PlatformKind::Windows);
        }
        if self.platform | PlatformKind::MacOS as u8 != 0 {
            platforms.push(PlatformKind::MacOS);
        }
        if self.platform | PlatformKind::Linux as u8 != 0 {
            platforms.push(PlatformKind::Linux);
        }
        if self.platform | PlatformKind::Android as u8 != 0 {
            platforms.push(PlatformKind::Android);
        }
        if self.platform | PlatformKind::IOS as u8 != 0 {
            platforms.push(PlatformKind::IOS);
        }

        let filter = UserAgentFilterSerde {
            kind: if kinds.is_empty() { None } else { Some(kinds) },
            platform: if platforms.is_empty() {
                None
            } else {
                Some(platforms)
            },
            initiator: self.initiator,
        };
        filter.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UserAgentFilter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let filter = UserAgentFilterSerde::deserialize(deserializer)?;
        let mut result = UserAgentFilter::default();
        if let Some(kinds) = filter.kind {
            for kind in kinds {
                result.kind |= kind as u8;
            }
        }
        if let Some(platforms) = filter.platform {
            for platform in platforms {
                result.platform |= platform as u8;
            }
        }
        if let Some(initiator) = filter.initiator {
            result.initiator = Some(initiator);
        }
        Ok(result)
    }
}

impl UserAgentDatabase {
    pub fn insert_http_profile(&mut self, profile: crate::UserAgentHttpProfile) {
        let key = profile.key();
        self.profiles
            .entry(UserAgentProfileKey {
                ua_kind: profile.ua_kind,
                ua_kind_version: profile.ua_kind_version,
                platform_kind: profile.platform_kind,
            })
            .or_insert_with(|| UserAgentProfile {
                ua_kind: profile.ua_kind,
                platform_kind: profile.platform_kind,
                http_profiles: Vec::new(),
                #[cfg(feature = "tls")]
                tls_profiles: Vec::new(),
            })
            .http_profiles
            .push(key);
        self.http_profiles.insert(key, profile.http);
    }

    #[cfg(feature = "tls")]
    pub fn insert_tls_profile(&mut self, profile: crate::UserAgentTlsProfile) {
        let key = profile.key();
        self.profiles
            .entry(UserAgentProfileKey {
                ua_kind: profile.ua_kind,
                ua_kind_version: profile.ua_kind_version,
                platform_kind: profile.platform_kind,
            })
            .or_insert_with(|| UserAgentProfile {
                ua_kind: profile.ua_kind,
                platform_kind: profile.platform_kind,
                http_profiles: Vec::new(),
                tls_profiles: Vec::new(),
            })
            .tls_profiles
            .push(key);
    }

    pub fn query(
        &self,
        filters: Option<UserAgentFilter>,
    ) -> Option<UserAgentProfileQueryResult<'_>> {
        let filter = filters.unwrap_or_default();
        let mut rng = rand::rng();

        let kind_mask = if filter.kind == 0 {
            tracing::trace!("no kind filter provided, using all");
            u8::MAX
        } else {
            filter.kind
        };

        let platform_mask = if filter.platform == 0 {
            tracing::trace!("no platform filter provided, using all");
            u8::MAX
        } else {
            filter.platform
        };

        let profiles: Vec<_> = self
            .profiles
            .values()
            .filter(|profile| profile.match_filters(kind_mask, platform_mask))
            .collect();
        if profiles.is_empty() {
            tracing::debug!(?filter, "no profiles found for provided filters");
            return None;
        } else {
            tracing::trace!(
                ?filter,
                "found {} profile(s) for provided filters",
                profiles.len()
            );
        }

        // market share from https://gs.statcounter.com/browser-market-share/mobile/worldwide (feb 2025)
        let weights: Vec<f64> = profiles
            .iter()
            .map(|profiles| match profiles.ua_kind {
                UserAgentKind::Firefox => 0.03,
                UserAgentKind::Safari => 0.18,
                UserAgentKind::Chromium => 0.79,
            })
            .collect();
        let dist = WeightedIndex::new(&weights).ok()?;
        let profile = profiles.get(dist.sample(&mut rng))?;

        // try to get random http profile with initiator if defined, else random http profile
        let http_profile_index = if let Some(initiator) = filter.initiator {
            profile
                .http_profiles
                .iter()
                .filter(|key| {
                    self.http_profiles
                        .get(key)
                        .map(|http| http.initiator == initiator)
                        .unwrap_or(false)
                })
                .choose(&mut rng)
        } else {
            profile.http_profiles.choose(&mut rng)
        }?;
        let http_profile = self.http_profiles.get(http_profile_index)?;

        #[cfg(feature = "tls")]
        let tls_profile = profile
            .tls_profiles
            .choose(&mut rng)
            .and_then(|key| self.tls_profiles.get(key))?;

        Some(UserAgentProfileQueryResult {
            http: http_profile,
            #[cfg(feature = "tls")]
            tls: tls_profile,
        })
    }
}
