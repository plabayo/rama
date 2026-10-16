mod index;

use crate::profile::{
    format::{
        archive::{ProfileArchiveLimits, load_profile_archive},
        canonical::ProfileDataError,
    },
    selection::variants::shapes::RequestShapeCache,
};
use ahash::HashMap;
use index::ProfileVersionIndex;
pub use index::{ProfileCandidate, ProfileCandidateFilter, ProfileCapabilities, ProfileVersion};
use itertools::Itertools as _;
use rama_core::error::BoxError;
use rand::seq::IndexedRandom as _;
use std::{ptr, sync::Arc};

use crate::{
    DeviceKind, PlatformKind, UserAgent, UserAgentKind, profile::model::ua::UserAgentProfile,
};

#[derive(Debug, Default)]
/// Reference implementation of a [`UserAgentProvider`].
///
/// It stores the profiles and several indices in memory
/// to quickly find a profile by User-Agent header value string,
/// [`UserAgentKind`], [`PlatformKind`] and [`DeviceKind`].
/// Where needed it makes use of market share data to select a random profile or subset.
///
/// See [`UserAgentProvider`] for more details.
///
/// [`UserAgentProvider`]: crate::layer::emulate::UserAgentProvider
pub struct UserAgentDatabase {
    profiles: Vec<UserAgentProfile>,
    request_shapes: Vec<Option<Arc<RequestShapeCache>>>,
    emulation_profiles: Vec<usize>,
    version_index: ProfileVersionIndex,

    map_ua_string: HashMap<String, usize>,

    map_ua_kind: HashMap<UserAgentKind, Vec<usize>>,
    map_platform: HashMap<(UserAgentKind, PlatformKind), Vec<usize>>,
    map_device: HashMap<(UserAgentKind, DeviceKind), Vec<usize>>,

    disable_unknown_user_agent_data: bool,
}

impl UserAgentDatabase {
    /// Load the profiles embedded with the rama-ua crate.
    ///
    /// This function is only available if the `embed-profiles` feature is enabled.
    #[cfg(feature = "embed-profiles")]
    #[cfg_attr(docsrs, doc(cfg(feature = "embed-profiles")))]
    pub fn try_embedded() -> Result<Self, rama_core::error::BoxError> {
        let profiles = crate::profile::format::input::try_load_embedded_profiles()?;
        Ok(Self::from_iter(profiles))
    }

    /// Load a user-agent database from a JSON array of
    /// [`UserAgentProfileInput`](crate::profile::format::input::UserAgentProfileInput) rows.
    ///
    /// Complementary rows with the same User-Agent are merged, but missing
    /// HTTP/1, HTTP/2 or TLS components are never synthesized. Partial captures
    /// remain available for inspection and capability queries; `get` and `rnd`
    /// select only profiles with compiled legacy HTTP and TLS components.
    pub fn try_from_json_slice(bytes: &[u8]) -> Result<Self, rama_core::error::BoxError> {
        let profiles = crate::profile::format::input::try_load_profiles_json(bytes)?;
        Ok(Self::from_iter(profiles))
    }

    pub fn try_from_archive(
        bytes: &[u8],
        authorized: bool,
        current_day: u32,
        horizon: u32,
        limits: ProfileArchiveLimits,
    ) -> Result<Self, BoxError> {
        Ok(
            load_profile_archive(bytes, authorized, current_day, horizon, limits)?
                .into_vec()
                .into_iter()
                .map(|entry| UserAgentProfile::from_captured(entry.analysis))
                .collect(),
        )
    }

    pub fn candidates(
        &self,
        filter: ProfileCandidateFilter<'_>,
    ) -> Result<Box<[ProfileCandidate<'_>]>, ProfileDataError> {
        let latest = filter
            .latest_versions
            .map(|maximum| self.version_index.latest(filter, maximum));
        self.profiles
            .iter()
            .enumerate()
            .filter(|(index, profile)| {
                filter
                    .client
                    .is_none_or(|client| client == profile.key.client.as_ref())
                    && filter
                        .platform
                        .is_none_or(|platform| Some(platform) == profile.key.platform)
                    && filter.device.is_none_or(|device| {
                        Some(device)
                            == profile
                                .key
                                .device
                                .or_else(|| profile.key.platform.map(|platform| platform.device()))
                    })
                    && latest
                        .as_ref()
                        .is_none_or(|indices| indices.contains(index))
                    && profile.capabilities().supports(filter.capabilities)
            })
            .map(|(_index, profile)| {
                Ok(ProfileCandidate {
                    profile,
                    weight: profile.observation_weight()?,
                })
            })
            .collect()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Disabling this option (disable = true) means here that in case
        /// you try to use [`UserAgentDatabase::get`] with a [`UserAgent`]
        /// containing no match (not even a platform or device), that it the database
        /// will return `None` instead of returning a global-random (market-based)
        /// [`UserAgentProfile`](crate::profile::model::ua::UserAgentProfile), which it would do by default.
        pub fn disable_unknown_user_agent_data(mut self, disable: bool) -> Self {
            self.disable_unknown_user_agent_data = disable;
            self
        }
    }

    #[inline]
    /// Get the number of profiles in the database.
    #[must_use]
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    #[inline]
    /// Check if the database is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// Iterate over the User-Agent header value strings in the database.
    pub fn iter_ua_str(&self) -> impl Iterator<Item = &str> {
        self.map_ua_string.keys().map(|s| s.as_str())
    }

    /// Iterate over the available [`UserAgentKind`]s in the database.
    pub fn iter_ua_kind(&self) -> impl Iterator<Item = &UserAgentKind> {
        self.map_ua_kind.keys()
    }

    /// Iterate over the available [`PlatformKind`]s in the database.
    pub fn iter_platform(&self) -> impl Iterator<Item = &PlatformKind> {
        self.map_platform
            .keys()
            .map(|(_, platform)| platform)
            .dedup()
    }

    /// Iterate over the available [`DeviceKind`]s in the database.
    pub fn iter_device(&self) -> impl Iterator<Item = &DeviceKind> {
        self.map_device.keys().map(|(_, device)| device).dedup()
    }

    /// Insert a new [`UserAgentProfile`] into the database,
    /// ensuring to also index it by User-Agent header value string,
    /// [`UserAgentKind`], [`PlatformKind`] and [`DeviceKind`].
    pub fn insert(&mut self, profile: UserAgentProfile) {
        let index = self.profiles.len();
        self.version_index.insert(&profile.key, index);
        if let Some(ua_header) = profile.ua_str() {
            self.map_ua_string.insert(ua_header.to_owned(), index);
        }

        if Self::emulation_ready(&profile) {
            self.emulation_profiles.push(index);
        }
        if let Some(kind) = profile.ua_kind.filter(|_| Self::emulation_ready(&profile)) {
            self.map_ua_kind.entry(kind).or_default().push(index);
            if let Some(platform) = profile.platform {
                self.map_platform
                    .entry((kind, platform))
                    .or_default()
                    .push(index);
                self.map_device
                    .entry((kind, platform.device()))
                    .or_default()
                    .push(index);
            }
        }

        self.request_shapes
            .push(profile.captured.as_ref().map(|_| Arc::default()));
        self.profiles.push(profile);
    }

    /// Each immutable database entry owns its own lazy decode cache. Profiles
    /// with the same identity may have different retained observations.
    pub(crate) fn request_shape_cache(
        &self,
        profile: &UserAgentProfile,
    ) -> Option<Arc<RequestShapeCache>> {
        self.profiles
            .iter()
            .zip(&self.request_shapes)
            .find(|(candidate, _)| ptr::eq(*candidate, profile))
            .and_then(|(_, cache)| cache.clone())
    }

    /// Select a random [`UserAgentProfile`] from the database.
    ///
    /// It makes use of global market share data to select a random profile.
    #[must_use]
    pub fn rnd(&self) -> Option<&UserAgentProfile> {
        let ua_kind = self.market_rnd_ua_kind();
        self.map_ua_kind
            .get(&ua_kind)
            .and_then(|v| v.choose(&mut rand::rng()))
            .and_then(|idx| self.profiles.get(*idx))
            .or_else(|| {
                self.emulation_profiles
                    .choose(&mut rand::rng())
                    .and_then(|index| self.profiles.get(*index))
            })
    }

    /// Get a [`UserAgentProfile`] from the database by an [`UserAgent`] header string
    #[must_use]
    pub fn get_exact_header_str(&self, ua: &str) -> Option<&UserAgentProfile> {
        self.map_ua_string
            .get(ua)
            .and_then(|idx| self.profiles.get(*idx))
    }

    /// Get a [`UserAgentProfile`] from the database by [`UserAgent`].
    ///
    /// It first tries to find the profile by User-Agent header value string,
    /// if not found it then makes use of [`UserAgentKind`], [`PlatformKind`] and [`DeviceKind`]
    /// to find a profile.
    #[must_use]
    pub fn get(&self, ua: &UserAgent) -> Option<&UserAgentProfile> {
        if let Some(profile) = self
            .map_ua_string
            .get(ua.header_str())
            .and_then(|idx| self.profiles.get(*idx))
            .filter(|profile| Self::emulation_ready(profile))
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
                        if self.disable_unknown_user_agent_data {
                            None
                        } else {
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
    }

    #[inline]
    /// Iterate over all [`UserAgentProfile`]s in the database.
    pub fn iter(&self) -> impl Iterator<Item = &UserAgentProfile> {
        self.profiles.iter()
    }

    fn emulation_ready(profile: &UserAgentProfile) -> bool {
        let Some(http) = &profile.http else {
            return false;
        };
        if http
            .h1
            .as_ref()
            .is_none_or(|h1| h1.settings.is_none() || h1.headers.navigate.is_none())
            || http
                .h2
                .as_ref()
                .is_none_or(|h2| h2.settings.is_none() || h2.headers.navigate.is_none())
        {
            return false;
        }
        #[cfg(feature = "tls")]
        if profile.tls.is_none() {
            return false;
        }
        true
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

        let mut db = Self {
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
mod tests;
