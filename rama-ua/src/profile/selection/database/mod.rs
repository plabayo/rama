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
use rama_core::error::BoxError;
use std::{ptr, sync::Arc};

use crate::profile::model::ua::UserAgentProfile;

#[derive(Debug, Default)]
/// In-memory catalogue of captured user-agent profiles.
///
/// Profiles are drawn per request flow by [`UserAgentDatabase::select`], weighted by
/// how often each was observed, and can be looked up by exact User-Agent header value.
pub struct UserAgentDatabase {
    profiles: Vec<UserAgentProfile>,
    request_shapes: Vec<Option<Arc<RequestShapeCache>>>,
    version_index: ProfileVersionIndex,
    map_ua_string: HashMap<Box<str>, Vec<usize>>,
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
    /// Complementary rows with the same User-Agent are merged and converted into
    /// captured profiles; missing HTTP/1, HTTP/2 or TLS components are never synthesized.
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
        self.map_ua_string.keys().map(AsRef::as_ref)
    }

    /// Insert a new [`UserAgentProfile`] into the database,
    /// also indexing it by its User-Agent header value.
    pub fn insert(&mut self, profile: UserAgentProfile) {
        let index = self.profiles.len();
        self.version_index.insert(&profile.key, index);
        if let Some(ua_header) = profile.ua_str() {
            self.map_ua_string
                .entry(ua_header.into())
                .or_default()
                .push(index);
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

    /// Every [`UserAgentProfile`] observed with exactly this User-Agent header value.
    pub fn get_exact_header_str(&self, ua: &str) -> impl Iterator<Item = &UserAgentProfile> {
        self.map_ua_string
            .get(ua)
            .into_iter()
            .flatten()
            .filter_map(|index| self.profiles.get(*index))
    }

    #[inline]
    /// Iterate over all [`UserAgentProfile`]s in the database.
    pub fn iter(&self) -> impl Iterator<Item = &UserAgentProfile> {
        self.profiles.iter()
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
