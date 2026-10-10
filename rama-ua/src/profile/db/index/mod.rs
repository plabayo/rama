use std::collections::{BTreeMap, BTreeSet};

use ahash::HashMap;

use crate::profile::{
    CanonicalDomain, ObservationWeight, ProfileDataError, ProfileKey, UserAgentProfile,
};
use crate::{DeviceKind, PlatformKind};

/// Numeric dotted versions sort by components, rather than lexical labels.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProfileVersion(Box<[u64]>);

impl ProfileVersion {
    pub fn parse(value: &str) -> Option<Self> {
        if value.is_empty() || value.len() > 256 {
            return None;
        }
        let mut parts = Vec::new();
        for part in value.split('.') {
            if parts.len() >= 16
                || part.is_empty()
                || !part.bytes().all(|byte| byte.is_ascii_digit())
            {
                return None;
            }
            parts.push(part.parse().ok()?);
        }
        while parts.len() > 1 && parts.last() == Some(&0) {
            parts.pop();
        }
        Some(Self(parts.into()))
    }
}

/// Required observed components. Replay additionally checks flow and provider support.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProfileCapabilities {
    pub h1: bool,
    pub h2: bool,
    pub h3: bool,
    pub tls_tcp: bool,
    pub tls_quic: bool,
    pub quic: bool,
}

impl ProfileCapabilities {
    pub fn supports(self, required: Self) -> bool {
        (!required.h1 || self.h1)
            && (!required.h2 || self.h2)
            && (!required.h3 || self.h3)
            && (!required.tls_tcp || self.tls_tcp)
            && (!required.tls_quic || self.tls_quic)
            && (!required.quic || self.quic)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProfileCandidateFilter<'a> {
    pub client: Option<&'a str>,
    pub platform: Option<PlatformKind>,
    pub device: Option<DeviceKind>,
    /// Latest observed numeric versions per client after platform/device filtering.
    /// Missing components never cause older versions to be substituted.
    pub latest_versions: Option<usize>,
    pub capabilities: ProfileCapabilities,
}

#[derive(Debug)]
pub struct ProfileCandidate<'a> {
    pub profile: &'a UserAgentProfile,
    pub weight: ObservationWeight,
}

type VersionGroup = (Box<str>, Option<PlatformKind>, Option<DeviceKind>);
#[derive(Debug, Default)]
pub(super) struct ProfileVersionIndex {
    groups: HashMap<VersionGroup, BTreeMap<ProfileVersion, Vec<usize>>>,
}

impl ProfileVersionIndex {
    pub(super) fn insert(&mut self, key: &ProfileKey, index: usize) {
        let Some(version) = key.version.as_deref().and_then(ProfileVersion::parse) else {
            return;
        };
        let group = (
            key.client.clone(),
            key.platform,
            key.device
                .or_else(|| key.platform.map(|platform| platform.device())),
        );
        self.groups
            .entry(group)
            .or_default()
            .entry(version)
            .or_default()
            .push(index);
    }

    pub(super) fn latest(
        &self,
        filter: ProfileCandidateFilter<'_>,
        maximum: usize,
    ) -> BTreeSet<usize> {
        let mut clients = BTreeMap::<&str, BTreeMap<&ProfileVersion, Vec<usize>>>::new();
        for ((client, platform, device), versions) in &self.groups {
            if filter
                .client
                .is_some_and(|expected| expected != client.as_ref())
                || filter
                    .platform
                    .is_some_and(|expected| Some(expected) != *platform)
                || filter
                    .device
                    .is_some_and(|expected| Some(expected) != *device)
            {
                continue;
            }
            let selected = clients.entry(client).or_default();
            for (version, indices) in versions {
                selected.entry(version).or_default().extend(indices);
            }
        }
        clients
            .into_values()
            .flat_map(|versions| {
                versions
                    .into_iter()
                    .rev()
                    .take(maximum)
                    .flat_map(|(_version, indices)| indices)
            })
            .collect()
    }
}

impl UserAgentProfile {
    pub fn capabilities(&self) -> ProfileCapabilities {
        let captured = self.captured.as_ref().map(|profile| &profile.components);
        ProfileCapabilities {
            h1: self.http.as_ref().is_some_and(|http| http.h1.is_some())
                || captured.is_some_and(|components| components.h1.is_some()),
            h2: self.http.as_ref().is_some_and(|http| http.h2.is_some())
                || captured.is_some_and(|components| components.h2.is_some()),
            h3: captured.is_some_and(|components| components.h3.is_some()),
            tls_tcp: {
                #[cfg(feature = "tls")]
                {
                    self.tls.is_some()
                        || captured.is_some_and(|components| components.tls_tcp.is_some())
                }

                #[cfg(not(feature = "tls"))]
                {
                    captured.is_some_and(|components| components.tls_tcp.is_some())
                }
            },
            tls_quic: captured.is_some_and(|components| components.tls_quic.is_some()),
            quic: captured.is_some_and(|components| components.quic.is_some()),
        }
    }

    /// Connection totals take precedence; request totals are used only when no
    /// connection tuples exist. Leaf buckets never multiply the observation count.
    pub fn observation_weight(&self) -> Result<ObservationWeight, ProfileDataError> {
        let Some(captured) = &self.captured else {
            return Ok(ObservationWeight::UnknownHistory {
                observed: 1,
                unassigned: 0,
            });
        };
        let connection = captured.scopes.iter().any(|scope| {
            scope.context.flow.is_none() && scope.observations.domain == CanonicalDomain::Joint
        });
        if !captured
            .scopes
            .iter()
            .any(|scope| scope.observations.domain == CanonicalDomain::Joint)
            && let Some(observed) = captured
                .scopes
                .iter()
                .filter(|scope| scope.observations.domain == CanonicalDomain::LegacyField)
                .map(|scope| scope.observations.counts.total)
                .max()
        {
            return Ok(ObservationWeight::UnknownHistory {
                observed,
                unassigned: 0,
            });
        }
        let mut total = 0_u64;
        let mut known = true;
        for scope in &captured.scopes {
            if scope.observations.domain != CanonicalDomain::Joint
                || scope.context.flow.is_none() != connection
            {
                continue;
            }
            total = total
                .checked_add(scope.observations.counts.total)
                .ok_or(ProfileDataError::CounterOverflow)?;
            known &= scope.observations.counts.losses.history_known;
        }
        if known {
            Ok(ObservationWeight::Exact(total))
        } else {
            Ok(ObservationWeight::UnknownHistory {
                observed: total,
                unassigned: 0,
            })
        }
    }
}

#[cfg(test)]
mod tests;
