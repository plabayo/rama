//! Read-only counted profiles shared by export and the terminal viewer.

use std::vec;

use rama::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    futures::stream::{self, BoxStream, StreamExt as _},
    ua::profile::{
        analysis::profile::{ProfileAnalysisLimits, analyze_profile_evidence},
        evidence::ProfileEvidence,
        format::{
            archive::{ProfileArchiveEntry, ProfileArchiveLimits},
            canonical::{ProfileDataError, ValueId},
        },
    },
};

use super::{counted, postgres, startup};

/// Profiles loaded and analyzed at once, each on its own pool connection.
const CONCURRENT_PROFILE_LOADS: usize = 8;

/// How many archive work bounds an embedded set may use.
const EMBEDDED_ARCHIVE_WORK_BOUNDS: usize = 8;

/// One profile's evidence and the work its analysis took under the default limits.
struct LoadedProfile {
    evidence: ProfileEvidence,
    sampler_seed: [u8; 32],
    truncation: counted::ScopeTruncation,
    work_units: Result<usize, ProfileDataError>,
}

async fn load_profile(
    pool: postgres::Pool,
    authorized: bool,
    id: ValueId,
    day: u32,
    horizon: u32,
) -> Result<Option<LoadedProfile>, BoxError> {
    let loaded = {
        let mut client = pool.get().await?;
        counted::load_profile(
            &mut client,
            authorized,
            id,
            day,
            horizon,
            ProfileAnalysisLimits::default(),
            startup::store_limits(),
        )
        .await?
    };
    let Some((evidence, sampler_seed, truncation)) = loaded else {
        return Ok(None);
    };
    // Validate before handing an entry to a consuming archive writer.
    let (evidence, work_units) = tokio::task::spawn_blocking(move || {
        let analysis = analyze_profile_evidence(
            &evidence,
            authorized,
            sampler_seed,
            day,
            horizon,
            ProfileAnalysisLimits::default(),
        );
        (evidence, analysis.map(|analysis| analysis.work_units))
    })
    .await?;
    Ok(Some(LoadedProfile {
        evidence,
        sampler_seed,
        truncation,
        work_units,
    }))
}

/// Analysis work a source hands out across all profiles it reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadBudget {
    /// The cumulative bound an archive loader applies, so a written archive loads.
    Archive,
    /// A cumulative bound for the analyses an embedded set retains in memory.
    Embedded,
    /// Only the per-profile bounds; the consumer bounds what it keeps.
    PerProfile,
}

impl ReadBudget {
    /// Cumulative analysis work units this budget hands out, if it bounds them.
    pub(crate) fn maximum_work(self) -> Option<usize> {
        let archive = ProfileArchiveLimits::default().maximum_work;
        match self {
            Self::Archive => Some(archive),
            // Saturates where `usize` cannot hold the product.
            Self::Embedded => Some(archive.saturating_mul(EMBEDDED_ARCHIVE_WORK_BOUNDS)),
            Self::PerProfile => None,
        }
    }
}

/// What became of the profiles with buckets in the read window.
#[derive(Debug, Default)]
pub(crate) struct ReadTally {
    /// Profiles listed for reading, at most the profile count bound.
    pub(crate) listed: usize,
    /// The window holds more profiles than the profile count bound lists.
    pub(crate) over_count: bool,
    /// Profiles handed to the consumer.
    pub(crate) read: usize,
    /// Profiles left unread once the cumulative work bound was reached.
    pub(crate) over_work_bound: Vec<Box<str>>,
    /// Profiles skipped over a per-profile bound, with the bound they exceeded.
    pub(crate) over_profile_bound: Vec<(&'static str, Box<str>)>,
    /// Profiles whose buckets left the window before they were read.
    pub(crate) left_window: Vec<Box<str>>,
    /// Profiles read without the scopes over their bound.
    pub(crate) truncated: usize,
    /// Stored scopes left out of truncated profiles.
    pub(crate) dropped_stored_scopes: usize,
    /// Normalized scopes left out of truncated profiles.
    pub(crate) dropped_scopes: usize,
    /// Stored scopes left out for a newer capture revision of their profile.
    pub(crate) superseded_scopes: usize,
    /// Profiles read with scopes left out for a newer capture revision.
    pub(crate) superseded_profiles: usize,
}

/// Outcome of charging one analyzed profile against the read budget.
#[derive(Debug, PartialEq, Eq)]
enum Admission {
    Accepted,
    OverProfileBound(&'static str),
    OverWorkBound,
}

/// Cumulative analysis work left; `None` leaves only the per-profile bound.
#[derive(Debug)]
struct WorkBudget {
    remaining: Option<usize>,
}

impl WorkBudget {
    fn new(budget: ReadBudget) -> Self {
        Self {
            remaining: budget.maximum_work(),
        }
    }

    fn exhausted(&self) -> bool {
        self.remaining == Some(0)
    }

    fn admit(
        &mut self,
        work_units: Result<usize, ProfileDataError>,
    ) -> Result<Admission, ProfileDataError> {
        let per_profile = ProfileAnalysisLimits::default().maximum_work;
        let allowance = self
            .remaining
            .map_or(per_profile, |remaining| remaining.min(per_profile));
        let admission = match work_units {
            Ok(work_units) if work_units <= allowance => {
                if let Some(remaining) = &mut self.remaining {
                    *remaining -= work_units;
                }
                return Ok(Admission::Accepted);
            }
            Ok(work_units) if work_units <= per_profile => Admission::OverWorkBound,
            Ok(_) => Admission::OverProfileBound("profile analysis work"),
            Err(ProfileDataError::LimitExceeded(reason)) => Admission::OverProfileBound(reason),
            Err(error) => return Err(error),
        };
        // A rejected analysis reserves its full allowance.
        if let Some(remaining) = &mut self.remaining {
            *remaining -= allowance;
        }
        Ok(admission)
    }
}

/// One profile read from the source.
pub(crate) struct SourcedProfile {
    /// The recorded User-Agent, or the client name when none was recorded.
    pub(crate) label: Box<str>,
    /// The profile's evidence, ready for analysis or an archive.
    pub(crate) entry: ProfileArchiveEntry,
}

pub(crate) struct CountedProfileSource {
    /// Loads run ahead of the consumer and arrive in listing order.
    profiles: BoxStream<'static, Result<Option<LoadedProfile>, BoxError>>,
    /// Labels of listed profiles not yet taken from `profiles`, in listing order.
    pending: vec::IntoIter<Box<str>>,
    day: u32,
    budget: WorkBudget,
    tally: ReadTally,
}

impl CountedProfileSource {
    pub(crate) async fn open(
        authorized: bool,
        horizon: u32,
        maximum_profiles: usize,
        budget: ReadBudget,
    ) -> Result<Self, BoxError> {
        if maximum_profiles == 0 {
            return Err(BoxError::from_static_str(
                "profile count limit must be positive",
            ));
        }
        let day = startup::current_day()?;
        ProfileAnalysisLimits::default()
            .window
            .retention
            .first_day(day, horizon)?;
        let url =
            std::env::var("RAMA_FP_DATABASE_URL").context("RAMA_FP_DATABASE_URL is required")?;
        let pool = postgres::try_new_pool(url).await?;
        // One extra row tells a window at the count bound from one over it.
        let mut listed = {
            let client = pool.get().await?;
            counted::profile_ids(
                &client,
                authorized,
                day,
                horizon,
                ProfileAnalysisLimits::default(),
                maximum_profiles.saturating_add(1),
            )
            .await?
        };
        let over_count = listed.len() > maximum_profiles;
        listed.truncate(maximum_profiles);
        let (ids, labels): (Vec<_>, Vec<_>) = listed
            .into_iter()
            .map(|profile| (profile.id, profile.label))
            .unzip();
        let profiles = stream::iter(ids)
            .map(move |id| load_profile(pool.clone(), authorized, id, day, horizon))
            .buffered(CONCURRENT_PROFILE_LOADS)
            .boxed();
        Ok(Self::new(profiles, labels, over_count, day, budget))
    }

    fn new(
        profiles: BoxStream<'static, Result<Option<LoadedProfile>, BoxError>>,
        labels: Vec<Box<str>>,
        over_count: bool,
        day: u32,
        budget: ReadBudget,
    ) -> Self {
        Self {
            profiles,
            tally: ReadTally {
                listed: labels.len(),
                over_count,
                ..ReadTally::default()
            },
            pending: labels.into_iter(),
            day,
            budget: WorkBudget::new(budget),
        }
    }

    pub(crate) fn day(&self) -> u32 {
        self.day
    }

    /// What became of the listed profiles so far; complete once `next` returns `None`.
    pub(crate) fn tally(&self) -> &ReadTally {
        &self.tally
    }

    pub(crate) async fn next(&mut self) -> Result<Option<SourcedProfile>, BoxError> {
        loop {
            if self.budget.exhausted() {
                self.tally.over_work_bound.extend(self.pending.by_ref());
                return Ok(None);
            }
            let Some(loaded) = self.profiles.next().await else {
                return Ok(None);
            };
            let label = self
                .pending
                .next()
                .ok_or_else(|| BoxError::from_static_str("profile source listing exhausted"))?;
            let loaded = match loaded {
                Ok(Some(loaded)) => loaded,
                Ok(None) => {
                    self.tally.left_window.push(label);
                    continue;
                }
                Err(error) => {
                    // Only resource limits are skippable; integrity and access errors remain fatal.
                    if let Some(limit) = error.downcast_ref::<counted::ProfileReadLimit>() {
                        self.tally.over_profile_bound.push((limit.reason, label));
                        continue;
                    }
                    return Err(error);
                }
            };
            match self.budget.admit(loaded.work_units)? {
                Admission::Accepted => {
                    let truncation = loaded.truncation;
                    let tally = &mut self.tally;
                    tally.read += 1;
                    if truncation.superseded_scopes > 0 {
                        tally.superseded_profiles += 1;
                        tally.superseded_scopes += truncation.superseded_scopes;
                    }
                    if truncation.is_truncated() {
                        tally.truncated += 1;
                        tally.dropped_stored_scopes += truncation.dropped_stored_scopes;
                        tally.dropped_scopes += truncation.dropped_scopes;
                    }
                    return Ok(Some(SourcedProfile {
                        label,
                        entry: ProfileArchiveEntry {
                            evidence: loaded.evidence,
                            sampler_seed: loaded.sampler_seed,
                        },
                    }));
                }
                Admission::OverProfileBound(reason) => {
                    self.tally.over_profile_bound.push((reason, label));
                }
                Admission::OverWorkBound => self.tally.over_work_bound.push(label),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::{ua::profile::model::identity::ProfileKey, utils::octets::kib};
    use std::ops::Range;

    type Load = Result<Option<LoadedProfile>, BoxError>;

    fn loaded(work_units: Result<usize, ProfileDataError>) -> Load {
        Ok(Some(LoadedProfile {
            evidence: ProfileEvidence {
                format_version: 1,
                profile: ProfileKey::new("library").canonical(kib(16)).unwrap(),
                scopes: Box::default(),
            },
            sampler_seed: [0; 32],
            truncation: counted::ScopeTruncation::default(),
            work_units,
        }))
    }

    fn source(loads: Vec<Load>, budget: ReadBudget) -> CountedProfileSource {
        let labels = (0..loads.len())
            .map(|index| index.to_string().into())
            .collect();
        CountedProfileSource::new(stream::iter(loads).boxed(), labels, false, 100, budget)
    }

    async fn drain(source: &mut CountedProfileSource) -> Result<Vec<Box<str>>, BoxError> {
        let mut read = Vec::new();
        while let Some(profile) = source.next().await? {
            read.push(profile.label);
        }
        Ok(read)
    }

    fn labels(range: Range<usize>) -> Vec<Box<str>> {
        range.map(|index| index.to_string().into()).collect()
    }

    #[tokio::test]
    async fn embedded_budget_reads_past_the_archive_work_bound_up_to_its_own() {
        let per_profile = ProfileAnalysisLimits::default().maximum_work;
        let archive_read = ReadBudget::Archive.maximum_work().unwrap() / per_profile;
        let embedded_read = ReadBudget::Embedded.maximum_work().unwrap() / per_profile;
        assert!(embedded_read > archive_read);
        let count = embedded_read + 2;
        let loads = || (0..count).map(|_| loaded(Ok(per_profile))).collect();

        let mut embedded = source(loads(), ReadBudget::Embedded);
        assert_eq!(
            drain(&mut embedded).await.unwrap(),
            labels(0..embedded_read)
        );
        let tally = embedded.tally();
        assert_eq!(tally.read, embedded_read);
        assert_eq!(tally.over_work_bound, labels(embedded_read..count));

        let mut archive = source(loads(), ReadBudget::Archive);
        assert_eq!(drain(&mut archive).await.unwrap(), labels(0..archive_read));
        let tally = archive.tally();
        assert_eq!(tally.read, archive_read);
        assert_eq!(tally.over_work_bound, labels(archive_read..count));
    }

    #[tokio::test]
    async fn every_listed_profile_is_read_or_left_out_for_one_reason() {
        let loads = vec![
            loaded(Ok(1)),
            Ok(None),
            Err(counted::ProfileReadLimit {
                reason: "export days",
            }
            .into()),
            loaded(Err(ProfileDataError::LimitExceeded("order elements"))),
            loaded(Ok(1)),
        ];
        let mut source = source(loads, ReadBudget::Archive);
        assert_eq!(drain(&mut source).await.unwrap(), ["0", "4"].map(Box::from));
        let tally = source.tally();
        assert_eq!(tally.listed, 5);
        assert_eq!(tally.left_window, ["1"].map(Box::from));
        assert_eq!(
            tally.over_profile_bound,
            [("export days", "2".into()), ("order elements", "3".into())]
        );
        assert!(tally.over_work_bound.is_empty());
        // A per-profile rejection reserves a full allowance of the archive bound.
        let reserved = ProfileAnalysisLimits::default().maximum_work + 2;
        assert_eq!(
            source.budget.remaining,
            ReadBudget::Archive
                .maximum_work()
                .map(|work| work - reserved)
        );
    }

    #[tokio::test]
    async fn invalid_evidence_stays_fatal() {
        let mut source = source(
            vec![loaded(Err(ProfileDataError::Invalid("scope")))],
            ReadBudget::PerProfile,
        );
        drain(&mut source).await.unwrap_err();
    }

    #[test]
    fn a_profile_within_its_own_bound_but_over_the_rest_of_the_archive_bound_ends_the_read() {
        let per_profile = ProfileAnalysisLimits::default().maximum_work;
        let mut budget = WorkBudget {
            remaining: Some(per_profile / 2),
        };
        assert_eq!(
            budget.admit(Ok(per_profile)).unwrap(),
            Admission::OverWorkBound
        );
        assert!(budget.exhausted());
        let mut budget = WorkBudget::new(ReadBudget::PerProfile);
        assert_eq!(
            budget.admit(Ok(per_profile + 1)).unwrap(),
            Admission::OverProfileBound("profile analysis work")
        );
        assert!(!budget.exhausted());
    }
}
