//! Read-only counted profiles shared by export and the terminal viewer.

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

pub(crate) struct CountedProfileSource {
    /// Loads run ahead of the consumer and arrive in profile id order.
    profiles: BoxStream<'static, Result<Option<LoadedProfile>, BoxError>>,
    day: u32,
    remaining: usize,
    skipped: usize,
    truncated: usize,
    dropped_stored_scopes: usize,
    dropped_scopes: usize,
    superseded_scopes: usize,
    limited: bool,
    remaining_work: usize,
}

impl CountedProfileSource {
    pub(crate) async fn open(
        authorized: bool,
        horizon: u32,
        maximum_profiles: usize,
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
        let ids = {
            let client = pool.get().await?;
            counted::profile_ids(
                &client,
                authorized,
                day,
                horizon,
                ProfileAnalysisLimits::default(),
                maximum_profiles,
            )
            .await?
        };
        let profiles = stream::iter(ids)
            .map(move |id| load_profile(pool.clone(), authorized, id, day, horizon))
            .buffered(CONCURRENT_PROFILE_LOADS)
            .boxed();
        Ok(Self {
            profiles,
            day,
            remaining: maximum_profiles,
            skipped: 0,
            truncated: 0,
            dropped_stored_scopes: 0,
            dropped_scopes: 0,
            superseded_scopes: 0,
            limited: false,
            remaining_work: ProfileArchiveLimits::default().maximum_work,
        })
    }

    pub(crate) fn day(&self) -> u32 {
        self.day
    }

    pub(crate) fn skipped(&self) -> usize {
        self.skipped
    }

    /// Profiles exported without the scopes over their bound.
    pub(crate) fn truncated(&self) -> usize {
        self.truncated
    }

    /// Stored scopes left out of truncated profiles.
    pub(crate) fn dropped_stored_scopes(&self) -> usize {
        self.dropped_stored_scopes
    }

    /// Normalized scopes left out of truncated profiles.
    pub(crate) fn dropped_scopes(&self) -> usize {
        self.dropped_scopes
    }

    /// Stored scopes left out for a newer capture revision of their profile.
    pub(crate) fn superseded_scopes(&self) -> usize {
        self.superseded_scopes
    }

    pub(crate) fn limited(&self) -> bool {
        self.limited
    }

    pub(crate) async fn next(&mut self) -> Result<Option<ProfileArchiveEntry>, BoxError> {
        loop {
            if self.remaining == 0 || self.remaining_work == 0 {
                self.limited = true;
                return Ok(None);
            }
            let Some(loaded) = self.profiles.next().await else {
                return Ok(None);
            };
            let loaded = match loaded {
                Ok(Some(loaded)) => loaded,
                Ok(None) => continue,
                Err(error) => {
                    // Only resource limits are skippable; integrity and access errors remain fatal.
                    if error.downcast_ref::<counted::ProfileReadLimit>().is_some() {
                        self.remaining -= 1;
                        self.skipped += 1;
                        continue;
                    }
                    return Err(error);
                }
            };
            self.remaining -= 1;
            let allowance = ProfileAnalysisLimits::default()
                .maximum_work
                .min(self.remaining_work);
            match loaded.work_units {
                Ok(work_units) if work_units <= allowance => {
                    self.remaining_work -= work_units;
                    let truncation = loaded.truncation;
                    self.superseded_scopes += truncation.superseded_scopes;
                    if truncation.is_truncated() {
                        self.truncated += 1;
                        self.dropped_stored_scopes += truncation.dropped_stored_scopes;
                        self.dropped_scopes += truncation.dropped_scopes;
                    }
                    return Ok(Some(ProfileArchiveEntry {
                        evidence: loaded.evidence,
                        sampler_seed: loaded.sampler_seed,
                    }));
                }
                Ok(_) | Err(ProfileDataError::LimitExceeded(_)) => {
                    // A rejected analysis reserves its full allowance.
                    self.remaining_work -= allowance;
                    self.skipped += 1;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}
