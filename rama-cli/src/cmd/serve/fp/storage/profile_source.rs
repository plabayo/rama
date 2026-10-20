//! Read-only counted profiles shared by export and the terminal viewer.

use rama::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    ua::profile::{
        analysis::profile::{ProfileAnalysisLimits, analyze_profile_evidence},
        format::{
            archive::{ProfileArchiveEntry, ProfileArchiveLimits},
            canonical::{ProfileDataError, ValueId},
        },
    },
};

use super::{counted, postgres, startup};

pub(crate) struct CountedProfileSource {
    pool: postgres::Pool,
    authorized: bool,
    day: u32,
    horizon: u32,
    remaining: usize,
    after: Option<ValueId>,
    skipped: usize,
    truncated: usize,
    dropped_scopes: usize,
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
        Ok(Self {
            pool: postgres::try_new_pool(url).await?,
            authorized,
            day,
            horizon,
            remaining: maximum_profiles,
            after: None,
            skipped: 0,
            truncated: 0,
            dropped_scopes: 0,
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
    pub(crate) fn dropped_scopes(&self) -> usize {
        self.dropped_scopes
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
            let next = {
                let mut client = self.pool.get().await?;
                counted::next_profile(
                    &mut client,
                    self.authorized,
                    self.after,
                    self.day,
                    self.horizon,
                    ProfileAnalysisLimits::default(),
                    startup::store_limits(),
                )
                .await
            };
            let (evidence, sampler_seed, truncation) = match next {
                Ok(Some(entry)) => entry,
                Ok(None) => return Ok(None),
                Err(error) => {
                    if let Some(limit) = error.downcast_ref::<counted::ProfileReadLimit>() {
                        self.after = Some(limit.id);
                        self.remaining -= 1;
                        self.skipped += 1;
                        continue;
                    }
                    return Err(error);
                }
            };
            self.remaining -= 1;
            self.after = Some(evidence.profile.id);
            // Validate before handing an entry to a consuming archive writer.
            // Only resource limits are skippable; integrity and access errors remain fatal.
            let authorized = self.authorized;
            let day = self.day;
            let horizon = self.horizon;
            let analysis_limits = ProfileAnalysisLimits {
                maximum_work: ProfileAnalysisLimits::default()
                    .maximum_work
                    .min(self.remaining_work),
                ..ProfileAnalysisLimits::default()
            };
            let (evidence, analysis) = tokio::task::spawn_blocking(move || {
                let analysis = analyze_profile_evidence(
                    &evidence,
                    authorized,
                    sampler_seed,
                    day,
                    horizon,
                    analysis_limits,
                );
                (evidence, analysis)
            })
            .await?;
            match analysis {
                Ok(analysis) => {
                    self.remaining_work -= analysis.work_units;
                    if truncation.is_truncated() {
                        self.truncated += 1;
                        self.dropped_scopes += truncation.dropped_stored_scopes;
                    }
                    return Ok(Some(ProfileArchiveEntry {
                        evidence,
                        sampler_seed,
                    }));
                }
                Err(ProfileDataError::LimitExceeded(_)) => {
                    // A rejected analysis has no work report; reserve its full allowance.
                    self.remaining_work -= analysis_limits.maximum_work;
                    self.skipped += 1;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}
