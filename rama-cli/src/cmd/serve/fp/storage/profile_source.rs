//! Read-only counted profiles shared by export and the terminal viewer.

use rama::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    ua::profile::{ProfileAnalysisLimits, ProfileArchiveEntry, ValueId},
};

use super::{counted, postgres, startup};

pub(crate) struct CountedProfileSource {
    pool: postgres::Pool,
    authorized: bool,
    day: u32,
    horizon: u32,
    remaining: usize,
    after: Option<ValueId>,
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
        })
    }

    pub(crate) fn day(&self) -> u32 {
        self.day
    }

    pub(crate) async fn next(&mut self) -> Result<Option<ProfileArchiveEntry>, BoxError> {
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
            .await?
        };
        let Some((evidence, sampler_seed)) = next else {
            return Ok(None);
        };
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or_else(|| BoxError::from_static_str("profile count limit exceeded"))?;
        self.after = Some(evidence.profile.id);
        Ok(Some(ProfileArchiveEntry {
            evidence,
            sampler_seed,
        }))
    }
}
