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

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::super::{counted::ingest, export::export_counted_profiles, migrations};
    use super::*;
    use crate::cmd::ua::ExportProfilesCommand;
    use rama::{
        http::{HeaderMap, HeaderName, HeaderValue, Method, Version},
        ua::profile::{
            capture::{
                completeness::ProfileCaptureCompleteness,
                headers::HeaderCapturePolicy,
                joint::{CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture},
                observation::ProfileCapture,
            },
            evidence::{
                ingestion::ObservationId,
                transaction::{CaptureRunId, IngestionAttempt},
            },
            format::archive::load_profile_archive_snapshot,
            model::identity::{ConnectionContext, FlowKey, ProfileKey},
        },
        utils::{fs::TempDir, octets::kib},
    };
    use std::{env, fs};
    use tokio_postgres::{Client, Config};

    async fn setup() -> (Client, postgres::Pool, u32) {
        let (_config, mut client) = migrations::tests::isolated_database().await.unwrap();
        let harness = env::var("RAMA_FP_TEST_PG").unwrap();
        assert!(env::var("RAMA_FP_DATABASE_URL").unwrap() == env::var("RAMA_FP_TEST_PG").unwrap());
        let command = env::var("RAMA_FP_DATABASE_URL")
            .unwrap()
            .parse::<Config>()
            .unwrap();
        assert!(command.get_hosts() == harness.parse::<Config>().unwrap().get_hosts());
        assert_eq!(command.get_dbname(), Some("rama_fp_m3_test"));
        client
            .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
            .await
            .unwrap();
        migrations::apply(&mut client).await.unwrap();
        let pool = postgres::try_new_pool(harness).await.unwrap();
        (client, pool, startup::current_day().unwrap())
    }

    fn source(pool: postgres::Pool, day: u32, maximum: usize) -> CountedProfileSource {
        CountedProfileSource {
            pool,
            authorized: false,
            day,
            horizon: 14,
            remaining: maximum,
            after: None,
            skipped: 0,
            truncated: 0,
            dropped_scopes: 0,
            limited: false,
            remaining_work: ProfileArchiveLimits::default().maximum_work,
        }
    }

    async fn observe(client: &mut Client, day: u32, sequence: u64, name: &str, header: &str) {
        observe_in_run(client, day, [7; 12], day, sequence, name, header).await;
    }

    async fn observe_in_run(
        client: &mut Client,
        current_day: u32,
        run: [u8; 12],
        day: u32,
        sequence: u64,
        name: &str,
        header: &str,
    ) {
        let policy = HeaderCapturePolicy::default();
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_bytes(header.as_bytes()).unwrap(),
            HeaderValue::from_static("value"),
        );
        let capture = ProfileCapture {
            profile: ProfileKey::new(name),
            flow: Some(FlowKey::Http {
                version: Version::HTTP_3,
                method: Method::GET,
                initiator: None,
                fetch: None,
                connection: ConnectionContext::default(),
            }),
            connection: ConnectionContext::default(),
            joint: JointCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                level: CaptureLevel::Request,
                slots: vec![CapturedSlot {
                    kind: CapturedSlotKind::Headers,
                    value: policy
                        .capture(
                            ProfileCaptureCompleteness::Complete,
                            Version::HTTP_3,
                            &headers,
                            None,
                        )
                        .unwrap()
                        .canonical(&policy)
                        .unwrap(),
                }]
                .into(),
            },
        };
        ingest(
            client,
            current_day,
            IngestionAttempt {
                authorized: false,
                observation_day: day,
                observation: ObservationId {
                    run: CaptureRunId::new(day, run).0,
                    sequence,
                },
            },
            &capture,
            [3; 32],
            startup::store_limits(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires the private PostgreSQL integration harness"]
    async fn over_limit_profile_keeps_its_most_observed_scopes() {
        let (mut client, pool, day) = setup().await;
        for index in 0..129u64 {
            observe(
                &mut client,
                day,
                index + 1,
                "many-scopes",
                &format!("x-field-{index}"),
            )
            .await;
        }
        for sequence in 200..203 {
            observe(&mut client, day, sequence, "many-scopes", "x-field-128").await;
        }
        observe(&mut client, day, 130, "ordinary", "accept").await;
        let mut reader = source(pool, day, 4096);
        let mut clients = Vec::new();
        while let Some(entry) = reader.next().await.unwrap() {
            let client = ProfileKey::from_canonical(&entry.evidence.profile, kib(16))
                .unwrap()
                .client;
            if client.as_ref() == "many-scopes" {
                assert_eq!(entry.evidence.scopes.len(), 256);
                // The scopes seen four times rank first, so the bound keeps them.
                let totals = entry
                    .evidence
                    .scopes
                    .iter()
                    .filter(|scope| {
                        scope
                            .window
                            .buckets
                            .iter()
                            .map(|day| day.bucket.counts.total)
                            .sum::<u64>()
                            == 4
                    })
                    .count();
                assert_eq!(totals, 2);
            }
            clients.push(client);
        }
        clients.sort();
        assert_eq!(
            clients.iter().map(AsRef::as_ref).collect::<Vec<&str>>(),
            ["many-scopes", "ordinary"]
        );
        assert_eq!(reader.skipped(), 0);
        assert_eq!(reader.truncated(), 1);
        assert_eq!(reader.dropped_scopes(), 2);
        assert!(!reader.limited());
        let directory = TempDir::new().unwrap();
        let output = directory.path().join("profiles.json");
        let limits = ProfileArchiveLimits::default();
        export_counted_profiles(ExportProfilesCommand {
            output: output.clone(),
            days: 14,
            authorized: false,
            import_legacy: false,
            replace: false,
            embed: false,
            max_profiles: limits.profiles,
            max_output_bytes: limits.bytes,
        })
        .await
        .unwrap();
        let archive =
            load_profile_archive_snapshot(&fs::read(output).unwrap(), false, limits).unwrap();
        assert_eq!(archive.len(), 2);
    }

    #[tokio::test]
    #[ignore = "requires the private PostgreSQL integration harness"]
    async fn high_volume_burst_does_not_evict_shapes_seen_across_runs() {
        let (mut client, pool, day) = setup().await;
        for (offset, run) in [(2, [1; 12]), (1, [2; 12])] {
            observe_in_run(
                &mut client,
                day - offset,
                run,
                day - offset,
                1,
                "public",
                "accept",
            )
            .await;
        }
        observe_in_run(&mut client, day, [3; 12], day, 1, "public", "accept").await;
        let mut sequence = 1;
        for index in 0..128 {
            for _ in 0..5 {
                sequence += 1;
                observe_in_run(
                    &mut client,
                    day,
                    [3; 12],
                    day,
                    sequence,
                    "public",
                    &format!("x-burst-{index}"),
                )
                .await;
            }
        }
        let mut reader = source(pool, day, 4096);
        let entry = reader.next().await.unwrap().unwrap();
        assert_eq!(entry.evidence.scopes.len(), 256);
        let genuine = entry
            .evidence
            .scopes
            .iter()
            .filter(|scope| scope.window.buckets.len() == 3)
            .count();
        assert_eq!(genuine, 2);
        assert_eq!(reader.truncated(), 1);
        assert_eq!(reader.dropped_scopes(), 2);
    }

    #[tokio::test]
    #[ignore = "requires the private PostgreSQL integration harness"]
    async fn profile_scan_limit_returns_available_rows_with_a_notice() {
        let (mut client, pool, day) = setup().await;
        observe(&mut client, day, 1, "first", "accept").await;
        observe(&mut client, day, 2, "second", "accept").await;
        let mut reader = source(pool, day, 1);
        assert!(reader.next().await.unwrap().is_some());
        assert!(reader.next().await.unwrap().is_none());
        assert!(reader.limited());
        assert_eq!(reader.skipped(), 0);
    }

    #[tokio::test]
    #[ignore = "requires the private PostgreSQL integration harness"]
    async fn corrupt_profile_is_an_error_instead_of_a_resource_skip() {
        let (mut client, pool, day) = setup().await;
        observe(&mut client, day, 1, "invalid", "accept").await;
        client
            .execute(
                "UPDATE fp_v2.profiles SET canonical=decode('00','hex')",
                &[],
            )
            .await
            .unwrap();
        let mut reader = source(pool, day, 4096);
        reader.next().await.unwrap_err();
        assert_eq!(reader.skipped(), 0);
    }
}
