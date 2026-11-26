//! Bounded, read-only profile snapshots for the common Rust analyzer.

use rama::{
    telemetry::tracing,
    ua::profile::{
        analysis::profile::{
            ProfileAnalysisLimits, normalize_profile_evidence, normalized_scope_id,
        },
        evidence::{
            ProfileEvidence, ProfileScopeEvidence,
            window::{DayBucketSnapshot, RetainedBucketsSnapshot},
        },
        model::identity::ProfileKey,
    },
};
use tokio_postgres::IsolationLevel;

use super::*;

/// Bucket loads in flight on the export transaction at once.
const PIPELINED_BUCKET_LOADS: usize = 64;

/// A bounded profile can be skipped without losing other profiles.
#[derive(Debug)]
pub(in super::super) struct ProfileReadLimit {
    pub reason: &'static str,
}

impl fmt::Display for ProfileReadLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "profile exceeds {}", self.reason)
    }
}

impl std::error::Error for ProfileReadLimit {}

/// Scopes left out of one exported profile; every flow keeps its best-ranked scope
/// per layer, then scopes seen in the most runs and days are kept.
#[derive(Debug, Clone, Copy, Default)]
pub(in super::super) struct ScopeTruncation {
    /// Stored scopes with retained days in the export window.
    pub stored_scopes: usize,
    /// Stored scopes not exported because their normalized scope did not fit.
    pub dropped_stored_scopes: usize,
    /// Normalized scopes those dropped stored scopes belong to.
    pub dropped_scopes: usize,
    /// Stored scopes not exported because the profile has captures of a newer revision.
    pub superseded_scopes: usize,
}

impl ScopeTruncation {
    pub(in super::super) fn is_truncated(&self) -> bool {
        self.dropped_stored_scopes > 0
    }
}

fn canonical(id: Vec<u8>, bytes: Option<Vec<u8>>) -> Result<CanonicalValue, BoxError> {
    Ok(CanonicalValue {
        id: identity(id)?,
        bytes: bytes
            .ok_or_else(|| bounded("export metadata bytes"))?
            .into(),
    })
}

/// SQL capture revision of bucket `b`: the structure-ID frame tells revision 0 from a u16 tail.
macro_rules! scope_revision {
    () => {
        "(CASE WHEN substring(b.scope_canonical FROM octet_length(b.scope_canonical)-41 FOR 8)
           ='\\x0000000000000020'::bytea
          THEN get_byte(b.scope_canonical,octet_length(b.scope_canonical)-2)*256
           +get_byte(b.scope_canonical,octet_length(b.scope_canonical)-1) ELSE 0 END)"
    };
}

/// Run `count` loads in pipelined chunks. Each chunk's bytes are charged before the next
/// chunk starts, so beyond the budget at most one chunk of loads holds retained bytes.
/// Each flow's best-ranked row per layer, then the rest, both in rank order, so a
/// new flow is never evicted by more popular shapes of known flows.
fn coverage_first<T, K: Ord>(
    rows: impl IntoIterator<Item = T>,
    mut coverage: impl FnMut(&T) -> Result<K, BoxError>,
) -> Result<Vec<T>, BoxError> {
    let mut covered = BTreeSet::new();
    let (mut ranked, mut rest) = (Vec::new(), Vec::new());
    for row in rows {
        if covered.insert(coverage(&row)?) {
            ranked.push(row);
        } else {
            rest.push(row);
        }
    }
    ranked.append(&mut rest);
    Ok(ranked)
}

async fn load_in_chunks<T, F, Fut>(
    count: usize,
    remaining: &mut usize,
    mut load: F,
) -> Result<Vec<T>, BoxError>
where
    F: FnMut(usize, usize) -> Fut,
    Fut: Future<Output = Result<(T, usize), BoxError>>,
{
    let mut loaded = Vec::with_capacity(count);
    for start in (0..count).step_by(PIPELINED_BUCKET_LOADS) {
        let end = count.min(start + PIPELINED_BUCKET_LOADS);
        let budget = *remaining;
        let chunk: Vec<_> = (start..end).map(|index| load(index, budget)).collect();
        for (value, bytes) in future::try_join_all(chunk).await? {
            *remaining = remaining
                .checked_sub(bytes)
                .ok_or_else(|| bounded("stored batch bytes"))?;
            loaded.push(value);
        }
    }
    Ok(loaded)
}

/// One bucket and the retained bytes it used out of `budget`.
async fn load_budgeted_bucket(
    transaction: &Transaction<'_>,
    authorized: bool,
    day: u32,
    input: &StoredScope<'_>,
    seed: [u8; 32],
    limits: StoreLimits,
    budget: usize,
) -> Result<(StoredObservationBucket, usize), BoxError> {
    let mut left = budget;
    let input = StoredScope {
        scope: input.scope,
        structure: input.structure,
        domain: input.domain,
    };
    let stored =
        load_retained_bucket(transaction, authorized, day, input, seed, limits, &mut left).await?;
    Ok((stored, budget - left))
}

/// One profile with buckets in the export window, in export order.
pub(in super::super) struct ListedProfile {
    /// Canonical profile identity.
    pub id: ValueId,
    /// The recorded User-Agent, or the client name when none was recorded.
    pub label: Box<str>,
}

/// At most `maximum` profiles with buckets in the export window, in export order.
pub(in super::super) async fn profile_ids(
    client: &Client,
    authorized: bool,
    current_day: u32,
    horizon: u32,
    analysis_limits: ProfileAnalysisLimits,
    maximum: usize,
) -> Result<Vec<ListedProfile>, BoxError> {
    let first = analysis_limits
        .window
        .retention
        .first_day(current_day, horizon)?;
    client
        .query(
            "SELECT p.id, CASE WHEN octet_length(p.canonical)::bigint <= $5 THEN p.canonical END
         FROM fp_v2.profiles p WHERE p.authorized=$1
         AND EXISTS (SELECT 1 FROM fp_v2.buckets b WHERE b.authorized=p.authorized
          AND b.profile_id=p.id AND b.day BETWEEN $2 AND $3)
         ORDER BY p.id LIMIT $4",
            &[
                &authorized,
                &i64::from(first),
                &i64::from(current_day),
                &integer(maximum)?,
                &integer(analysis_limits.metadata_bytes)?,
            ],
        )
        .await?
        .into_iter()
        .map(|row| {
            listed_profile(
                row.try_get(0)?,
                row.try_get(1)?,
                analysis_limits.metadata_bytes,
            )
        })
        .collect()
}

/// Label of a listed profile whose canonical identity exceeds the metadata bound.
const OVER_BOUND_LABEL: &str = "(profile identity over the metadata bound)";

/// A profile over the metadata bound stays listed so its load skips and reports it.
fn listed_profile(
    id: Vec<u8>,
    bytes: Option<Vec<u8>>,
    metadata_bytes: usize,
) -> Result<ListedProfile, BoxError> {
    if bytes.is_none() {
        return Ok(ListedProfile {
            id: identity(id)?,
            label: OVER_BOUND_LABEL.into(),
        });
    }
    let profile = canonical(id, bytes)?;
    let key = ProfileKey::from_canonical(&profile, metadata_bytes)?;
    Ok(ListedProfile {
        id: profile.id,
        label: key.user_agent.unwrap_or(key.client),
    })
}

/// One profile's evidence; `None` once it has no bucket left in the export window.
pub(in super::super) async fn load_profile(
    client: &mut Client,
    authorized: bool,
    id: ValueId,
    current_day: u32,
    horizon: u32,
    analysis_limits: ProfileAnalysisLimits,
    store_limits: StoreLimits,
) -> Result<Option<(ProfileEvidence, [u8; 32], ScopeTruncation)>, BoxError> {
    let first = analysis_limits
        .window
        .retention
        .first_day(current_day, horizon)?;
    let transaction = client
        .build_transaction()
        .read_only(true)
        .isolation_level(IsolationLevel::RepeatableRead)
        .start()
        .await?;
    let maximum = integer(analysis_limits.metadata_bytes)?;
    let row = transaction
        .query_opt(
            "SELECT p.id, CASE WHEN octet_length(p.canonical)::bigint <= $5 THEN p.canonical END
         FROM fp_v2.profiles p WHERE p.authorized=$1 AND p.id=$2
         AND EXISTS (SELECT 1 FROM fp_v2.buckets b WHERE b.authorized=p.authorized
          AND b.profile_id=p.id AND b.day BETWEEN $3 AND $4)",
            &[
                &authorized,
                &&id.0[..],
                &i64::from(first),
                &i64::from(current_day),
                &maximum,
            ],
        )
        .await?;
    let Some(row) = row else {
        transaction.commit().await?;
        return Ok(None);
    };
    let result: Result<_, BoxError> = async {
        let profile = canonical(row.try_get(0)?, row.try_get(1)?)?;
        // Independent lookups share one round trip.
        let (first_sql, current_sql) = (i64::from(first), i64::from(current_day));
        let (quota, newest) = future::try_join(
            transaction.query_one(
                "SELECT watermark,sampler_seed,buckets,runs,interned_values FROM fp_v2.quotas WHERE authorized=$1",
                &[&authorized],
            ),
            transaction.query_one(
                concat!(
                    "SELECT max(",
                    scope_revision!(),
                    ") FROM fp_v2.buckets b
                     WHERE b.authorized=$1 AND b.profile_id=$2 AND b.day BETWEEN $3 AND $4"
                ),
                &[&authorized, &&profile.id.0[..], &first_sql, &current_sql],
            ),
        )
        .await?;
        if u32::try_from(quota.try_get::<_, i64>(0)?)? > current_day {
            return Err(invalid("export clock predates store watermark"));
        }
        let seed = stored_sampler_seed(
            quota.try_get(1)?,
            quota.try_get(2)?,
            quota.try_get(3)?,
            quota.try_get(4)?,
        )?
        .ok_or_else(|| invalid("export sampler seed missing"))?;
        // Rank and limit only the newest revision so superseded captures never replay.
        let newest: i32 = newest
            .try_get::<_, Option<i32>>(0)?
            .ok_or_else(|| invalid("export profile without buckets"))?;
        let stored_limit = bounded_rows(analysis_limits.stored_scopes)?;
        let (rows, superseded) = future::try_join(transaction.query(
            concat!("SELECT b.scope,
              CASE WHEN octet_length(b.scope_canonical)::bigint <= $5 THEN b.scope_canonical END,
              b.domain,b.structure_id,
              CASE WHEN octet_length(s.canonical)::bigint <= $5 THEN s.canonical END,
              b.flow_id,CASE WHEN octet_length(f.canonical)::bigint <= $5 THEN f.canonical END,
              array_agg(b.day ORDER BY b.day)
             FROM fp_v2.buckets b JOIN fp_v2.structures s ON s.authorized=b.authorized AND s.id=b.structure_id
             LEFT JOIN fp_v2.flows f ON f.authorized=b.authorized AND f.profile_id=b.profile_id AND f.id=b.flow_id
             WHERE b.authorized=$1 AND b.profile_id=$2 AND b.day BETWEEN $3 AND $4 AND ",
             scope_revision!(),
             "=$7
             GROUP BY b.scope,b.scope_canonical,b.domain,b.structure_id,s.canonical,b.flow_id,f.canonical
             ORDER BY (SELECT count(DISTINCT x.run) FROM fp_v2.samples x WHERE x.authorized=$1
               AND x.scope=b.scope AND x.day BETWEEN $3 AND $4) DESC,
              count(*) DESC, sum(b.total) DESC, b.scope LIMIT $6"),
            &[&authorized,&&profile.id.0[..],&first_sql,&current_sql,&maximum,&stored_limit,&newest],
        ), transaction.query_one(
                concat!(
                    "SELECT count(DISTINCT b.scope) FROM fp_v2.buckets b
                     WHERE b.authorized=$1 AND b.profile_id=$2 AND b.day BETWEEN $3 AND $4 AND ",
                    scope_revision!(),
                    "<>$5"
                ),
                &[&authorized, &&profile.id.0[..], &first_sql, &current_sql, &newest],
        ))
        .await?;
        let superseded: i64 = superseded.try_get(0)?;
        let mut truncation = ScopeTruncation {
            stored_scopes: rows.len(),
            superseded_scopes: usize::try_from(superseded)?,
            ..ScopeTruncation::default()
        };
        if rows.len() > analysis_limits.stored_scopes {
            let stored: i64 = transaction
                .query_one(
                    concat!(
                        "SELECT count(DISTINCT b.scope) FROM fp_v2.buckets b
                         WHERE b.authorized=$1 AND b.profile_id=$2 AND b.day BETWEEN $3 AND $4 AND ",
                        scope_revision!(),
                        "=$5"
                    ),
                    &[&authorized, &&profile.id.0[..], &i64::from(first), &i64::from(current_day), &newest],
                )
                .await?
                .try_get(0)?;
            truncation.stored_scopes = usize::try_from(stored)?;
            truncation.dropped_stored_scopes =
                truncation.stored_scopes - analysis_limits.stored_scopes;
        }
        let mut remaining = analysis_limits
            .bytes
            .checked_sub(profile.bytes.len())
            .ok_or_else(|| bounded("export bytes"))?;
        let mut planned = Vec::new();
        let mut seen = BTreeSet::new();
        // Rows rank by capture runs, then days, then volume, so a burst of
        // high-volume shapes cannot evict shapes seen across runs and days.
        let ranked = coverage_first(
            rows.into_iter().take(analysis_limits.stored_scopes),
            |row| Ok((row.try_get::<_, Option<Vec<u8>>>(5)?, row.try_get::<_, i32>(2)?)),
        )?;
        let mut kept = BTreeSet::new();
        let mut dropped = BTreeSet::new();
        let mut work = analysis_limits.maximum_work;
        for row in ranked {
            let scope = canonical(row.try_get(0)?, row.try_get(1)?)?;
            let revision =
                ProfileObservationScope::from_canonical(&scope, analysis_limits.metadata_bytes)?
                    .revision;
            if i32::from(revision) != newest {
                return Err(invalid("export scope revision"));
            }
            if !seen.insert(scope.id) {
                return Err(invalid("export duplicate scope"));
            }
            let domain = CanonicalDomain::try_from(u16::try_from(row.try_get::<_, i32>(2)?)?)?;
            let structure = canonical(row.try_get(3)?, row.try_get(4)?)?;
            work = work
                .checked_sub(scope.bytes.len() + structure.bytes.len())
                .ok_or_else(|| bounded("export normalization work"))?;
            let normalized =
                normalized_scope_id(&scope, &structure, analysis_limits.metadata_bytes)?;
            if !kept.contains(&normalized) {
                if kept.len() >= analysis_limits.scopes {
                    truncation.dropped_stored_scopes += 1;
                    dropped.insert(normalized);
                    continue;
                }
                kept.insert(normalized);
            }
            let flow = match row.try_get::<_, Option<Vec<u8>>>(5)? {
                Some(id) => Some(canonical(id, row.try_get(6)?)?),
                None => None,
            };
            for size in [
                scope.bytes.len(),
                structure.bytes.len(),
                flow.as_ref().map_or(0, |flow| flow.bytes.len()),
            ] {
                remaining = remaining
                    .checked_sub(size)
                    .ok_or_else(|| bounded("export bytes"))?;
            }
            let days = row
                .try_get::<_, Vec<i64>>(7)?
                .into_iter()
                .map(u32::try_from)
                .collect::<Result<Vec<_>, _>>()?;
            if days.len() > analysis_limits.window.retention.days as usize {
                return Err(bounded("export days"));
            }
            planned.push((scope, structure, domain, flow, days));
        }
        truncation.dropped_scopes = dropped.len();
        // Each bucket load is several dependent queries; issuing a profile's loads
        // together pipelines them on this one transaction instead of paying a
        // round trip per query. Every load is checked against the budget left
        // before the batch, the batch total right after.
        let mut jobs = Vec::new();
        for (scope, structure, domain, _, days) in &planned {
            for &day in days {
                let input = StoredScope {
                    scope,
                    structure,
                    domain: *domain,
                };
                jobs.push((day, input));
            }
        }
        let transaction = &transaction;
        let jobs = &jobs;
        let mut loaded = load_in_chunks(jobs.len(), &mut remaining, |index, budget| {
            let (day, input) = &jobs[index];
            load_budgeted_bucket(
                transaction,
                authorized,
                *day,
                input,
                seed,
                store_limits,
                budget,
            )
        })
        .await?
        .into_iter();
        let mut scopes = Vec::with_capacity(planned.len());
        for (scope, structure, domain, flow, days) in planned {
            let mut buckets = Vec::with_capacity(days.len());
            for day in days {
                let stored = loaded
                    .next()
                    .ok_or_else(|| invalid("export bucket load missing"))?;
                buckets.push(DayBucketSnapshot {
                    day,
                    bucket: stored.bucket,
                });
            }
            let window = RetainedBucketsSnapshot {
                format_version: 1,
                domain,
                scope: scope.id,
                last_day: current_day,
                buckets: buckets.into(),
            };
            scopes.push(ProfileScopeEvidence {
                scope,
                flow,
                structure,
                window,
            });
        }
        let normalized = normalize_profile_evidence(
            &ProfileEvidence {
                format_version: 1,
                profile,
                scopes: scopes.into(),
            },
            authorized,
            seed,
            analysis_limits,
        )?;
        Ok((normalized.evidence, seed, truncation))
    }
    .await;
    let (evidence, seed, truncation) = result.map_err(|error| {
        if let Some(ProfileDataError::LimitExceeded(reason)) =
            error.downcast_ref::<ProfileDataError>()
        {
            BoxError::from(ProfileReadLimit { reason })
        } else {
            error
        }
    })?;
    transaction.commit().await?;
    if truncation.is_truncated() {
        tracing::warn!(
            profile = ?evidence.profile.id,
            stored_scopes = truncation.stored_scopes,
            dropped_stored_scopes = truncation.dropped_stored_scopes,
            dropped_scopes = truncation.dropped_scopes,
            "profile export dropped scopes over its bound; kept every flow, then those seen in the most runs and days"
        );
    }
    Ok(Some((evidence, seed, truncation)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn run(
        count: usize,
        remaining: &mut usize,
        started: &AtomicUsize,
    ) -> Result<Vec<usize>, BoxError> {
        load_in_chunks(count, remaining, |index, budget| {
            started.fetch_add(1, Ordering::Relaxed);
            async move {
                if budget == 0 {
                    return Err(bounded("stored bucket bytes"));
                }
                Ok((index, 1))
            }
        })
        .await
    }

    #[test]
    fn a_profile_over_the_metadata_bound_stays_listed_for_its_load_to_skip() {
        let listed = listed_profile(vec![7; 32], None, 16).unwrap();
        assert_eq!(listed.id, ValueId([7; 32]));
        assert_eq!(&*listed.label, OVER_BOUND_LABEL);

        let profile = ProfileKey::new("library").canonical(kib(16)).unwrap();
        let listed =
            listed_profile(profile.id.0.to_vec(), Some(profile.bytes.to_vec()), kib(16)).unwrap();
        assert_eq!(listed.id, profile.id);
        assert_eq!(&*listed.label, "library");
    }

    #[test]
    fn every_flow_layer_ranks_before_more_popular_shapes_of_known_ones() {
        // (flow, layer, rank) in popularity order.
        let rows = [
            ("old", 1, 0),
            ("old", 1, 1),
            ("old", 2, 2),
            ("old", 1, 3),
            ("new", 1, 4),
            ("new", 1, 5),
        ];
        let ranked = coverage_first(rows, |&(flow, layer, _)| Ok((flow, layer))).unwrap();
        assert_eq!(
            ranked.iter().map(|&(_, _, rank)| rank).collect::<Vec<_>>(),
            [0, 2, 4, 1, 3, 5]
        );
    }

    #[tokio::test]
    async fn chunks_are_charged_before_the_next_chunk_starts() {
        let started = AtomicUsize::new(0);
        let mut remaining = 3 * PIPELINED_BUCKET_LOADS;
        let loaded = run(2 * PIPELINED_BUCKET_LOADS + 1, &mut remaining, &started)
            .await
            .unwrap();
        assert_eq!(
            loaded,
            (0..2 * PIPELINED_BUCKET_LOADS + 1).collect::<Vec<_>>()
        );
        assert_eq!(remaining, PIPELINED_BUCKET_LOADS - 1);

        // A budget exhausted by the second chunk never starts the third.
        let started = AtomicUsize::new(0);
        let mut remaining = PIPELINED_BUCKET_LOADS + 1;
        run(3 * PIPELINED_BUCKET_LOADS, &mut remaining, &started)
            .await
            .unwrap_err();
        assert_eq!(started.load(Ordering::Relaxed), 2 * PIPELINED_BUCKET_LOADS);
    }
}
