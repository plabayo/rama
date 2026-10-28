//! Bounded, read-only profile snapshots for the common Rust analyzer.

use rama::{
    futures::future,
    telemetry::tracing,
    ua::profile::{
        analysis::profile::{
            ProfileAnalysisLimits, normalize_profile_evidence, normalized_scope_id,
        },
        evidence::{
            ProfileEvidence, ProfileScopeEvidence,
            window::{DayBucketSnapshot, RetainedBucketsSnapshot},
        },
    },
};
use tokio_postgres::IsolationLevel;

use super::*;

/// Bucket loads in flight on the export transaction at once.
const PIPELINED_BUCKET_LOADS: usize = 64;

/// A bounded profile can be skipped without losing the cursor or other profiles.
#[derive(Debug)]
pub(in super::super) struct ProfileReadLimit {
    pub id: ValueId,
    pub reason: &'static str,
}

impl fmt::Display for ProfileReadLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "profile exceeds {}", self.reason)
    }
}

impl std::error::Error for ProfileReadLimit {}

/// Scopes left out of one exported profile; scopes seen in the most runs and days are kept.
#[derive(Debug, Clone, Copy, Default)]
pub(in super::super) struct ScopeTruncation {
    /// Stored scopes with retained days in the export window.
    pub stored_scopes: usize,
    /// Stored scopes not exported because their normalized scope did not fit.
    pub dropped_stored_scopes: usize,
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

/// Run `count` loads in pipelined chunks. Each chunk's bytes are charged before the next
/// chunk starts, so beyond the budget at most one chunk of loads holds retained bytes.
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

pub(in super::super) async fn next_profile(
    client: &mut Client,
    authorized: bool,
    after: Option<ValueId>,
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
    let after = after.map(|id| id.0.to_vec());
    let maximum = integer(analysis_limits.metadata_bytes)?;
    let row = transaction
        .query_opt(
            "SELECT p.id, CASE WHEN octet_length(p.canonical)::bigint <= $5 THEN p.canonical END
         FROM fp_v2.profiles p WHERE p.authorized=$1 AND ($2::bytea IS NULL OR p.id>$2)
         AND EXISTS (SELECT 1 FROM fp_v2.buckets b WHERE b.authorized=p.authorized
          AND b.profile_id=p.id AND b.day BETWEEN $3 AND $4)
         ORDER BY p.id LIMIT 1",
            &[
                &authorized,
                &after,
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
    let profile_id = identity(row.try_get(0)?)?;
    let result: Result<_, BoxError> = async {
        let profile = canonical(row.try_get(0)?, row.try_get(1)?)?;
        let quota=transaction.query_one("SELECT watermark,sampler_seed,buckets,runs,interned_values FROM fp_v2.quotas WHERE authorized=$1",&[&authorized]).await?;
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
        let rows=transaction.query(
            "SELECT b.scope,
              CASE WHEN octet_length(b.scope_canonical)::bigint <= $5 THEN b.scope_canonical END,
              b.domain,b.structure_id,
              CASE WHEN octet_length(s.canonical)::bigint <= $5 THEN s.canonical END,
              b.flow_id,CASE WHEN octet_length(f.canonical)::bigint <= $5 THEN f.canonical END,
              array_agg(b.day ORDER BY b.day)
             FROM fp_v2.buckets b JOIN fp_v2.structures s ON s.authorized=b.authorized AND s.id=b.structure_id
             LEFT JOIN fp_v2.flows f ON f.authorized=b.authorized AND f.profile_id=b.profile_id AND f.id=b.flow_id
             WHERE b.authorized=$1 AND b.profile_id=$2 AND b.day BETWEEN $3 AND $4
             GROUP BY b.scope,b.scope_canonical,b.domain,b.structure_id,s.canonical,b.flow_id,f.canonical
             ORDER BY (SELECT count(DISTINCT x.run) FROM fp_v2.samples x WHERE x.authorized=$1
               AND x.scope=b.scope AND x.day BETWEEN $3 AND $4) DESC,
              count(*) DESC, sum(b.total) DESC, b.scope LIMIT $6",
            &[&authorized,&&profile.id.0[..],&i64::from(first),&i64::from(current_day),&maximum,&bounded_rows(analysis_limits.stored_scopes)?],
        ).await?;
        let mut truncation = ScopeTruncation {
            stored_scopes: rows.len(),
            dropped_stored_scopes: 0,
        };
        if rows.len() > analysis_limits.stored_scopes {
            let stored: i64 = transaction
                .query_one(
                    "SELECT count(DISTINCT scope) FROM fp_v2.buckets
                     WHERE authorized=$1 AND profile_id=$2 AND day BETWEEN $3 AND $4",
                    &[&authorized, &&profile.id.0[..], &i64::from(first), &i64::from(current_day)],
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
        let mut kept = BTreeSet::new();
        let mut work = analysis_limits.maximum_work;
        for row in rows.into_iter().take(analysis_limits.stored_scopes) {
            let scope = canonical(row.try_get(0)?, row.try_get(1)?)?;
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
            BoxError::from(ProfileReadLimit {
                id: profile_id,
                reason,
            })
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
            "profile export dropped scopes over its bound; kept those seen in the most runs and days"
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
