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
    },
};
use tokio_postgres::IsolationLevel;

use super::*;

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
        let mut scopes = Vec::new();
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
            let days: Vec<i64> = row.try_get(7)?;
            if days.len() > analysis_limits.window.retention.days as usize {
                return Err(bounded("export days"));
            }
            let mut buckets = Vec::new();
            for day in days {
                let day = u32::try_from(day)?;
                let stored = load_retained_bucket(
                    &transaction,
                    authorized,
                    day,
                    StoredScope {
                        scope: &scope,
                        structure: &structure,
                        domain,
                    },
                    seed,
                    store_limits,
                    &mut remaining,
                )
                .await?;
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
