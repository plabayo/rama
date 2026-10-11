//! Bounded additive imports from the overwrite-schema fingerprint tables.

use std::{env, fmt::Write as _};

use rama::{
    error::{BoxError, ErrorContext as _},
    telemetry::tracing,
    tls::boring::core::{rand::rand_bytes, sha::sha256},
    ua::profile::{LegacyFieldCapture, ProfileDataError, UserAgentProfileInput},
    utils::octets::kib,
};
use tokio_postgres::Client;

use super::{
    counted::{self, LegacyRevision, StoreLimits},
    migrations,
    postgres::{self, Pool},
    startup,
};

mod fields;
mod rejections;

use fields::decode_fields;
use rejections::{RejectedRevision, Rejection, error_category};

const FIELDS: &[&str] = &[
    "h1_settings",
    "h1_headers_navigate",
    "h1_headers_fetch",
    "h1_headers_xhr",
    "h1_headers_form",
    "h1_headers_ws",
    "h2_settings",
    "h2_headers_navigate",
    "h2_headers_fetch",
    "h2_headers_xhr",
    "h2_headers_form",
    "h2_headers_ws",
    "tls_client_hello",
    "tls_ws_client_config_overwrites",
    "js_web_apis",
    "source_info",
];
const PAGE_ROWS: usize = 32;
const ROW_BYTES: usize = kib(128);
const KEY_BYTES: usize = kib(8);

#[derive(Debug, Default)]
pub(super) struct BackfillReport {
    pub read: usize,
    pub imported: usize,
    pub already_imported_or_empty: usize,
    pub rejected_invalid: usize,
    pub rejected_oversize: usize,
    pub rejected_expired: usize,
    pub rejected_fields: usize,
}

/// Explicit CLI import writes only owned fp_v2 tables. The viewer/export reader
/// remains read-only unless this option is requested.
pub(super) async fn import_from_environment(authorized: bool) -> Result<BackfillReport, BoxError> {
    let url = env::var("RAMA_FP_DATABASE_URL").context("RAMA_FP_DATABASE_URL is required")?;
    let pool = postgres::try_new_pool(url).await?;
    let mut client = pool.get().await?;
    migrations::apply(&mut client).await?;
    let mut candidates = [[0; 32]; 2];
    for seed in &mut candidates {
        rand_bytes(seed)?;
    }
    let seeds = counted::sampler_seeds(&mut client, candidates).await?;
    backfill(
        &mut client,
        authorized,
        startup::current_day()?,
        seeds[usize::from(authorized)],
        startup::store_limits(),
    )
    .await
}

pub(super) async fn backfill_partitions(pool: Pool, seeds: [[u8; 32]; 2], limits: StoreLimits) {
    for authorized in [false, true] {
        let import = async {
            let mut client = pool.get().await?;
            backfill(
                &mut client,
                authorized,
                startup::current_day()?,
                seeds[usize::from(authorized)],
                limits,
            )
            .await
        }
        .await;
        match import {
            Ok(report) => tracing::debug!(
                authorized,
                rows = report.read,
                imported = report.imported,
                rejected_invalid = report.rejected_invalid,
                rejected_oversize = report.rejected_oversize,
                rejected_expired = report.rejected_expired,
                rejected_fields = report.rejected_fields,
                "legacy profile backfill complete"
            ),
            Err(error) => tracing::warn!(
                authorized,
                category = error_category(error.as_ref()),
                "legacy profile backfill incomplete; completed rows remain checkpointed"
            ),
        }
    }
}

fn source_table(authorized: bool) -> &'static str {
    if authorized {
        "ua-profiles"
    } else {
        "public-ua-profiles"
    }
}

fn source_query(authorized: bool) -> Result<String, BoxError> {
    let table = source_table(authorized);
    let mut payload = String::from("ARRAY[");
    let mut size = String::from("octet_length(uastr)::bigint");
    let mut discarded = String::from("0");
    // Rejected data cannot always be canonicalized. Hash each original column
    // separately in PostgreSQL; no unbounded raw value crosses into the client.
    // Successful import identities still use owned canonical field encodings.
    let mut revision = String::from(
        "convert_to('rama.fp.legacy-rejection.v1:' || extract(epoch FROM updated_at)::text,'UTF8')",
    );
    for (index, field) in FIELDS.iter().enumerate() {
        if index != 0 {
            payload.push(',');
        }
        write!(
            payload,
            "CASE WHEN octet_length({field}::text)::bigint <= $5 THEN {field}::text END"
        )?;
        write!(
            size,
            "+CASE WHEN octet_length({field}::text)::bigint <= $5 THEN octet_length({field}::text)::bigint ELSE 0 END"
        )?;
        write!(
            discarded,
            "+CASE WHEN octet_length({field}::text)::bigint > $5 THEN 1 ELSE 0 END"
        )?;
        write!(
            revision,
            " || CASE WHEN {field} IS NULL THEN decode('00','hex') ELSE decode('01','hex') || sha256(convert_to({field}::text,'UTF8')) END"
        )?;
    }
    payload.push(']');
    // Use the source key's native collation so its primary-key index serves
    // both the cursor and ordering. Names are fixed literals.
    // The exclusion also advances past oversized keys,
    // whose unbounded text is deliberately unavailable as a client-side cursor.
    let query = format!("SELECT CASE WHEN octet_length(uastr)::bigint <= $4 THEN uastr END,
        CASE WHEN isfinite(updated_at) THEN floor(extract(epoch FROM updated_at)/86400)::bigint END,
        CASE WHEN isfinite(updated_at) AND updated_at < to_timestamp(($8::bigint + 1) * 86400) THEN floor(extract(epoch FROM updated_at) * 1000000)::bigint END,
        payload,source_key,source_revision,discarded
        FROM (SELECT uastr,updated_at,source_key,source_revision,({discarded}) AS discarded,
          CASE WHEN ({size}) <= $5 AND octet_length(uastr)::bigint <= $4 THEN {payload} END AS payload
          FROM (SELECT *,sha256(convert_to(uastr,'UTF8')) AS source_key,sha256({revision}) AS source_revision
            FROM public.\"{table}\" WHERE ($1::text IS NULL OR uastr > $1)
            AND updated_at >= to_timestamp($2::bigint * 86400)) keyed
          WHERE NOT EXISTS (SELECT 1 FROM fp_v2.legacy_rejections r
            WHERE r.authorized=$6 AND r.source_table=$7 AND r.source_key=keyed.source_key
            AND r.row_digest=keyed.source_revision AND r.rejected_day >= $2)
          ORDER BY uastr LIMIT $3) bounded ORDER BY uastr");
    Ok(query)
}

/// Pages and rejection checkpoints are bounded. Valid fields survive malformed
/// neighbours; database and quota failures stop the partition without skipping it.
pub(super) async fn backfill(
    client: &mut Client,
    authorized: bool,
    current_day: u32,
    seed: [u8; 32],
    limits: StoreLimits,
) -> Result<BackfillReport, BoxError> {
    let table = source_table(authorized);
    let exists: bool = client
        .query_one(
            "SELECT to_regclass($1) IS NOT NULL",
            &[&format!("public.\"{table}\"")],
        )
        .await?
        .try_get(0)?;
    if !exists {
        return Ok(BackfillReport::default());
    }
    let first = limits
        .ingestion
        .retention
        .first_day(current_day, limits.ingestion.retention.days)?;
    let query = source_query(authorized)?;
    let mut after: Option<String> = None;
    let mut report = BackfillReport::default();
    loop {
        let remaining = limits.retained[0]
            .checked_sub(report.read)
            .ok_or_else(|| BoxError::from(ProfileDataError::LimitExceeded("legacy row scan")))?;
        let page_limit = i64::try_from(PAGE_ROWS.min(remaining.saturating_add(1)))?;
        let tx = client.build_transaction().read_only(true).start().await?;
        tx.batch_execute("SET LOCAL statement_timeout = '5s'; SET LOCAL TIME ZONE 'UTC'")
            .await?;
        let rows = tx
            .query(
                &query,
                &[
                    &after,
                    &i64::from(first),
                    &page_limit,
                    &i64::try_from(KEY_BYTES)?,
                    &i64::try_from(ROW_BYTES)?,
                    &authorized,
                    &table,
                    &i64::from(current_day),
                ],
            )
            .await?;
        tx.commit().await?;
        if rows.is_empty() {
            for (category, count) in [
                ("invalid", report.rejected_invalid),
                ("oversize", report.rejected_oversize),
                ("expired", report.rejected_expired),
            ] {
                if count != 0 {
                    tracing::warn!(
                        authorized,
                        category,
                        count,
                        "legacy profile revisions checkpointed with rejected fields"
                    );
                }
            }
            return Ok(report);
        }
        if rows.len() > remaining {
            return Err(BoxError::from(ProfileDataError::LimitExceeded(
                "legacy row scan",
            )));
        }
        for source in rows {
            report.read += 1;
            let key: Option<String> = source.try_get(0)?;
            let day: Option<i64> = source.try_get(1)?;
            let timestamp: Option<i64> = source.try_get(2)?;
            let payload: Option<Vec<Option<String>>> = source.try_get(3)?;
            let rejected = RejectedRevision {
                source_key: source.try_get(4)?,
                row_digest: source.try_get(5)?,
            };
            let day = day.and_then(|day| u32::try_from(day).ok());
            let category = match day {
                Some(day) if day < first => Some(Rejection::Expired),
                Some(day) if day <= current_day => None,
                _ => Some(Rejection::Invalid),
            };
            let category = category
                .or_else(|| (key.is_none() || payload.is_none()).then_some(Rejection::Oversize));
            if let Some(category) = category {
                reject(
                    &rejected,
                    client,
                    authorized,
                    current_day,
                    category,
                    limits,
                    &mut report,
                )
                .await?;
                if key.is_some() {
                    after = key;
                }
                continue;
            }
            let (Some(key), Some(payload), Some(day), Some(timestamp)) =
                (key, payload, day, timestamp)
            else {
                return Err(ProfileDataError::Invalid("legacy read disposition").into());
            };
            after = Some(key.clone());
            let mut decoded = decode_fields(&payload, &key, limits)?;
            decoded.oversize += usize::try_from(source.try_get::<_, i32>(6)?)?;
            let row = decoded.row;
            // Revision identity follows owned field encodings, not JSON formatting.
            let mut revision_bytes = b"rama.fp.legacy-revision.v1\0".to_vec();
            revision_bytes.extend_from_slice(&timestamp.to_be_bytes());
            for field in LegacyFieldCapture::capture_row(&row, limits.capture.value_bytes)? {
                revision_bytes
                    .extend_from_slice(&field.canonical(limits.capture.value_bytes)?.id.0);
            }
            let mut nonce = [0; 12];
            rand_bytes(&mut nonce)?;
            let revision = LegacyRevision {
                source_table: table,
                source_key: sha256(key.as_bytes()),
                row_digest: sha256(&revision_bytes),
                observation_day: day,
                nonce,
            };
            if counted::ingest_legacy(
                client,
                current_day,
                authorized,
                &row,
                &revision,
                seed,
                limits,
            )
            .await?
            {
                report.imported += 1;
            } else {
                report.already_imported_or_empty += 1;
            }
            report.rejected_fields += decoded.invalid + decoded.oversize;
            let category = if decoded.oversize != 0 {
                Some(Rejection::Oversize)
            } else if decoded.invalid != 0 {
                Some(Rejection::Invalid)
            } else {
                None
            };
            if let Some(category) = category {
                // A crash between the import and this checkpoint is safe: the
                // canonical successful revision already prevents double counts.
                reject(
                    &rejected,
                    client,
                    authorized,
                    current_day,
                    category,
                    limits,
                    &mut report,
                )
                .await?;
            }
        }
    }
}

async fn reject(
    revision: &RejectedRevision,
    client: &mut Client,
    authorized: bool,
    current_day: u32,
    category: Rejection,
    limits: StoreLimits,
    report: &mut BackfillReport,
) -> Result<(), BoxError> {
    revision
        .checkpoint(client, authorized, current_day, category, limits)
        .await?;
    match category {
        Rejection::Invalid => report.rejected_invalid += 1,
        Rejection::Oversize => report.rejected_oversize += 1,
        Rejection::Expired => report.rejected_expired += 1,
    }
    Ok(())
}

#[cfg(test)]
mod tests;
