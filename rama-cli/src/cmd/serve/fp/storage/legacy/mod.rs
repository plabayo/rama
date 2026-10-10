//! Bounded additive imports from the overwrite-schema fingerprint tables.

use std::{env, fmt::Write as _};

use rama::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    telemetry::tracing,
    tls::boring::core::{rand::rand_bytes, sha::sha256},
    ua::profile::{LegacyFieldCapture, UserAgentProfileInput},
    utils::octets::kib,
};
use tokio_postgres::Client;

use super::{
    counted::{self, LegacyRevision, StoreLimits},
    migrations,
    postgres::{self, Pool},
    startup,
};

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
                "legacy profile backfill complete"
            ),
            Err(_error) => tracing::warn!(
                authorized,
                "legacy profile backfill incomplete; completed rows remain checkpointed"
            ),
        }
    }
}

/// Each page is bounded before crossing the database/client boundary. A failed
/// row commits no fields; completed row hashes make restarting idempotent.
pub(super) async fn backfill(
    client: &mut Client,
    authorized: bool,
    current_day: u32,
    seed: [u8; 32],
    limits: StoreLimits,
) -> Result<BackfillReport, BoxError> {
    let table = if authorized {
        "ua-profiles"
    } else {
        "public-ua-profiles"
    };
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
    let mut payload = String::from("json_build_object('uastr',uastr");
    let mut size = String::from("octet_length(uastr)::bigint");
    for field in FIELDS {
        write!(payload, ",'{field}',{field}")?;
        write!(size, "+COALESCE(octet_length({field}::text)::bigint,0)")?;
    }
    payload.push_str(")::text");
    // Table and field names are fixed literals, never data supplied by a peer.
    let query = format!("SELECT CASE WHEN octet_length(uastr)::bigint <= $4 THEN uastr END,
        floor(extract(epoch FROM updated_at)/86400)::bigint,
        floor(extract(epoch FROM updated_at) * 1000000)::bigint,
        CASE WHEN octet_length(payload)::bigint <= $5 THEN payload END
        FROM (SELECT uastr,updated_at,CASE WHEN ({size}) <= $5 AND octet_length(uastr)::bigint <= $4 THEN {payload} END AS payload
         FROM public.\"{table}\" WHERE ($1::text IS NULL OR uastr COLLATE \"C\" > $1 COLLATE \"C\")
         AND updated_at >= to_timestamp($2::bigint * 86400)
         ORDER BY uastr COLLATE \"C\" LIMIT $3) bounded ORDER BY uastr COLLATE \"C\"");
    let mut after: Option<String> = None;
    let mut report = BackfillReport::default();
    loop {
        let remaining = limits.retained[0]
            .checked_sub(report.read)
            .ok_or_else(|| BoxError::from_static_str("legacy row scan limit exceeded"))?;
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
                ],
            )
            .await?;
        tx.commit().await?;
        if rows.is_empty() {
            return Ok(report);
        }
        if rows.len() > remaining {
            return Err(BoxError::from_static_str("legacy row scan limit exceeded"));
        }
        for source in rows {
            let key: Option<String> = source.try_get(0)?;
            let key =
                key.ok_or_else(|| BoxError::from_static_str("legacy source key exceeds limit"))?;
            let day = u32::try_from(source.try_get::<_, i64>(1)?)?;
            limits
                .ingestion
                .retention
                .validate_observation(current_day, day)?;
            let timestamp: i64 = source.try_get(2)?;
            let payload: Option<String> = source.try_get(3)?;
            let payload = payload
                .ok_or_else(|| BoxError::from_static_str("legacy source row exceeds limit"))?;
            let row: UserAgentProfileInput = serde_json::from_str(&payload)
                .map_err(|_error| BoxError::from_static_str("invalid legacy profile row"))?;
            if row.uastr.as_str() != key {
                return Err(BoxError::from_static_str("legacy source identity mismatch"));
            }
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
            report.read += 1;
            after = Some(key);
        }
    }
}

#[cfg(test)]
mod tests;
