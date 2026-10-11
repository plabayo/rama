//! Atomic, restart-safe conversion of one legacy row into independent field counts.

use super::*;
use rama::ua::profile::{LegacyFieldCapture, UserAgentProfileInput};
use std::time::Duration;
use tokio::time::{Instant, timeout_at};

pub(in super::super) struct LegacyRevision {
    pub source_table: &'static str,
    pub source_key: [u8; 32],
    pub row_digest: [u8; 32],
    pub observation_day: u32,
    pub nonce: [u8; 12],
}

impl LegacyRevision {
    pub(super) async fn was_imported(
        &self,
        transaction: &Transaction<'_>,
        authorized: bool,
    ) -> Result<bool, BoxError> {
        let row = transaction.query_opt(
            "SELECT run_id FROM fp_v2.legacy_imports WHERE authorized=$1 AND source_table=$2 AND source_key=$3 AND row_digest=$4",
            &[&authorized, &self.source_table, &&self.source_key[..], &&self.row_digest[..]],
        ).await?;
        if let Some(row) = row {
            let run: Option<Vec<u8>> = row.try_get(0)?;
            if run.as_ref().is_none_or(|run| run.len() != 16) {
                return Err(invalid("legacy checkpoint run"));
            }
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) async fn checkpoint(
        &self,
        transaction: &Transaction<'_>,
        authorized: bool,
        current_day: u32,
        run: CaptureRunId,
    ) -> Result<(), BoxError> {
        transaction.execute(
            "INSERT INTO fp_v2.legacy_imports (authorized,source_table,source_key,row_digest,imported_day,run_id) VALUES ($1,$2,$3,$4,$5,$6)",
            &[&authorized, &self.source_table, &&self.source_key[..], &&self.row_digest[..], &i64::from(current_day), &&run.0[..]],
        ).await?;
        Ok(())
    }
}

pub(in super::super) async fn ingest_legacy(
    client: &mut Client,
    current_day: u32,
    authorized: bool,
    row: &UserAgentProfileInput,
    revision: &LegacyRevision,
    seed: [u8; 32],
    limits: StoreLimits,
) -> Result<bool, IngestFailure> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let prepare = async {
        limits.ingestion.bucket.validate()?;
        limits
            .ingestion
            .retention
            .validate_observation(current_day, revision.observation_day)?;
        if limits.capture.bytes > limits.ingestion.bucket.input_bytes
            || limits.capture.value_bytes > limits.capture.bytes
        {
            return Err(invalid("capture and bucket input limits"));
        }
        if !matches!(
            (authorized, revision.source_table),
            (true, "ua-profiles") | (false, "public-ua-profiles")
        ) {
            return Err(invalid("legacy source authorization"));
        }
        let Some(prepared) = LegacyFieldCapture::prepare_row(row, authorized, limits.capture)?
        else {
            return Ok(None);
        };
        let run = CaptureRunId::new(revision.observation_day, revision.nonce);
        let attempt = IngestionAttempt {
            authorized,
            observation_day: revision.observation_day,
            observation: ObservationId {
                run: run.0,
                sequence: 1,
            },
        };
        prepare_batch_transaction(
            client,
            current_day,
            attempt,
            prepared,
            seed,
            limits,
            Some(revision),
        )
        .await
    };
    let Some(transaction) = timeout_at(deadline, prepare)
        .await
        .map_err(|error| IngestFailure::Rejected(error.into()))?
        .map_err(IngestFailure::Rejected)?
    else {
        return Ok(false);
    };
    timeout_at(deadline, transaction.commit())
        .await
        .map_err(|error| IngestFailure::Unconfirmed(error.into()))?
        .map_err(|error| IngestFailure::Unconfirmed(error.into()))?;
    Ok(true)
}
