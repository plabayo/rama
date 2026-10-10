//! Bounded rejection checkpoints; raw legacy keys and field values stay private.

use std::error::Error;

use super::*;
use rama::ua::profile::ProfileDataError;

#[derive(Clone, Copy)]
pub(super) enum Rejection {
    Invalid,
    Oversize,
    Expired,
}

impl Rejection {
    pub(super) fn category(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::Oversize => "oversize",
            Self::Expired => "expired",
        }
    }
}

pub(super) struct RejectedRevision {
    pub source_key: Vec<u8>,
    pub row_digest: Vec<u8>,
}

impl RejectedRevision {
    pub(super) async fn checkpoint(
        &self,
        client: &mut Client,
        authorized: bool,
        current_day: u32,
        category: Rejection,
        limits: StoreLimits,
    ) -> Result<(), BoxError> {
        if self.source_key.len() != 32 || self.row_digest.len() != 32 {
            return Err(ProfileDataError::Invalid("legacy rejected identity").into());
        }
        let table = source_table(authorized);
        let tx = client.transaction().await?;
        tx.batch_execute("SET LOCAL statement_timeout = '5s'")
            .await?;
        let watermark: i64 = tx
            .query_one(
                "SELECT watermark FROM fp_v2.quotas WHERE authorized=$1 FOR UPDATE",
                &[&authorized],
            )
            .await?
            .try_get(0)?;
        if i64::from(current_day) < watermark {
            return Err(ProfileDataError::Invalid("storage time watermark").into());
        }
        let first = i64::from(
            limits
                .ingestion
                .retention
                .first_day(current_day, limits.ingestion.retention.days)?,
        );
        // Explicit CLI imports also reclaim expired checkpoints without relying
        // on a running fp service's maintenance worker.
        tx.execute(
            "DELETE FROM fp_v2.legacy_rejections r USING
               (SELECT authorized,source_table,source_key FROM fp_v2.legacy_rejections
                WHERE authorized=$1 AND rejected_day<$2 ORDER BY rejected_day,source_key LIMIT $3) old
             WHERE r.authorized=old.authorized AND r.source_table=old.source_table AND r.source_key=old.source_key",
            &[&authorized, &first, &i64::try_from(PAGE_ROWS)?],
        ).await?;
        let exists: bool = tx.query_one(
            "SELECT EXISTS (SELECT 1 FROM fp_v2.legacy_rejections WHERE authorized=$1 AND source_table=$2 AND source_key=$3)",
            &[&authorized, &table, &self.source_key],
        ).await?.try_get(0)?;
        let count: i64 = tx
            .query_one(
                "SELECT legacy_rejections FROM fp_v2.quotas WHERE authorized=$1",
                &[&authorized],
            )
            .await?
            .try_get(0)?;
        let maximum = i64::try_from(limits.retained[4])?;
        if count > maximum || (!exists && count >= maximum) {
            return Err(ProfileDataError::LimitExceeded("legacy rejection quota").into());
        }
        tx.execute(
            "INSERT INTO fp_v2.legacy_rejections (authorized,source_table,source_key,row_digest,rejected_day,category)
             VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (authorized,source_table,source_key)
             DO UPDATE SET row_digest=EXCLUDED.row_digest,rejected_day=EXCLUDED.rejected_day,category=EXCLUDED.category",
            &[&authorized, &table, &self.source_key, &self.row_digest, &i64::from(current_day), &category.category()],
        ).await?;
        tx.execute(
            "UPDATE fp_v2.quotas SET watermark=$2 WHERE authorized=$1",
            &[&authorized, &i64::from(current_day)],
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

pub(super) fn error_category(mut error: &(dyn Error + 'static)) -> &'static str {
    loop {
        if let Some(error) = error.downcast_ref::<ProfileDataError>() {
            return match error {
                ProfileDataError::LimitExceeded(_) => "quota",
                _ => "invalid",
            };
        }
        if error.is::<tokio_postgres::Error>() {
            return "database";
        }
        let Some(source) = error.source() else {
            return "system";
        };
        error = source;
    }
}
