//! Sequential writer IDs, separated by authorization and bounded by retention.

use rama::{
    error::BoxError,
    ua::profile::{
        CaptureRunId, IngestionAttempt, ObservationId, ProfileDataError, RetentionWindow,
    },
};

#[derive(Debug)]
struct Run {
    id: CaptureRunId,
    next: u64,
}

#[derive(Debug)]
pub(super) struct SequenceIssuer {
    authorized: bool,
    run: Option<Run>,
    watermark: u32,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum WriteDisposition {
    Confirmed,
    Rejected,
    Unconfirmed,
}

impl SequenceIssuer {
    pub(super) const fn new(authorized: bool) -> Self {
        Self {
            authorized,
            run: None,
            watermark: 0,
        }
    }

    /// Called only by the sequential worker after queue admission. An outstanding
    /// permit borrows the issuer, so no later payload can take its sequence.
    pub(super) fn begin(
        &mut self,
        current_day: u32,
        observed_day: u32,
        retention: RetentionWindow,
        nonce: impl FnOnce() -> Result<[u8; 12], BoxError>,
    ) -> Result<PendingSequence<'_>, BoxError> {
        retention.validate_observation(current_day, observed_day)?;
        if current_day < self.watermark {
            return Err(ProfileDataError::Invalid("writer time watermark").into());
        }
        if self.run.as_ref().is_some_and(|run| {
            retention
                .validate_observation(current_day, run.id.created_day())
                .is_err()
        }) {
            self.run = None;
        }
        if let Some(run) = &self.run {
            if observed_day < run.id.created_day() {
                return Err(ProfileDataError::Invalid("observation predates writer run").into());
            }
        } else {
            self.run = Some(Run {
                id: CaptureRunId::new(observed_day, nonce()?),
                next: 1,
            });
        }
        self.watermark = current_day;
        let run = self
            .run
            .as_ref()
            .ok_or(ProfileDataError::Invalid("missing writer run"))?;
        let attempt = IngestionAttempt {
            authorized: self.authorized,
            observation_day: observed_day,
            observation: ObservationId {
                run: run.id.0,
                sequence: run.next,
            },
        };
        Ok(PendingSequence {
            issuer: self,
            attempt,
            armed: true,
        })
    }
}

#[derive(Debug)]
pub(super) struct PendingSequence<'a> {
    issuer: &'a mut SequenceIssuer,
    attempt: IngestionAttempt,
    armed: bool,
}

impl PendingSequence<'_> {
    pub(super) fn attempt(&self) -> IngestionAttempt {
        self.attempt
    }

    /// Rejected means every attempt is known not to have committed and the old
    /// job is retired. An uncertain attempt must be retried with the same payload
    /// or retire the whole run, even if a later retry was rejected.
    pub(super) fn finish(mut self, disposition: WriteDisposition) {
        match disposition {
            WriteDisposition::Confirmed => {
                self.issuer.run = self
                    .attempt
                    .observation
                    .sequence
                    .checked_add(1)
                    .map(|next| Run {
                        id: CaptureRunId(self.attempt.observation.run),
                        next,
                    });
            }
            WriteDisposition::Rejected => {}
            WriteDisposition::Unconfirmed => self.issuer.run = None,
        }
        self.armed = false;
    }
}

impl Drop for PendingSequence<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Cancellation can occur after PostgreSQL commits but before its reply.
            self.issuer.run = None;
        }
    }
}

#[cfg(test)]
#[path = "issuer/tests.rs"]
mod tests;
