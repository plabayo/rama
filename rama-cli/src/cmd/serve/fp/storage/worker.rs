//! Bounded optional collection with retry IDs owned by the database worker.

use rama::{
    error::BoxError,
    ua::profile::{CaptureLevel, IngestionAttempt, ProfileCapture, ProfileDataError},
    utils::octets::{kib, mib},
};
use std::{
    iter,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::mpsc,
    time::{Instant, sleep_until, timeout},
};

use super::super::collection::{
    CollectionOwner, CollectionResult, ConnectionCompletion, ConnectionPermit,
};
use super::{
    counted::{self, IngestFailure, StoreLimits},
    issuer::{SequenceIssuer, WriteDisposition},
    postgres::Pool,
};

#[derive(Debug, Clone, Copy)]
pub(super) struct QueueConfig {
    pub capacity: usize,
    pub attempt_timeout: Duration,
    pub maintenance_interval: Duration,
    pub maintenance_rows: usize,
}
impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            capacity: 128,
            attempt_timeout: Duration::from_secs(5),
            maintenance_interval: Duration::from_secs(60),
            maintenance_rows: 256,
        }
    }
}
impl QueueConfig {
    fn validate(self, limits: StoreLimits) -> Result<(), BoxError> {
        let bytes = self
            .capacity
            .checked_mul(limits.capture.bytes)
            .and_then(|bytes| bytes.checked_mul(2));
        if self.capacity == 0
            || self.capacity > 128
            || bytes.is_none_or(|bytes| bytes > mib(16))
            || limits.capture.bytes == 0
            || limits.capture.bytes > kib(64)
            || limits.capture.slots == 0
            || limits.capture.slots > 16
            || limits.capture.value_bytes == 0
            || limits.capture.value_bytes > kib(16)
            || self.attempt_timeout.is_zero()
            || self.attempt_timeout > Duration::from_secs(5)
            || self.maintenance_interval.is_zero()
            || self.maintenance_interval > Duration::from_secs(60)
            || self.maintenance_rows == 0
            || self.maintenance_rows > 256
        {
            return Err(ProfileDataError::Invalid("collection queue limits").into());
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(super) struct CollectionCounters {
    dropped_jobs: AtomicU64,
    maintenance_failures: AtomicU64,
    queue_full: AtomicU64,
    queue_closed: AtomicU64,
    preparation_drops: AtomicU64,
    clock_failures: AtomicU64,
    admission_failures: AtomicU64,
    expired: AtomicU64,
    storage_limits: AtomicU64,
    invalid_capture: AtomicU64,
    database_rejections: AtomicU64,
    uncertain_attempts: AtomicU64,
    confirmed: AtomicU64,
    rejected: AtomicU64,
    unconfirmed: AtomicU64,
}
fn increment(counter: &AtomicU64) {
    _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}
#[derive(Debug, Clone, Copy)]
pub(super) struct CollectionCounts {
    pub dropped_jobs: u64,
    pub maintenance_failures: u64,
    pub queue_full: u64,
    pub queue_closed: u64,
    pub preparation_drops: u64,
    pub clock_failures: u64,
    pub admission_failures: u64,
    pub expired: u64,
    pub storage_limits: u64,
    pub invalid_capture: u64,
    pub database_rejections: u64,
    pub uncertain_attempts: u64,
    pub confirmed: u64,
    pub rejected: u64,
    pub unconfirmed: u64,
}
impl CollectionCounters {
    /// Failure categories never retain error messages or captured values. These
    /// count attempts; the terminal counters count retired observations.
    fn admission_failed(&self, error: &BoxError) {
        increment(&self.admission_failures);
        if error.downcast_ref::<ProfileDataError>().is_some() {
            self.rejected_attempt(error);
        }
    }
    fn rejected_attempt(&self, error: &BoxError) {
        increment(match error.downcast_ref::<ProfileDataError>() {
            Some(ProfileDataError::Expired) => &self.expired,
            Some(ProfileDataError::LimitExceeded(_)) => &self.storage_limits,
            Some(_) => &self.invalid_capture,
            None => &self.database_rejections,
        });
    }

    pub(super) fn snapshot(&self) -> CollectionCounts {
        CollectionCounts {
            dropped_jobs: self.dropped_jobs.load(Ordering::Relaxed),
            maintenance_failures: self.maintenance_failures.load(Ordering::Relaxed),
            queue_full: self.queue_full.load(Ordering::Relaxed),
            queue_closed: self.queue_closed.load(Ordering::Relaxed),
            preparation_drops: self.preparation_drops.load(Ordering::Relaxed),
            clock_failures: self.clock_failures.load(Ordering::Relaxed),
            admission_failures: self.admission_failures.load(Ordering::Relaxed),
            expired: self.expired.load(Ordering::Relaxed),
            storage_limits: self.storage_limits.load(Ordering::Relaxed),
            invalid_capture: self.invalid_capture.load(Ordering::Relaxed),
            database_rejections: self.database_rejections.load(Ordering::Relaxed),
            uncertain_attempts: self.uncertain_attempts.load(Ordering::Relaxed),
            confirmed: self.confirmed.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            unconfirmed: self.unconfirmed.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct CollectionQueue {
    sender: mpsc::Sender<Job>,
    closed: Arc<AtomicBool>,
    counters: Arc<CollectionCounters>,
    limits: StoreLimits,
}
#[derive(Debug)]
pub(super) struct CollectionReceiver {
    receiver: mpsc::Receiver<Job>,
    closed: Arc<AtomicBool>,
    counters: Arc<CollectionCounters>,
}

#[derive(Debug)]
pub(super) struct CollectionReservation {
    slot: Option<mpsc::OwnedPermit<Job>>,
    submitted: bool,
    closed: Arc<AtomicBool>,
    counters: Arc<CollectionCounters>,
    limits: StoreLimits,
}
impl CollectionQueue {
    pub(super) fn new(
        config: QueueConfig,
        limits: StoreLimits,
    ) -> Result<(Self, CollectionReceiver), BoxError> {
        config.validate(limits)?;
        let (sender, receiver) = mpsc::channel(config.capacity);
        let counters = Arc::default();
        let closed = Arc::new(AtomicBool::new(false));
        Ok((
            Self {
                sender,
                closed: closed.clone(),
                counters: Arc::clone(&counters),
                limits,
            },
            CollectionReceiver {
                receiver,
                closed,
                counters,
            },
        ))
    }
    /// Reserve before building optional captures or waiting for connection metadata.
    pub(super) fn try_reserve(&self) -> Option<CollectionReservation> {
        if self.closed.load(Ordering::Acquire) {
            increment(&self.counters.dropped_jobs);
            increment(&self.counters.queue_closed);
            return None;
        }
        match self.sender.clone().try_reserve_owned() {
            Ok(slot) => Some(CollectionReservation {
                slot: Some(slot),
                submitted: false,
                closed: self.closed.clone(),
                counters: self.counters.clone(),
                limits: self.limits,
            }),
            Err(error) => {
                increment(&self.counters.dropped_jobs);
                increment(match error {
                    mpsc::error::TrySendError::Full(_) => &self.counters.queue_full,
                    mpsc::error::TrySendError::Closed(_) => &self.counters.queue_closed,
                });
                None
            }
        }
    }
    pub(super) fn counts(&self) -> CollectionCounts {
        self.counters.snapshot()
    }
}

#[derive(Debug)]
pub(super) struct Job {
    authorized: bool,
    day: u32,
    connection: Option<ObservationJob>,
    request: ObservationJob,
}
#[derive(Debug)]
struct ObservationJob {
    capture: ProfileCapture,
    connection: Option<ConnectionCompletion>,
    counters: Arc<CollectionCounters>,
    attempted: bool,
    finished: bool,
}
impl ObservationJob {
    fn finish(mut self, result: CollectionResult) {
        self.record(result);
        self.finished = true;
    }
    fn record(&mut self, result: CollectionResult) {
        increment(match result {
            CollectionResult::Stored => &self.counters.confirmed,
            CollectionResult::Rejected => &self.counters.rejected,
            CollectionResult::Unconfirmed => &self.counters.unconfirmed,
        });
        if let Some(completion) = self.connection.take() {
            completion.finish(result);
        }
    }
}
impl Drop for ObservationJob {
    fn drop(&mut self) {
        if !self.finished {
            self.record(if self.attempted {
                CollectionResult::Unconfirmed
            } else {
                CollectionResult::Rejected
            });
        }
    }
}
impl CollectionReservation {
    /// This method has no await point between transferring connection ownership
    /// and sending to the reserved queue slot.
    pub(super) fn submit(
        mut self,
        owner: CollectionOwner,
        day: u32,
        request: ProfileCapture,
        connection: Option<(ProfileCapture, ConnectionPermit)>,
    ) -> Result<(), BoxError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(ProfileDataError::Invalid("closed collection queue").into());
        }
        if connection
            .as_ref()
            .is_some_and(|(_capture, permit)| permit.owner() != owner)
        {
            return Err(ProfileDataError::Invalid("connection collection owner").into());
        }
        if request.joint.level != CaptureLevel::Request {
            return Err(ProfileDataError::Invalid("request collection level").into());
        }
        for capture in
            iter::once(&request).chain(connection.as_ref().map(|(capture, _permit)| capture))
        {
            let prepared = capture.prepare(owner.authorized, self.limits.capture)?;
            if prepared.profile.id != owner.profile
                || prepared.buckets.len() > self.limits.ingestion.buckets
            {
                return Err(
                    ProfileDataError::Invalid("collection owner or component budget").into(),
                );
            }
        }
        if connection.as_ref().is_some_and(|(capture, _permit)| {
            capture.joint.level != CaptureLevel::Connection
                || capture.connection != request.connection
        }) {
            return Err(ProfileDataError::Invalid("connection collection context").into());
        }
        let slot = self.slot.take().ok_or(ProfileDataError::Invalid(
            "missing reserved collection slot",
        ))?;
        let connection = connection.map(|(capture, permit)| ObservationJob {
            capture,
            connection: Some(permit.queued()),
            counters: self.counters.clone(),
            attempted: false,
            finished: false,
        });
        let request = ObservationJob {
            capture: request,
            connection: None,
            counters: self.counters.clone(),
            attempted: false,
            finished: false,
        };
        self.submitted = true;
        slot.send(Job {
            authorized: owner.authorized,
            day,
            connection,
            request,
        });
        Ok(())
    }
}

impl Drop for CollectionReservation {
    fn drop(&mut self) {
        if !self.submitted {
            increment(&self.counters.dropped_jobs);
            increment(&self.counters.preparation_drops);
        }
    }
}

pub(super) trait CollectionSink {
    fn maintain(
        &mut self,
        current_day: u32,
        rows: usize,
    ) -> impl Future<Output = Result<(), BoxError>> + Send;
    fn ingest(
        &mut self,
        current_day: u32,
        attempt: IngestionAttempt,
        capture: &ProfileCapture,
    ) -> impl Future<Output = Result<bool, IngestFailure>> + Send;
}
#[derive(Debug)]
pub(super) struct PostgresSink {
    pub pool: Pool,
    pub seeds: [[u8; 32]; 2],
    pub limits: StoreLimits,
}
impl CollectionSink for PostgresSink {
    async fn maintain(&mut self, current_day: u32, rows: usize) -> Result<(), BoxError> {
        let mut client = self.pool.get().await?;
        for authorized in [false, true] {
            counted::prune(&mut client, authorized, current_day, self.limits, rows).await?;
        }
        Ok(())
    }
    async fn ingest(
        &mut self,
        current_day: u32,
        attempt: IngestionAttempt,
        capture: &ProfileCapture,
    ) -> Result<bool, IngestFailure> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|error| IngestFailure::Rejected(error.into()))?;
        counted::ingest(
            &mut client,
            current_day,
            attempt,
            capture,
            self.seeds[usize::from(attempt.authorized)],
            self.limits,
        )
        .await
    }
}

pub(super) async fn run(
    input: CollectionReceiver,
    mut sink: impl CollectionSink,
    limits: StoreLimits,
    config: QueueConfig,
    shutdown: impl Future<Output = ()> + Send,
    mut day: impl FnMut() -> Result<u32, BoxError>,
    mut nonce: impl FnMut() -> Result<[u8; 12], BoxError>,
) -> Result<(), BoxError> {
    config.validate(limits)?;
    let CollectionReceiver {
        mut receiver,
        closed,
        counters,
    } = input;
    tokio::pin!(shutdown);
    let mut closing = false;
    let mut next_maintenance = Instant::now() + config.maintenance_interval;
    let mut issuers = [SequenceIssuer::new(false), SequenceIssuer::new(true)];
    loop {
        // Check between jobs too: a busy queue cannot starve retention cleanup.
        if Instant::now() >= next_maintenance {
            match day() {
                Ok(current_day) => {
                    if !matches!(
                        timeout(
                            config.attempt_timeout,
                            sink.maintain(current_day, config.maintenance_rows)
                        )
                        .await,
                        Ok(Ok(()))
                    ) {
                        increment(&counters.maintenance_failures);
                    }
                }
                Err(_error) => increment(&counters.maintenance_failures),
            }
            next_maintenance = Instant::now() + config.maintenance_interval;
        }
        // Outstanding preparation reservations cannot prolong shutdown. If one
        // races the closed flag, dropping the receiver rejects its owned job.
        if closing && receiver.is_empty() {
            break;
        }
        let job = tokio::select! {
            biased;
            () = &mut shutdown, if !closing => { closed.store(true, Ordering::Release); receiver.close(); closing = true; continue; }
            () = sleep_until(next_maintenance) => continue,
            job = receiver.recv() => match job { Some(job) => job, None => break },
        };
        for mut observation in job.connection.into_iter().chain(iter::once(job.request)) {
            let Ok(current_day) = day() else {
                increment(&counters.clock_failures);
                observation.finish(CollectionResult::Rejected);
                continue;
            };
            let sequence = match issuers[usize::from(job.authorized)].begin(
                current_day,
                job.day,
                limits.ingestion.retention,
                &mut nonce,
            ) {
                Ok(sequence) => sequence,
                Err(error) => {
                    counters.admission_failed(&error);
                    observation.finish(CollectionResult::Rejected);
                    continue;
                }
            };
            let mut result = CollectionResult::Rejected;
            let mut uncertain = false;
            for _ in 0..3 {
                let Ok(current_day) = day() else {
                    increment(&counters.clock_failures);
                    result = if uncertain {
                        CollectionResult::Unconfirmed
                    } else {
                        CollectionResult::Rejected
                    };
                    break;
                };
                observation.attempted = true;
                match timeout(
                    config.attempt_timeout,
                    sink.ingest(current_day, sequence.attempt(), &observation.capture),
                )
                .await
                {
                    Ok(Ok(_inserted)) => {
                        result = CollectionResult::Stored;
                        break;
                    }
                    Ok(Err(IngestFailure::Rejected(error))) => {
                        counters.rejected_attempt(&error);
                        result = if uncertain {
                            CollectionResult::Unconfirmed
                        } else {
                            CollectionResult::Rejected
                        };
                        break;
                    }
                    Ok(Err(IngestFailure::Unconfirmed(_))) | Err(_) => {
                        increment(&counters.uncertain_attempts);
                        uncertain = true;
                        result = CollectionResult::Unconfirmed;
                    }
                }
            }
            sequence.finish(match result {
                CollectionResult::Stored => WriteDisposition::Confirmed,
                CollectionResult::Rejected => WriteDisposition::Rejected,
                CollectionResult::Unconfirmed => WriteDisposition::Unconfirmed,
            });
            observation.finish(result);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "worker/tests.rs"]
mod tests;
