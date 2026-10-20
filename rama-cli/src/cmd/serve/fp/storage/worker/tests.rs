use super::super::super::collection::{CollectionClaim, CollectionLease};
use super::*;
use parking_lot::Mutex;
use rama::{
    http::{HeaderMap, HeaderValue, Method, Version},
    ua::profile::{
        capture::{
            completeness::ProfileCaptureCompleteness,
            headers::HeaderCapturePolicy,
            joint::{CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits},
            order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture},
        },
        evidence::transaction::IngestionBatchLimits,
        format::canonical::ValueId,
        model::identity::{ConnectionContext, ConnectionIpFamily, FlowKey, ProfileKey},
    },
};
use std::{collections::VecDeque, future::pending, io};
use tokio::{
    sync::oneshot,
    time::{advance, sleep},
};

fn limits() -> StoreLimits {
    StoreLimits {
        ingestion: IngestionBatchLimits::default(),
        capture: JointCaptureLimits::default(),
        retained: [32, 32, 64, 128, 64, 2048, mib(4)],
        checkpoint_bytes: kib(16),
    }
}

fn capture(connection: bool) -> ProfileCapture {
    let policy = HeaderCapturePolicy::default();
    let mut headers = HeaderMap::new();
    headers.insert("accept", HeaderValue::from_static("text/plain"));
    let slot = if connection {
        CapturedSlot {
            kind: CapturedSlotKind::QuicParameters,
            value: OrderedProtocolCapture::capture(
                ProfileCaptureCompleteness::Complete,
                OrderNamespace::QuicParameter,
                [(1, [1])],
                OrderCaptureLimits::default(),
            )
            .unwrap()
            .canonical(OrderCaptureLimits::default())
            .unwrap(),
        }
    } else {
        CapturedSlot {
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
        }
    };
    ProfileCapture {
        profile: ProfileKey::new("queue-test"),
        flow: if connection {
            None
        } else {
            Some(FlowKey::Http {
                version: Version::HTTP_3,
                method: Method::GET,
                initiator: None,
                fetch: None,
                connection: ConnectionContext::default(),
            })
        },
        connection: ConnectionContext::default(),
        joint: JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: if connection {
                CaptureLevel::Connection
            } else {
                CaptureLevel::Request
            },
            slots: vec![slot].into(),
        },
    }
}

fn owner(authorized: bool) -> CollectionOwner {
    CollectionOwner {
        authorized,
        profile: capture(false).profile.canonical(kib(16)).unwrap().id,
    }
}

fn permit(lease: &Arc<CollectionLease>, owner: CollectionOwner) -> ConnectionPermit {
    match lease.claim(owner) {
        CollectionClaim::Connection(permit) => permit,
        claim => panic!("expected permit, got {claim:?}"),
    }
}

#[derive(Clone, Copy)]
enum Outcome {
    Confirmed,
    Rejected,
    Unconfirmed,
    Pending,
}

#[derive(Default)]
struct Recorded {
    attempts: Vec<(IngestionAttempt, ValueId)>,
    maintenance: Vec<(u32, usize)>,
}
struct Sink {
    actions: VecDeque<Outcome>,
    records: Arc<Mutex<Recorded>>,
    started: Option<oneshot::Sender<()>>,
    advance: Duration,
}

fn sink(actions: impl IntoIterator<Item = Outcome>) -> (Sink, Arc<Mutex<Recorded>>) {
    let records = Arc::new(Mutex::new(Recorded::default()));
    (
        Sink {
            actions: actions.into_iter().collect(),
            records: records.clone(),
            started: None,
            advance: Duration::ZERO,
        },
        records,
    )
}

impl CollectionSink for Sink {
    async fn maintain(&mut self, current_day: u32, rows: usize) -> Result<(), BoxError> {
        self.records.lock().maintenance.push((current_day, rows));
        Ok(())
    }

    async fn ingest(
        &mut self,
        _current_day: u32,
        attempt: IngestionAttempt,
        capture: &ProfileCapture,
    ) -> Result<bool, IngestFailure> {
        self.records.lock().attempts.push((
            attempt,
            capture
                .joint
                .canonical(JointCaptureLimits::default())
                .unwrap()
                .id,
        ));
        if let Some(started) = self.started.take() {
            started.send(()).unwrap();
        }
        if !self.advance.is_zero() {
            advance(self.advance).await;
        }
        match self.actions.pop_front().expect("unexpected ingestion") {
            Outcome::Confirmed => Ok(true),
            Outcome::Rejected => Err(IngestFailure::Rejected(
                ProfileDataError::Invalid("test rejection").into(),
            )),
            Outcome::Unconfirmed => Err(IngestFailure::Unconfirmed(
                ProfileDataError::Invalid("test uncertainty").into(),
            )),
            Outcome::Pending => pending().await,
        }
    }
}

fn nonce() -> impl FnMut() -> Result<[u8; 12], BoxError> {
    let mut n = 0u8;
    move || {
        n = n.checked_add(1).unwrap();
        Ok([n; 12])
    }
}

#[test]
fn queue_limits_and_reservations_bound_optional_preparation() {
    let good = QueueConfig::default();
    for config in [
        QueueConfig {
            capacity: 0,
            ..good
        },
        QueueConfig {
            capacity: usize::MAX,
            ..good
        },
        QueueConfig {
            attempt_timeout: Duration::ZERO,
            ..good
        },
        QueueConfig {
            attempt_timeout: Duration::from_secs(6),
            ..good
        },
        QueueConfig {
            maintenance_interval: Duration::ZERO,
            ..good
        },
        QueueConfig {
            maintenance_rows: 257,
            ..good
        },
    ] {
        CollectionQueue::new(config, limits()).unwrap_err();
    }
    let (queue, receiver) = CollectionQueue::new(
        QueueConfig {
            capacity: 1,
            ..good
        },
        limits(),
    )
    .unwrap();
    let reserved = queue.try_reserve().unwrap();
    assert!(queue.try_reserve().is_none());
    drop(reserved);
    assert_eq!(queue.counts().dropped_jobs, 2);
    let next = queue.try_reserve().unwrap();
    drop(receiver);
    drop(next);
    assert!(queue.try_reserve().is_none());
    assert_eq!(queue.counts().dropped_jobs, 4);
    let counts = queue.counts();
    assert_eq!(
        (
            counts.queue_full,
            counts.queue_closed,
            counts.preparation_drops
        ),
        (1, 1, 2)
    );
}

#[test]
fn mismatched_connection_owners_cannot_transfer_their_lease() {
    let (queue, _receiver) = CollectionQueue::new(QueueConfig::default(), limits()).unwrap();
    for wrong in [
        CollectionOwner {
            authorized: true,
            ..owner(false)
        },
        CollectionOwner {
            profile: ValueId([42; 32]),
            ..owner(false)
        },
    ] {
        let lease = Arc::new(CollectionLease::default());
        queue
            .try_reserve()
            .unwrap()
            .submit(
                owner(false),
                100,
                capture(false),
                Some((capture(true), permit(&lease, wrong))),
            )
            .unwrap_err();
        assert!(matches!(lease.claim(wrong), CollectionClaim::Connection(_)));
        assert_eq!(queue.counts().confirmed, 0);
    }
}

#[tokio::test]
async fn shutdown_drains_queued_jobs_with_live_senders_and_separate_ids() {
    let config = QueueConfig::default();
    let (queue, receiver) = CollectionQueue::new(config, limits()).unwrap();
    let lease = Arc::new(CollectionLease::default());
    let first = owner(false);
    queue
        .try_reserve()
        .unwrap()
        .submit(
            first,
            100,
            capture(false),
            Some((capture(true), permit(&lease, first))),
        )
        .unwrap();
    queue
        .try_reserve()
        .unwrap()
        .submit(first, 100, capture(false), None)
        .unwrap();
    queue
        .try_reserve()
        .unwrap()
        .submit(owner(true), 100, capture(false), None)
        .unwrap();
    let (sink, records) = sink([Outcome::Confirmed; 4]);
    run(
        receiver,
        sink,
        limits(),
        config,
        async {},
        || Ok(100),
        nonce(),
    )
    .await
    .unwrap();
    let records = records.lock();
    let attempts = &records.attempts;
    assert_eq!(attempts.len(), 4);
    assert_eq!(
        attempts
            .iter()
            .map(|(a, _)| a.observation.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 1]
    );
    assert_eq!(attempts[0].0.observation.run, attempts[2].0.observation.run);
    assert_ne!(attempts[0].0.observation.run, attempts[3].0.observation.run);
    assert_ne!(attempts[0].1, attempts[1].1);
    assert_eq!(queue.counts().confirmed, 4);
    assert!(queue.try_reserve().is_none());
    assert!(matches!(lease.claim(first), CollectionClaim::RequestOnly));
}

#[tokio::test]
async fn uncertainty_keeps_retry_ids_and_retires_the_run_after_rejection() {
    let config = QueueConfig::default();
    let (queue, receiver) = CollectionQueue::new(config, limits()).unwrap();
    for _ in 0..3 {
        queue
            .try_reserve()
            .unwrap()
            .submit(owner(false), 100, capture(false), None)
            .unwrap();
    }
    let (sink, records) = sink([
        Outcome::Unconfirmed,
        Outcome::Rejected,
        Outcome::Rejected,
        Outcome::Confirmed,
    ]);
    run(
        receiver,
        sink,
        limits(),
        config,
        async {},
        || Ok(100),
        nonce(),
    )
    .await
    .unwrap();
    let records = records.lock();
    let attempts = &records.attempts;
    assert_eq!(attempts.len(), 4);
    same_attempt(&attempts[0], &attempts[1]);
    assert_ne!(attempts[1].0.observation.run, attempts[2].0.observation.run);
    same_attempt(&attempts[2], &attempts[3]);
    let counts = queue.counts();
    assert_eq!(
        (counts.confirmed, counts.rejected, counts.unconfirmed),
        (1, 1, 1)
    );
}

#[tokio::test(start_paused = true)]
async fn timed_out_writes_keep_one_id_and_cannot_reclaim_connection_ownership() {
    let config = QueueConfig::default();
    let (queue, receiver) = CollectionQueue::new(config, limits()).unwrap();
    let lease = Arc::new(CollectionLease::default());
    let first = owner(false);
    queue
        .try_reserve()
        .unwrap()
        .submit(
            first,
            100,
            capture(false),
            Some((capture(true), permit(&lease, first))),
        )
        .unwrap();
    let (sink, records) = sink([
        Outcome::Pending,
        Outcome::Pending,
        Outcome::Pending,
        Outcome::Confirmed,
    ]);
    run(
        receiver,
        sink,
        limits(),
        config,
        async {},
        || Ok(100),
        nonce(),
    )
    .await
    .unwrap();
    let records = records.lock();
    let attempts = &records.attempts;
    assert_eq!(attempts.len(), 4);
    same_attempt(&attempts[0], &attempts[1]);
    same_attempt(&attempts[1], &attempts[2]);
    assert_ne!(attempts[2].0.observation.run, attempts[3].0.observation.run);
    assert_eq!(queue.counts().unconfirmed, 1);
    assert_eq!(queue.counts().confirmed, 1);
    assert_eq!(queue.counts().uncertain_attempts, 3);
    assert!(matches!(lease.claim(first), CollectionClaim::RequestOnly));
}

#[tokio::test]
async fn abort_after_sink_admission_keeps_uncertainty_and_retires_queued_payloads() {
    let config = QueueConfig::default();
    let (queue, receiver) = CollectionQueue::new(config, limits()).unwrap();
    let lease = Arc::new(CollectionLease::default());
    let first = owner(false);
    queue
        .try_reserve()
        .unwrap()
        .submit(
            first,
            100,
            capture(false),
            Some((capture(true), permit(&lease, first))),
        )
        .unwrap();
    let (mut sink, _records) = sink([Outcome::Pending]);
    let (started, entered) = oneshot::channel();
    sink.started = Some(started);
    let worker = tokio::spawn(run(
        receiver,
        sink,
        limits(),
        config,
        pending(),
        || Ok(100),
        nonce(),
    ));
    entered.await.unwrap();
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    let counts = queue.counts();
    assert_eq!((counts.rejected, counts.unconfirmed), (1, 1));
    assert!(matches!(lease.claim(first), CollectionClaim::RequestOnly));
}

#[tokio::test(start_paused = true)]
async fn expired_jobs_are_rejected_and_busy_collection_runs_bounded_maintenance() {
    let config = QueueConfig::default();
    let (queue, receiver) = CollectionQueue::new(config, limits()).unwrap();
    for day in [86, 100, 100, 100] {
        queue
            .try_reserve()
            .unwrap()
            .submit(owner(false), day, capture(false), None)
            .unwrap();
    }
    let (mut sink, records) = sink([Outcome::Confirmed; 3]);
    sink.advance = Duration::from_secs(61);
    run(
        receiver,
        sink,
        limits(),
        config,
        async {},
        || Ok(100),
        nonce(),
    )
    .await
    .unwrap();
    let records = records.lock();
    assert_eq!(records.attempts.len(), 3);
    assert_eq!(records.attempts[0].0.observation.sequence, 1);
    assert_eq!(queue.counts().rejected, 1);
    assert_eq!(queue.counts().confirmed, 3);
    assert_eq!(queue.counts().expired, 1);
    assert_eq!(queue.counts().admission_failures, 1);
    assert_eq!(records.maintenance, vec![(100, 256); 3]);
    assert_eq!(queue.counts().maintenance_failures, 0);
}

fn same_attempt(a: &(IngestionAttempt, ValueId), b: &(IngestionAttempt, ValueId)) {
    assert_eq!(a.0.authorized, b.0.authorized);
    assert_eq!(a.0.observation_day, b.0.observation_day);
    assert_eq!(a.0.observation, b.0.observation);
    assert_eq!(a.1, b.1);
}

#[tokio::test(start_paused = true)]
async fn shutdown_does_not_wait_for_unsubmitted_reservations() {
    let config = QueueConfig::default();
    let (queue, receiver) = CollectionQueue::new(config, limits()).unwrap();
    let reservation = queue.try_reserve().unwrap();
    let (sink, records) = sink([]);
    timeout(
        Duration::from_secs(1),
        run(
            receiver,
            sink,
            limits(),
            config,
            async {},
            || Ok(100),
            nonce(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let lease = Arc::new(CollectionLease::default());
    let first = owner(false);
    reservation
        .submit(
            first,
            100,
            capture(false),
            Some((capture(true), permit(&lease, first))),
        )
        .unwrap_err();
    assert!(matches!(lease.claim(first), CollectionClaim::Connection(_)));
    assert!(records.lock().attempts.is_empty());
    assert_eq!(queue.counts().dropped_jobs, 1);
}

#[test]
fn collection_diagnostics_separate_limits_expiry_invalid_input_and_database_errors() {
    let counters = CollectionCounters::default();
    for error in [
        BoxError::from(ProfileDataError::Expired),
        BoxError::from(ProfileDataError::LimitExceeded("private-limit")),
        BoxError::from(ProfileDataError::Invalid("private-detail")),
        BoxError::from(io::Error::other("private-database-error")),
    ] {
        counters.rejected_attempt(&error);
    }
    let counts = counters.snapshot();
    assert_eq!(
        (
            counts.expired,
            counts.storage_limits,
            counts.invalid_capture,
            counts.database_rejections
        ),
        (1, 1, 1, 1)
    );
    assert_eq!(
        (counts.confirmed, counts.rejected, counts.unconfirmed),
        (0, 0, 0)
    );
    assert!(!format!("{counts:?}").contains("private-"));
    counters.admission_failed(&io::Error::other("private-nonce-error").into());
    assert_eq!(counters.snapshot().admission_failures, 1);
    assert_eq!(counters.snapshot().database_rejections, 1);
    assert_eq!(counters.snapshot().clock_failures, 0);
    counters.dropped_jobs.store(u64::MAX, Ordering::Relaxed);
    increment(&counters.dropped_jobs);
    assert_eq!(counters.snapshot().dropped_jobs, u64::MAX);
}

#[tokio::test]
async fn clock_and_entropy_failures_do_not_consume_observation_sequences() {
    for fail_clock in [false, true] {
        let config = QueueConfig::default();
        let (queue, receiver) = CollectionQueue::new(config, limits()).unwrap();
        let lease = Arc::new(CollectionLease::default());
        let first = owner(false);
        queue
            .try_reserve()
            .unwrap()
            .submit(
                first,
                100,
                capture(false),
                Some((capture(true), permit(&lease, first))),
            )
            .unwrap();
        let (sink, records) = sink([Outcome::Confirmed]);
        let mut first_clock = fail_clock;
        let mut first_nonce = !fail_clock;
        run(
            receiver,
            sink,
            limits(),
            config,
            async {},
            move || {
                if first_clock {
                    first_clock = false;
                    Err(io::Error::other("clock unavailable").into())
                } else {
                    Ok(100)
                }
            },
            move || {
                if first_nonce {
                    first_nonce = false;
                    Err(io::Error::other("entropy unavailable").into())
                } else {
                    Ok([1; 12])
                }
            },
        )
        .await
        .unwrap();
        let counts = queue.counts();
        assert_eq!(
            (counts.confirmed, counts.rejected, counts.unconfirmed),
            (1, 1, 0)
        );
        assert_eq!(
            (counts.clock_failures, counts.admission_failures),
            (u64::from(fail_clock), u64::from(!fail_clock))
        );
        assert_eq!(counts.database_rejections, 0);
        let records = records.lock();
        assert_eq!(records.attempts.len(), 1);
        assert_eq!(records.attempts[0].0.observation.sequence, 1);
        assert!(matches!(lease.claim(first), CollectionClaim::RequestOnly));
    }
}

#[test]
fn invalid_jobs_release_reserved_capacity_and_connection_preparation() {
    enum InvalidCapture {
        RequestLevel,
        Profile,
        ConnectionLevel,
        RequestIncomplete,
        ConnectionIncomplete,
        Context,
    }
    for case in [
        InvalidCapture::RequestLevel,
        InvalidCapture::Profile,
        InvalidCapture::ConnectionLevel,
        InvalidCapture::RequestIncomplete,
        InvalidCapture::ConnectionIncomplete,
        InvalidCapture::Context,
    ] {
        let config = QueueConfig {
            capacity: 1,
            ..QueueConfig::default()
        };
        let (queue, _receiver) = CollectionQueue::new(config, limits()).unwrap();
        let lease = Arc::new(CollectionLease::default());
        let first = owner(false);
        let mut request = capture(false);
        let mut connection = capture(true);
        match case {
            InvalidCapture::RequestLevel => request = capture(true),
            InvalidCapture::Profile => request.profile = ProfileKey::new("different-profile"),
            InvalidCapture::ConnectionLevel => connection = capture(false),
            InvalidCapture::RequestIncomplete => {
                request.joint.completeness = ProfileCaptureCompleteness::Incomplete
            }
            InvalidCapture::ConnectionIncomplete => {
                connection.joint.completeness = ProfileCaptureCompleteness::Incomplete
            }
            InvalidCapture::Context => {
                connection.connection.ip_family = Some(ConnectionIpFamily::V4)
            }
        }
        queue
            .try_reserve()
            .unwrap()
            .submit(
                first,
                100,
                request,
                Some((connection, permit(&lease, first))),
            )
            .unwrap_err();
        assert!(matches!(lease.claim(first), CollectionClaim::Connection(_)));
        let counts = queue.counts();
        assert_eq!(
            (
                counts.invalid_capture,
                counts.preparation_drops,
                counts.confirmed,
                counts.unconfirmed
            ),
            (1, 0, 0, 0)
        );
        assert!(queue.try_reserve().is_some());
    }
}

#[tokio::test(start_paused = true)]
async fn idle_collection_maintains_retention_with_live_senders() {
    let config = QueueConfig::default();
    let (queue, receiver) = CollectionQueue::new(config, limits()).unwrap();
    let (sink, records) = sink([]);
    run(
        receiver,
        sink,
        limits(),
        config,
        sleep(Duration::from_secs(121)),
        || Ok(100),
        nonce(),
    )
    .await
    .unwrap();
    assert_eq!(records.lock().maintenance, vec![(100, 256); 2]);
    assert_eq!(queue.counts().maintenance_failures, 0);
    assert!(queue.try_reserve().is_none());
}

#[tokio::test]
async fn preparation_crossing_midnight_does_not_drop_retained_observations() {
    let config = QueueConfig::default();
    let (queue, receiver) = CollectionQueue::new(config, limits()).unwrap();
    for day in [101, 100, 101] {
        queue
            .try_reserve()
            .unwrap()
            .submit(owner(false), day, capture(false), None)
            .unwrap();
    }
    let (sink, records) = sink([Outcome::Confirmed; 3]);
    run(
        receiver,
        sink,
        limits(),
        config,
        async {},
        || Ok(101),
        nonce(),
    )
    .await
    .unwrap();
    let records = records.lock();
    let attempts = &records.attempts;
    assert_eq!(attempts.len(), 3);
    assert_ne!(attempts[0].0.observation.run, attempts[1].0.observation.run);
    assert_eq!(attempts[1].0.observation.run, attempts[2].0.observation.run);
    assert_eq!(
        attempts
            .iter()
            .map(|(attempt, _)| attempt.observation.sequence)
            .collect::<Vec<_>>(),
        vec![1, 1, 2]
    );
    assert_eq!((queue.counts().confirmed, queue.counts().rejected), (3, 0));
}

#[test]
fn submission_and_receiver_shutdown_share_one_critical_section() {
    let (queue, mut receiver) = CollectionQueue::new(QueueConfig::default(), limits()).unwrap();
    let reservation = queue.try_reserve().unwrap();
    let gate = queue.closed.clone();
    BEFORE_SEND.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            // The exact interleaving from W-1 cannot close the receiver here.
            assert!(gate.try_write().is_none());
        }))
    });
    reservation
        .submit(owner(false), 100, capture(false), None)
        .unwrap();
    receiver.close();
    assert!(!receiver.receiver.is_empty());
    drop(receiver);
    assert_eq!(queue.counts().rejected, 1);
    assert_eq!(queue.counts().preparation_drops, 0);
}

#[test]
fn dropped_receiver_rejects_reserved_jobs_before_last_sender_drops() {
    let (queue, receiver) = CollectionQueue::new(QueueConfig::default(), limits()).unwrap();
    let clone = queue.clone();
    let reservation = queue.try_reserve().unwrap();
    let lease = Arc::new(CollectionLease::default());
    let first = owner(false);
    drop(receiver);
    reservation
        .submit(
            first,
            100,
            capture(false),
            Some((capture(true), permit(&lease, first))),
        )
        .unwrap_err();
    assert!(matches!(lease.claim(first), CollectionClaim::Connection(_)));
    let counts = clone.counts();
    assert_eq!(
        (
            counts.queue_closed,
            counts.dropped_jobs,
            counts.preparation_drops,
            counts.invalid_capture
        ),
        (1, 1, 0, 0)
    );
}

#[test]
fn preparation_failures_keep_clock_capture_and_cancellation_separate() {
    let (queue, _receiver) = CollectionQueue::new(QueueConfig::default(), limits()).unwrap();
    queue.try_reserve().unwrap().reject_clock();
    queue.try_reserve().unwrap().reject_capture();
    drop(queue.try_reserve().unwrap());
    let counts = queue.counts();
    assert_eq!(
        (
            counts.dropped_jobs,
            counts.clock_failures,
            counts.invalid_capture,
            counts.preparation_drops
        ),
        (3, 1, 1, 1)
    );
}

#[cfg(unix)]
mod postgres_harness {
    use super::super::super::{migrations, postgres};
    use super::*;
    use std::env;

    #[tokio::test]
    #[ignore = "requires the private PostgreSQL integration harness"]
    async fn fp_collection_queue_retries_committed_observations_and_separates_owners() {
        let (_config, mut fixture) = migrations::tests::isolated_database().await.unwrap();
        fixture
            .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
            .await
            .unwrap();
        migrations::apply(&mut fixture).await.unwrap();
        let pool = postgres::try_new_pool(env::var("RAMA_FP_TEST_PG").unwrap())
            .await
            .unwrap();
        let seeds = counted::sampler_seeds(&mut fixture, [[3; 32], [4; 32]])
            .await
            .unwrap();
        let sink = PostgresSink {
            pool,
            seeds,
            limits: limits(),
        };
        struct LoseCommitReply {
            inner: PostgresSink,
            lose: bool,
            attempts: Arc<Mutex<Vec<IngestionAttempt>>>,
        }

        impl CollectionSink for LoseCommitReply {
            async fn maintain(&mut self, day: u32, rows: usize) -> Result<(), BoxError> {
                self.inner.maintain(day, rows).await
            }

            async fn ingest(
                &mut self,
                day: u32,
                attempt: IngestionAttempt,
                capture: &ProfileCapture,
            ) -> Result<bool, IngestFailure> {
                self.attempts.lock().push(attempt);
                let inserted = self.inner.ingest(day, attempt, capture).await?;
                if self.lose {
                    self.lose = false;
                    Err(IngestFailure::Unconfirmed(
                        io::Error::other("test commit reply lost").into(),
                    ))
                } else {
                    Ok(inserted)
                }
            }
        }
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let sink = LoseCommitReply {
            inner: sink,
            lose: true,
            attempts: attempts.clone(),
        };
        let config = QueueConfig::default();
        let (queue, receiver) = CollectionQueue::new(config, limits()).unwrap();
        let public = Arc::new(CollectionLease::default());
        let authorized = Arc::new(CollectionLease::default());
        queue
            .try_reserve()
            .unwrap()
            .submit(
                owner(false),
                100,
                capture(false),
                Some((capture(true), permit(&public, owner(false)))),
            )
            .unwrap();
        queue
            .try_reserve()
            .unwrap()
            .submit(owner(false), 100, capture(false), None)
            .unwrap();
        queue
            .try_reserve()
            .unwrap()
            .submit(
                owner(true),
                100,
                capture(false),
                Some((capture(true), permit(&authorized, owner(true)))),
            )
            .unwrap();
        run(
            receiver,
            sink,
            limits(),
            config,
            async {},
            || Ok(100),
            nonce(),
        )
        .await
        .unwrap();
        let counts = queue.counts();
        assert_eq!(
            (
                counts.confirmed,
                counts.rejected,
                counts.unconfirmed,
                counts.uncertain_attempts
            ),
            (5, 0, 0, 1)
        );
        {
            let attempts = attempts.lock();
            assert_eq!(attempts.len(), 6);
            assert_eq!(attempts[0].observation, attempts[1].observation);
            assert_eq!(attempts[0].observation_day, attempts[1].observation_day);
            assert!(matches!(
                public.claim(owner(false)),
                CollectionClaim::RequestOnly
            ));
            assert!(matches!(
                authorized.claim(owner(true)),
                CollectionClaim::RequestOnly
            ));
        }
        let rows=fixture.query("SELECT authorized,sum(total)::bigint FROM fp_v2.buckets GROUP BY authorized ORDER BY authorized",&[]).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert!(!rows[0].get::<_, bool>(0));
        assert_eq!(rows[0].get::<_, i64>(1), 6);
        assert!(rows[1].get::<_, bool>(0));
        assert_eq!(rows[1].get::<_, i64>(1), 4);
        let (queue, receiver) = CollectionQueue::new(config, limits()).unwrap();
        queue
            .try_reserve()
            .unwrap()
            .submit(owner(false), 100, capture(false), None)
            .unwrap();
        queue
            .try_reserve()
            .unwrap()
            .submit(owner(false), 114, capture(false), None)
            .unwrap();
        let pool = postgres::try_new_pool(env::var("RAMA_FP_TEST_PG").unwrap())
            .await
            .unwrap();
        let mut sink = PostgresSink {
            pool,
            seeds,
            limits: limits(),
        };
        sink.maintain(114, 256).await.unwrap();
        run(
            receiver,
            sink,
            limits(),
            config,
            async {},
            || Ok(114),
            || Ok([99; 12]),
        )
        .await
        .unwrap();
        assert_eq!(
            (
                queue.counts().expired,
                queue.counts().rejected,
                queue.counts().confirmed
            ),
            (1, 1, 1)
        );
        let row = fixture
            .query_one(
                "SELECT count(*)::bigint,sum(total)::bigint,min(day) FROM fp_v2.buckets",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i64>(0), 2);
        assert_eq!(row.get::<_, i64>(1), 2);
        assert_eq!(row.get::<_, i64>(2), 114);
    }
}
