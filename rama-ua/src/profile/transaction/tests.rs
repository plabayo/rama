use crate::profile::CanonicalDomain;
use rama_http::{HeaderMap, HeaderValue, Version};
use rama_utils::octets::kib;

use super::*;
use crate::profile::{HeaderCapturePolicy, ValueId};

fn value(text: &'static str) -> CanonicalValue {
    let mut headers = HeaderMap::new();
    headers.insert("x-mode", HeaderValue::from_static(text));
    let policy = HeaderCapturePolicy::default();
    policy
        .capture(Version::HTTP_11, &headers, None)
        .unwrap()
        .canonical(&policy)
        .unwrap()
}

fn empty(scope: u8, day: u32) -> StoredObservationBucket {
    StoredObservationBucket {
        authorized: false,
        day,
        bucket: CountedObservationBucket::new(
            CanonicalDomain::Headers,
            ValueId([scope; 32]),
            [3; 32],
            ProfileBucketLimits::default(),
        )
        .unwrap()
        .snapshot(),
    }
}

fn run() -> CaptureRunCheckpoint {
    CaptureRunCheckpoint::new(
        CaptureRunId::new(100, [1; 12]),
        false,
        100,
        IngestionBatchLimits::default(),
    )
    .unwrap()
}

fn attempt(run: &CaptureRunCheckpoint, sequence: u64, day: u32) -> IngestionAttempt {
    IngestionAttempt {
        authorized: run.authorized,
        observation_day: day,
        observation: ObservationId {
            run: run.run.0,
            sequence,
        },
    }
}

#[test]
fn ingestion_batch_commits_complete_tuple_once_across_retries_and_days() {
    let limits = IngestionBatchLimits::default();
    let mut run = run();
    let a = value("A");
    let b = value("B");
    let mut buckets = vec![empty(1, 100), empty(2, 100)];
    for sequence in [3, 1, 2] {
        let pending = [
            PendingBucketObservation {
                expected_scope: buckets[0].bucket.scope,
                previous: &buckets[0],
                value: &a,
            },
            PendingBucketObservation {
                expected_scope: buckets[1].bucket.scope,
                previous: &buckets[1],
                value: &b,
            },
        ];
        let result = run
            .prepare(100, attempt(&run, sequence, 100), &pending, [3; 32], limits)
            .unwrap();
        let PreparedIngestion::Commit {
            run: next,
            buckets: next_buckets,
        } = result
        else {
            panic!("new observation must commit")
        };
        run = next;
        buckets = next_buckets.into_vec();
        let different_day = empty(9, 101);
        let retry = [PendingBucketObservation {
            expected_scope: different_day.bucket.scope,
            previous: &different_day,
            value: &b,
        }];
        assert!(matches!(
            run.prepare(101, attempt(&run, sequence, 101), &retry, [3; 32], limits)
                .unwrap(),
            PreparedIngestion::Duplicate
        ));
    }
    assert_eq!(run.sequences.prefix, 3);
    for bucket in &buckets {
        assert_eq!(bucket.bucket.counts.total, 3);
        assert_eq!(bucket.bucket.samples.len(), 3);
        assert_eq!(bucket.bucket.values.len(), 1);
    }
    let restored: CaptureRunCheckpoint =
        serde_json::from_slice(&serde_json::to_vec(&run).unwrap()).unwrap();
    let retry = [PendingBucketObservation {
        expected_scope: buckets[0].bucket.scope,
        previous: &buckets[0],
        value: &a,
    }];
    assert!(matches!(
        restored
            .prepare(100, attempt(&restored, 2, 100), &retry, [3; 32], limits)
            .unwrap(),
        PreparedIngestion::Duplicate
    ));
}

#[test]
fn ingestion_batch_failure_does_not_consume_id_or_partially_count() {
    let limits = IngestionBatchLimits::default();
    let run = run();
    let a = value("A");
    let mut invalid = value("B");
    invalid.id.0[0] ^= 1;
    let first = empty(1, 100);
    let second = empty(2, 100);
    let before = serde_json::to_vec(&(&run, &first, &second)).unwrap();
    let pending = [
        PendingBucketObservation {
            expected_scope: first.bucket.scope,
            previous: &first,
            value: &a,
        },
        PendingBucketObservation {
            expected_scope: second.bucket.scope,
            previous: &second,
            value: &invalid,
        },
    ];
    run.prepare(100, attempt(&run, 1, 100), &pending, [3; 32], limits)
        .unwrap_err();
    assert_eq!(
        before,
        serde_json::to_vec(&(&run, &first, &second)).unwrap()
    );
    let pending = [
        pending[0],
        PendingBucketObservation {
            expected_scope: second.bucket.scope,
            previous: &second,
            value: &a,
        },
    ];
    let PreparedIngestion::Commit { run: next, buckets } = run
        .prepare(100, attempt(&run, 1, 100), &pending, [3; 32], limits)
        .unwrap()
    else {
        panic!("failed batch must leave its ID available")
    };
    assert_eq!(next.sequences.prefix, 1);
    assert!(buckets.iter().all(|bucket| bucket.bucket.counts.total == 1));
    let mut overflow = second.clone();
    overflow.bucket.counts.total = i64::MAX as u64;
    overflow.bucket.counts.untracked = i64::MAX as u64;
    let pending = [
        pending[0],
        PendingBucketObservation {
            expected_scope: overflow.bucket.scope,
            previous: &overflow,
            value: &a,
        },
    ];
    run.prepare(100, attempt(&run, 1, 100), &pending, [3; 32], limits)
        .unwrap_err();
    assert_eq!(run.sequences.prefix, 0);
}

#[test]
fn ingestion_batch_enforces_run_auth_day_and_bucket_ownership() {
    let limits = IngestionBatchLimits::default();
    let run = run();
    let a = value("A");
    let bucket = empty(1, 100);
    let pending = [PendingBucketObservation {
        expected_scope: bucket.bucket.scope,
        previous: &bucket,
        value: &a,
    }];
    let valid = attempt(&run, 1, 100);
    let mut wrong = valid;
    let mut authorized_run = run.clone();
    authorized_run.authorized = true;
    authorized_run
        .prepare(100, wrong, &pending, [3; 32], limits)
        .unwrap_err();
    wrong = valid;
    wrong.observation.run[15] ^= 1;
    run.prepare(100, wrong, &pending, [3; 32], limits)
        .unwrap_err();
    wrong = valid;
    wrong.observation_day = 99;
    let earlier = empty(1, 99);
    run.prepare(
        100,
        wrong,
        &[PendingBucketObservation {
            expected_scope: earlier.bucket.scope,
            previous: &earlier,
            value: &a,
        }],
        [3; 32],
        limits,
    )
    .unwrap_err();
    let future = empty(1, 101);
    run.prepare(
        100,
        attempt(&run, 1, 101),
        &[PendingBucketObservation {
            expected_scope: future.bucket.scope,
            previous: &future,
            value: &a,
        }],
        [3; 32],
        limits,
    )
    .unwrap_err();
    for day in [99, 101] {
        let wrong_bucket = empty(1, day);
        run.prepare(
            100,
            valid,
            &[PendingBucketObservation {
                expected_scope: wrong_bucket.bucket.scope,
                previous: &wrong_bucket,
                value: &a,
            }],
            [3; 32],
            limits,
        )
        .unwrap_err();
    }
    let mut wrong_bucket = bucket.clone();
    wrong_bucket.authorized = true;
    run.prepare(
        100,
        valid,
        &[PendingBucketObservation {
            expected_scope: wrong_bucket.bucket.scope,
            previous: &wrong_bucket,
            value: &a,
        }],
        [3; 32],
        limits,
    )
    .unwrap_err();
    run.prepare(100, valid, &[pending[0], pending[0]], [3; 32], limits)
        .unwrap_err();
    run.prepare(100, valid, &[], [3; 32], limits).unwrap_err();
}

#[test]
fn ingestion_expired_run_cannot_restart_after_checkpoint_pruning() {
    let limits = IngestionBatchLimits::default();
    let run = run();
    assert_eq!(&run.run.0[..4], &[0, 0, 0, 100]);
    assert_eq!(run.run.created_day(), 100);
    let a = value("A");
    let bucket = empty(1, 114);
    let pending = [PendingBucketObservation {
        expected_scope: bucket.bucket.scope,
        previous: &bucket,
        value: &a,
    }];
    run.prepare(114, attempt(&run, 1, 114), &pending, [3; 32], limits)
        .unwrap_err();
    CaptureRunCheckpoint::new(run.run, false, 114, limits).unwrap_err();
    CaptureRunCheckpoint::new(CaptureRunId::new(101, [2; 12]), false, 100, limits).unwrap_err();
    CaptureRunCheckpoint::new(CaptureRunId::new(114, [2; 12]), false, 114, limits).unwrap();
    let valid_bucket = empty(1, 100);
    let pending = [PendingBucketObservation {
        expected_scope: valid_bucket.bucket.scope,
        previous: &valid_bucket,
        value: &a,
    }];
    let mut corrupt = run;
    corrupt.format_version = 2;
    corrupt
        .prepare(100, attempt(&corrupt, 1, 100), &pending, [3; 32], limits)
        .unwrap_err();
    corrupt.format_version = 1;
    corrupt.last_day = 99;
    corrupt
        .prepare(100, attempt(&corrupt, 1, 100), &pending, [3; 32], limits)
        .unwrap_err();
    corrupt.last_day = 101;
    corrupt
        .prepare(100, attempt(&corrupt, 1, 100), &pending, [3; 32], limits)
        .unwrap_err();
}

#[test]
fn ingestion_batch_bounds_total_payload_and_metadata_before_copying() {
    let limits = IngestionBatchLimits::default();
    let run = run();
    let a = value("A");
    let first = empty(1, 100);
    let second = empty(2, 100);
    let pending = [
        PendingBucketObservation {
            expected_scope: first.bucket.scope,
            previous: &first,
            value: &a,
        },
        PendingBucketObservation {
            expected_scope: second.bucket.scope,
            previous: &second,
            value: &a,
        },
    ];
    for limits in [
        IngestionBatchLimits {
            buckets: 1,
            ..limits
        },
        IngestionBatchLimits {
            input_bytes: a.bytes.len(),
            ..limits
        },
        IngestionBatchLimits {
            bucket: ProfileBucketLimits {
                value_bytes: 1,
                input_bytes: 1,
                ..limits.bucket
            },
            ..limits
        },
    ] {
        run.prepare(100, attempt(&run, 1, 100), &pending, [3; 32], limits)
            .unwrap_err();
    }
    let mut oversized = first.clone();
    oversized.bucket.values =
        vec![a.clone(); limits.bucket.literal_values + limits.bucket.samples + 1].into();
    run.prepare(
        100,
        attempt(&run, 1, 100),
        &[PendingBucketObservation {
            expected_scope: oversized.bucket.scope,
            previous: &oversized,
            value: &a,
        }],
        [3; 32],
        limits,
    )
    .unwrap_err();
    let result = run
        .prepare(
            100,
            attempt(&run, 1, 100),
            &pending,
            [3; 32],
            IngestionBatchLimits {
                input_bytes: kib(8),
                retained_bytes: kib(8),
                ..limits
            },
        )
        .unwrap();
    assert!(matches!(result, PreparedIngestion::Commit { .. }));
    assert_eq!(run.sequences.prefix, 0);
}

#[test]
fn ingestion_batch_ten_thousand_observations_keep_bounded_shared_checkpoint() {
    let limits = IngestionBatchLimits {
        bucket: ProfileBucketLimits {
            literal_values: 2,
            samples: 8,
            ..ProfileBucketLimits::default()
        },
        ..IngestionBatchLimits::default()
    };
    let mut run = run();
    let a = value("A");
    let b = value("B");
    let mut buckets = vec![empty(1, 100), empty(2, 100)];
    for sequence in 1..=10_000 {
        let pending = [
            PendingBucketObservation {
                expected_scope: buckets[0].bucket.scope,
                previous: &buckets[0],
                value: if sequence % 2 == 0 { &a } else { &b },
            },
            PendingBucketObservation {
                expected_scope: buckets[1].bucket.scope,
                previous: &buckets[1],
                value: &a,
            },
        ];
        let PreparedIngestion::Commit {
            run: next,
            buckets: next_buckets,
        } = run
            .prepare(100, attempt(&run, sequence, 100), &pending, [3; 32], limits)
            .unwrap()
        else {
            panic!("new sequence must commit")
        };
        run = next;
        buckets = next_buckets.into_vec();
    }
    assert_eq!(run.sequences.prefix, 10_000);
    assert!(run.sequences.completed.is_empty());
    assert_eq!(buckets[0].bucket.values.len(), 2);
    assert_eq!(buckets[1].bucket.values.len(), 1);
    for bucket in &buckets {
        assert_eq!(bucket.bucket.counts.total, 10_000);
        assert_eq!(bucket.bucket.counts.untracked, 0);
        assert_eq!(bucket.bucket.samples.len(), 8);
    }
    for value in &buckets[0].bucket.counts.values {
        assert_eq!(value.count, 5_000);
    }
}

#[test]
fn ingestion_reserves_existing_payloads_before_admitting_any_growth() {
    let a = value("A");
    let limits = IngestionBatchLimits {
        retained_bytes: a.bytes.len(),
        ..IngestionBatchLimits::default()
    };
    let first = empty(2, 100);
    let mut second = empty(3, 100);
    let mut existing = CountedObservationBucket::from_snapshot(
        &second.bucket,
        CanonicalDomain::Headers,
        ValueId([3; 32]),
        [3; 32],
        limits.bucket,
    )
    .unwrap();
    existing
        .observe(
            ObservationId {
                run: [9; 16],
                sequence: 1,
            },
            &a,
        )
        .unwrap();
    second.bucket = existing.snapshot();
    let run = run();
    let pending = [
        PendingBucketObservation {
            expected_scope: first.bucket.scope,
            previous: &first,
            value: &a,
        },
        PendingBucketObservation {
            expected_scope: second.bucket.scope,
            previous: &second,
            value: &a,
        },
    ];
    let (run, buckets) = match run
        .prepare(100, attempt(&run, 1, 100), &pending, [3; 32], limits)
        .unwrap()
    {
        PreparedIngestion::Commit { run, buckets } => Some((run, buckets)),
        PreparedIngestion::Duplicate => None,
    }
    .unwrap();
    assert_eq!(run.sequences.prefix, 1);
    assert_eq!(buckets[0].bucket.counts.total, 1);
    assert_eq!(buckets[0].bucket.counts.losses.retention, 1);
    assert!(buckets[0].bucket.values.is_empty());
    assert_eq!(buckets[1].bucket.counts.total, 2);
    assert_eq!(buckets[1].bucket.counts.losses.retention, 0);
    assert_eq!(buckets[1].bucket.values.len(), 1);
    assert_eq!(second.bucket.counts.total, 1);
}

#[test]
fn version_one_checkpoint_layout_preserves_authorization_run_day_and_ranges() {
    let limits = IngestionBatchLimits::default();
    let mut checkpoint =
        CaptureRunCheckpoint::new(CaptureRunId::new(100, [1; 12]), true, 100, limits).unwrap();
    let mut cursor = IngestionCursor::new(limits.ingestion);
    cursor.record(1).unwrap();
    cursor.record(3).unwrap();
    checkpoint.sequences = cursor.checkpoint();
    let expected = r#"{"format_version":1,"run":[0,0,0,100,1,1,1,1,1,1,1,1,1,1,1,1],"authorized":true,"last_day":100,"sequences":{"prefix":1,"completed":[{"first":3,"last":3}]}}"#;
    assert_eq!(serde_json::to_string(&checkpoint).unwrap(), expected);
    let restored: CaptureRunCheckpoint = serde_json::from_str(expected).unwrap();
    assert_eq!(serde_json::to_string(&restored).unwrap(), expected);
    let mut cursor =
        IngestionCursor::from_checkpoint(&restored.sequences, limits.ingestion).unwrap();
    assert!(matches!(
        cursor.record(2).unwrap(),
        IngestionDisposition::New
    ));
    assert_eq!(cursor.checkpoint().prefix, 3);
}

#[test]
fn ingestion_restores_against_capture_scope_without_consuming_a_rejected_id() {
    let limits = IngestionBatchLimits::default();
    let run = run();
    let previous = empty(2, 100);
    let value = value("A");
    let mut pending = PendingBucketObservation {
        expected_scope: ValueId([9; 32]),
        previous: &previous,
        value: &value,
    };
    run.prepare(100, attempt(&run, 1, 100), &[pending], [3; 32], limits)
        .unwrap_err();
    assert_eq!(run.sequences.prefix, 0);
    assert_eq!(previous.bucket.counts.total, 0);
    pending.expected_scope = ValueId([2; 32]);
    assert!(matches!(
        run.prepare(100, attempt(&run, 1, 100), &[pending], [3; 32], limits)
            .unwrap(),
        PreparedIngestion::Commit { .. }
    ));
}
