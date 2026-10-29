use crate::profile::capture::completeness::ProfileCaptureCompleteness;
use rama_http::{HeaderMap, HeaderValue, Version};

use super::*;
use crate::profile::{
    capture::headers::HeaderCapturePolicy,
    evidence::counts::{LiteralCount, ObservationLosses, ObservationWeight},
    format::canonical::{CanonicalWriter, edited},
    model::{identity::ConnectionContext, scope::ProfileObservationScope},
};

fn canonical(value: u64) -> CanonicalValue {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-value",
        HeaderValue::from_str(&value.to_string()).unwrap(),
    );
    let policy = HeaderCapturePolicy::default();
    policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &headers,
            None,
        )
        .unwrap()
        .canonical(&policy)
        .unwrap()
}
fn observation(sequence: u64) -> ObservationId {
    ObservationId {
        run: [1; 16],
        sequence,
    }
}
fn encoded(bucket: &CountedObservationBucket) -> Vec<u8> {
    serde_json::to_vec(&bucket.snapshot()).unwrap()
}

#[test]
fn counting_bucket_bounds_random_values_and_reclaims_evictions() {
    let limits = ProfileBucketLimits {
        literal_values: 4,
        samples: 16,
        ..ProfileBucketLimits::default()
    };
    let mut bucket =
        CountedObservationBucket::new(CanonicalDomain::Headers, ValueId([2; 32]), [3; 32], limits)
            .unwrap();
    for sequence in 1..=10_000 {
        bucket
            .observe(observation(sequence), &canonical(sequence))
            .unwrap();
    }
    let snapshot = bucket.snapshot();
    assert_eq!(snapshot.counts.total, 10_000);
    assert_eq!(snapshot.counts.values.len(), 4);
    assert_eq!(snapshot.counts.untracked, 9996);
    assert_eq!(snapshot.samples.len(), 16);
    assert!(snapshot.values.len() <= 20);
    let ids = references(&bucket.counts, &bucket.samples);
    assert_eq!(ids.len(), snapshot.values.len());
    let restored = CountedObservationBucket::from_snapshot(
        &snapshot,
        CanonicalDomain::Headers,
        ValueId([2; 32]),
        [3; 32],
        limits,
    )
    .unwrap();
    assert_eq!(encoded(&bucket), encoded(&restored));
}

#[test]
fn counting_bucket_failure_does_not_update_counts_samples_or_dictionary() {
    let value = canonical(1);
    let limits = ProfileBucketLimits {
        retained_bytes: value.bytes.len(),
        ..ProfileBucketLimits::default()
    };
    let mut bucket =
        CountedObservationBucket::new(CanonicalDomain::Headers, ValueId([2; 32]), [3; 32], limits)
            .unwrap();
    bucket.observe(observation(1), &value).unwrap();
    let before = encoded(&bucket);

    bucket.observe(observation(0), &value).unwrap_err();
    let mut corrupt = value.clone();
    corrupt.id.0[0] ^= 1;
    bucket.observe(observation(2), &corrupt).unwrap_err();
    assert_eq!(before, encoded(&bucket));
    bucket.observe(observation(2), &value).unwrap();
    assert_eq!(bucket.snapshot().values.len(), 1);
    assert!(matches!(
        bucket.counts().weight(value.id),
        ObservationWeight::Exact(2)
    ));
    let mut snapshot = bucket.snapshot();
    snapshot.values[0].bytes = edited(&snapshot.values[0].bytes, |bytes| bytes[0] ^= 1);
    CountedObservationBucket::from_snapshot(
        &snapshot,
        CanonicalDomain::Headers,
        ValueId([2; 32]),
        [3; 32],
        limits,
    )
    .unwrap_err();
    let mut snapshot = bucket.snapshot();
    snapshot.values = Box::default();
    CountedObservationBucket::from_snapshot(
        &snapshot,
        CanonicalDomain::Headers,
        ValueId([2; 32]),
        [3; 32],
        limits,
    )
    .unwrap_err();
    let mut snapshot = bucket.snapshot();
    snapshot.format_version = 2;
    CountedObservationBucket::from_snapshot(
        &snapshot,
        CanonicalDomain::Headers,
        ValueId([2; 32]),
        [3; 32],
        limits,
    )
    .unwrap_err();
    snapshot.format_version = 1;
    snapshot.domain = CanonicalDomain::Profile;
    CountedObservationBucket::from_snapshot(
        &snapshot,
        CanonicalDomain::Headers,
        ValueId([2; 32]),
        [3; 32],
        limits,
    )
    .unwrap_err();
}

#[test]
fn counting_bucket_merge_reuses_values_and_keeps_joint_sample_identity() {
    let limits = ProfileBucketLimits {
        literal_values: 2,
        samples: 16,
        ..ProfileBucketLimits::default()
    };
    let mut left =
        CountedObservationBucket::new(CanonicalDomain::Headers, ValueId([2; 32]), [3; 32], limits)
            .unwrap();
    let mut right = left.clone();
    let a = canonical(1);
    let b = canonical(2);
    for sequence in 1..=1000 {
        if sequence % 2 == 0 {
            left.observe(observation(sequence), &a).unwrap();
        } else {
            right.observe(observation(sequence), &b).unwrap();
        }
    }
    let merged = left.merge(&right).unwrap();
    assert_eq!(encoded(&merged), encoded(&right.merge(&left).unwrap()));
    assert_eq!(merged.snapshot().values.len(), 2);
    assert!(matches!(
        merged.counts().weight(a.id),
        ObservationWeight::Exact(500)
    ));
    assert!(matches!(
        merged.counts().weight(b.id),
        ObservationWeight::Exact(500)
    ));
    for sample in merged.samples.entries() {
        assert_eq!(
            sample.value,
            if sample.observation.sequence % 2 == 0 {
                a.id
            } else {
                b.id
            }
        );
    }
}

#[test]
fn valid_digest_cannot_smuggle_request_values_into_retained_storage() {
    let limits = ProfileBucketLimits::default();
    let scope = ValueId([2; 32]);
    let mut writer = CanonicalWriter::new(CanonicalDomain::Headers, limits.value_bytes).unwrap();
    writer.u8(2).unwrap();
    writer.u8(1).unwrap();
    writer.u64(1).unwrap();
    writer.bytes(b"cookie").unwrap();
    writer.u32(0).unwrap();
    writer.u8(0).unwrap();
    writer.u8(0).unwrap();
    writer.u8(0).unwrap();
    writer.bytes(b"request-value-canary").unwrap();
    let forged = writer.finish();
    forged
        .verify(CanonicalDomain::Headers, limits.value_bytes)
        .unwrap();
    let mut bucket =
        CountedObservationBucket::new(CanonicalDomain::Headers, scope, [3; 32], limits).unwrap();
    bucket.observe(observation(1), &forged).unwrap_err();
    assert_eq!(bucket.snapshot().counts.total, 0);
    assert_eq!(bucket.retained_bytes(), 0);
    let snapshot = CountedBucketSnapshot {
        format_version: 1,
        domain: CanonicalDomain::Headers,
        scope,
        counts: CounterSnapshot {
            untracked_distinct: Default::default(),
            losses: ObservationLosses {
                history_known: true,
                ..ObservationLosses::default()
            },
            total: 1,
            untracked: 0,
            values: vec![LiteralCount {
                value: forged.id,
                count: 1,
            }]
            .into(),
        },
        samples: Box::default(),
        values: vec![forged].into(),
    };
    CountedObservationBucket::from_snapshot(
        &snapshot,
        CanonicalDomain::Headers,
        ValueId([2; 32]),
        [3; 32],
        limits,
    )
    .unwrap_err();
    CanonicalDomain::try_from(u16::MAX).unwrap_err();
    let mut unknown = CanonicalWriter::new(CanonicalDomain::Headers, limits.value_bytes)
        .unwrap()
        .finish();
    unknown.bytes = edited(&unknown.bytes, |bytes| {
        bytes[15..17].copy_from_slice(&u16::MAX.to_be_bytes());
    });
    unknown.validated_domain(limits.value_bytes).unwrap_err();
}

#[test]
fn valid_oversize_values_count_without_retention_or_secret_bypass() {
    let limits = ProfileBucketLimits::default();
    let policy = HeaderCapturePolicy::default();
    let mut headers = HeaderMap::new();
    headers.insert(
        "accept",
        HeaderValue::from_bytes(&vec![b'a'; kib(20)]).unwrap(),
    );
    let large = policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            &headers,
            None,
        )
        .unwrap()
        .canonical(&policy)
        .unwrap();
    assert!(large.bytes.len() > limits.value_bytes && large.bytes.len() <= limits.input_bytes);
    let mut bucket =
        CountedObservationBucket::new(CanonicalDomain::Headers, ValueId([2; 32]), [3; 32], limits)
            .unwrap();
    bucket.observe(observation(1), &large).unwrap();
    let snapshot = bucket.snapshot();
    assert_eq!(snapshot.counts.total, 1);
    assert_eq!(snapshot.counts.untracked, 1);
    assert_eq!(snapshot.counts.losses.oversize, 1);
    assert!(snapshot.samples.is_empty() && snapshot.values.is_empty());
    assert_eq!(bucket.retained_bytes(), 0);
    CountedObservationBucket::from_snapshot(
        &snapshot,
        CanonicalDomain::Headers,
        ValueId([2; 32]),
        [3; 32],
        limits,
    )
    .unwrap();
    let before = encoded(&bucket);
    let mut writer = CanonicalWriter::new(CanonicalDomain::Headers, limits.input_bytes).unwrap();
    writer.u8(2).unwrap();
    writer.u8(1).unwrap();
    writer.u64(1).unwrap();
    writer.bytes(b"cookie").unwrap();
    writer.u32(0).unwrap();
    writer.u8(0).unwrap();
    writer.u8(0).unwrap();
    writer.u8(0).unwrap();
    writer.bytes(&vec![b's'; kib(20)]).unwrap();
    let secret = writer.finish();
    secret
        .verify(CanonicalDomain::Headers, limits.input_bytes)
        .unwrap();
    bucket.observe(observation(2), &secret).unwrap_err();
    bucket.observe(observation(0), &large).unwrap_err();
    let mut forged = large;
    forged.id.0[0] ^= 1;
    bucket.observe(observation(2), &forged).unwrap_err();
    assert_eq!(before, encoded(&bucket));
    let invalid = ProfileBucketLimits {
        input_bytes: 1,
        ..limits
    };
    invalid.validate().unwrap_err();
    CountedObservationBucket::new(CanonicalDomain::Headers, ValueId([2; 32]), [3; 32], invalid)
        .unwrap_err();
}

#[test]
fn retention_losses_preserve_payloads_and_restore_requires_full_eligible_samples() {
    let a = canonical(1);
    let limits = ProfileBucketLimits {
        retained_bytes: a.bytes.len(),
        ..ProfileBucketLimits::default()
    };
    let mut bucket =
        CountedObservationBucket::new(CanonicalDomain::Headers, ValueId([2; 32]), [3; 32], limits)
            .unwrap();
    bucket.observe(observation(1), &a).unwrap();
    bucket.observe(observation(2), &canonical(2)).unwrap();
    let snapshot = bucket.snapshot();
    assert_eq!(snapshot.counts.total, 2);
    assert_eq!(snapshot.counts.untracked, 1);
    assert_eq!(snapshot.counts.losses.retention, 1);
    assert_eq!(snapshot.samples.len(), 1);
    assert_eq!(snapshot.values.len(), 1);
    assert_eq!(snapshot.values[0].id, a.id);
    let mut restored = CountedObservationBucket::from_snapshot(
        &snapshot,
        CanonicalDomain::Headers,
        ValueId([2; 32]),
        [3; 32],
        limits,
    )
    .unwrap();
    restored.observe(observation(3), &a).unwrap();
    assert_eq!(restored.snapshot().counts.total, 3);
    assert_eq!(restored.snapshot().samples.len(), 2);
    let mut incomplete = snapshot;
    incomplete.samples = Box::default();
    CountedObservationBucket::from_snapshot(
        &incomplete,
        CanonicalDomain::Headers,
        ValueId([2; 32]),
        [3; 32],
        limits,
    )
    .unwrap_err();
    incomplete.counts.losses.history_known = false;
    let imported = CountedObservationBucket::from_snapshot(
        &incomplete,
        CanonicalDomain::Headers,
        ValueId([2; 32]),
        [3; 32],
        limits,
    )
    .unwrap();
    assert!(matches!(
        imported.counts().weight(a.id),
        ObservationWeight::UnknownHistory { .. }
    ));
}

#[test]
fn restored_bucket_requires_the_expected_domain_and_authorization_scope() {
    let limits = ProfileBucketLimits::default();
    let mut scope = ProfileObservationScope {
        authorized: false,
        profile: ValueId([1; 32]),
        flow: None,
        connection: ConnectionContext::default(),
        structure: ValueId([2; 32]),
    };
    let public = scope.canonical(limits.input_bytes).unwrap().id;
    scope.authorized = true;
    let authorized = scope.canonical(limits.input_bytes).unwrap().id;
    assert_ne!(public, authorized);
    let mut bucket =
        CountedObservationBucket::new(CanonicalDomain::Headers, public, [3; 32], limits).unwrap();
    bucket.observe(observation(1), &canonical(1)).unwrap();
    let snapshot = bucket.snapshot();
    CountedObservationBucket::from_snapshot(
        &snapshot,
        CanonicalDomain::Headers,
        authorized,
        [3; 32],
        limits,
    )
    .unwrap_err();
    CountedObservationBucket::from_snapshot(
        &snapshot,
        CanonicalDomain::Order,
        public,
        [3; 32],
        limits,
    )
    .unwrap_err();
    let restored = CountedObservationBucket::from_snapshot(
        &snapshot,
        CanonicalDomain::Headers,
        public,
        [3; 32],
        limits,
    )
    .unwrap();
    assert_eq!(encoded(&restored), encoded(&bucket));
}
