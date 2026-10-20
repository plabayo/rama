use crate::profile::capture::completeness::ProfileCaptureCompleteness;
use rama_http::{HeaderMap, HeaderValue, Version};
use rama_utils::octets::kib;

use super::*;
use crate::profile::{capture::headers::HeaderCapturePolicy, evidence::counts::ObservationWeight};

fn value(value: &'static str) -> CanonicalValue {
    let mut headers = HeaderMap::new();
    headers.insert("x-mode", HeaderValue::from_static(value));
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
fn encoded(window: &RetainedBucketWindow) -> Vec<u8> {
    serde_json::to_vec(&window.snapshot()).unwrap()
}

#[test]
fn fourteen_day_window_expires_weights_and_samples_together() {
    let limits = ProfileWindowLimits::default();
    let mut window =
        RetainedBucketWindow::new(CanonicalDomain::Headers, ValueId([2; 32]), [3; 32], limits)
            .unwrap();
    let a = value("A");
    let b = value("B");
    for sequence in 1..=1000 {
        window.observe(100, 100, observation(sequence), &a).unwrap();
    }
    for day in 101..=113 {
        window
            .observe(day, day, observation(1000 + u64::from(day)), &b)
            .unwrap();
    }
    let selected = window.select(113, 14).unwrap();
    assert!(matches!(
        selected.counts().weight(a.id),
        ObservationWeight::Exact(1000)
    ));
    assert!(matches!(
        selected.counts().weight(b.id),
        ObservationWeight::Exact(13)
    ));
    let selected = window.select(114, 14).unwrap();
    assert!(matches!(
        selected.counts().weight(a.id),
        ObservationWeight::Exact(0)
    ));
    assert!(matches!(
        selected.counts().weight(b.id),
        ObservationWeight::Exact(13)
    ));
    for sample in selected.snapshot().samples {
        assert_eq!(sample.value, b.id);
    }
    let restored = RetainedBucketWindow::from_snapshot(
        &window.snapshot(),
        CanonicalDomain::Headers,
        ValueId([2; 32]),
        [3; 32],
        limits,
    )
    .unwrap();
    assert_eq!(encoded(&window), encoded(&restored));
    window.advance(114).unwrap();
    assert_eq!(window.snapshot().buckets.len(), 13);
    window.observe(114, 100, observation(2000), &a).unwrap_err();
    window.select(113, 14).unwrap_err();
    window.select(114, 15).unwrap_err();
    window.advance(127).unwrap();
    assert!(window.snapshot().buckets.is_empty());
    assert_eq!(window.retained_bytes(), 0);
}

#[test]
fn selection_preserves_exact_literals_across_disjoint_days() {
    let limits = ProfileWindowLimits {
        bucket: ProfileBucketLimits {
            literal_values: 1,
            samples: 0,
            ..ProfileBucketLimits::default()
        },
        ..ProfileWindowLimits::default()
    };
    let mut window =
        RetainedBucketWindow::new(CanonicalDomain::Headers, ValueId([2; 32]), [3; 32], limits)
            .unwrap();
    let (mut a, mut b) = (value("A"), value("B"));
    if a.id < b.id {
        std::mem::swap(&mut a, &mut b);
    }
    for sequence in 1..=1000 {
        window.observe(100, 100, observation(sequence), &a).unwrap();
    }
    window.observe(101, 101, observation(1001), &b).unwrap();
    let selected = window.select(101, 14).unwrap();
    assert!(matches!(
        selected.counts().weight(a.id),
        ObservationWeight::Exact(1000)
    ));
    assert!(matches!(
        selected.counts().weight(b.id),
        ObservationWeight::Exact(1)
    ));
    assert_eq!(selected.snapshot().counts.untracked, 0);
    let mut all = CountedObservationBucket::new(
        CanonicalDomain::Headers,
        ValueId([2; 32]),
        [3; 32],
        ProfileBucketLimits {
            literal_values: 2,
            ..limits.bucket
        },
    )
    .unwrap();
    for sequence in 1..=1000 {
        all.observe(observation(sequence), &a).unwrap();
    }
    all.observe(observation(1001), &b).unwrap();
    assert_eq!(
        serde_json::to_vec(&selected.snapshot()).unwrap(),
        serde_json::to_vec(&all.snapshot()).unwrap()
    );
}

#[test]
fn window_byte_limit_counts_losses_and_expiration_frees_capacity() {
    let a = value("A");
    let limits = ProfileWindowLimits {
        retained_bytes: a.bytes.len(),
        ..ProfileWindowLimits::default()
    };
    let mut window =
        RetainedBucketWindow::new(CanonicalDomain::Headers, ValueId([2; 32]), [3; 32], limits)
            .unwrap();
    window.observe(100, 100, observation(1), &a).unwrap();
    window.observe(101, 101, observation(2), &a).unwrap();
    let counts = window.select(101, 14).unwrap().snapshot().counts;
    assert_eq!(counts.total, 2);
    assert_eq!(counts.untracked, 1);
    assert_eq!(counts.losses.retention, 1);
    assert_eq!(window.retained_bytes(), a.bytes.len());
    window.observe(114, 114, observation(3), &a).unwrap();
    assert_eq!(window.snapshot().buckets.len(), 2);
    let retained = window.select(114, 14).unwrap().snapshot();
    assert_eq!(retained.counts.total, 2);
    assert_eq!(retained.counts.losses.retention, 1);
    window.advance(115).unwrap();
    assert_eq!(window.snapshot().buckets.len(), 1);
    assert_eq!(window.retained_bytes(), a.bytes.len());
    assert!(matches!(
        window.select(115, 14).unwrap().counts().weight(a.id),
        ObservationWeight::Exact(1)
    ));
}

#[test]
fn merging_near_budget_scopes_trims_old_samples_and_keeps_counts() {
    let values: Vec<_> = (0..16)
        .map(|index| {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-mode",
                HeaderValue::from_str(&format!("{index:0>64}")).unwrap(),
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
        })
        .collect();
    let size = values[0].bytes.len();
    let limits = ProfileWindowLimits {
        retained_bytes: size * 10,
        bucket: ProfileBucketLimits {
            literal_values: 1,
            ..ProfileBucketLimits::default()
        },
        ..ProfileWindowLimits::default()
    };
    let window = |day: u32, run: u8| {
        let mut window =
            RetainedBucketWindow::new(CanonicalDomain::Headers, ValueId([2; 32]), [3; 32], limits)
                .unwrap();
        for (sequence, value) in (1..).zip(&values[..8]) {
            let observation = ObservationId {
                run: [run; 16],
                sequence,
            };
            window.observe(day, day, observation, value).unwrap();
        }
        window
    };
    let older = window(100, 1);
    let newer = window(101, 2);
    assert_eq!(older.retained_bytes(), size * 8);
    let merged = older.merge_scope(&newer).unwrap();
    assert!(merged.retained_bytes() <= limits.retained_bytes);
    let snapshot = merged.snapshot();
    assert_eq!(snapshot.buckets[0].bucket.samples.len(), 2);
    assert_eq!(snapshot.buckets[1].bucket.samples.len(), 8);
    assert_eq!(merged.select(101, 14).unwrap().snapshot().counts.total, 16);
}

#[test]
fn window_restore_rejects_scope_aliases_duplicate_days_and_future_data() {
    let limits = ProfileWindowLimits::default();
    let mut window =
        RetainedBucketWindow::new(CanonicalDomain::Headers, ValueId([2; 32]), [3; 32], limits)
            .unwrap();
    window
        .observe(100, 100, observation(1), &value("A"))
        .unwrap();
    let mut snapshot = window.snapshot();
    let mut other_scope = CountedObservationBucket::new(
        CanonicalDomain::Headers,
        ValueId([9; 32]),
        [3; 32],
        limits.bucket,
    )
    .unwrap();
    other_scope.observe(observation(1), &value("A")).unwrap();
    snapshot.buckets[0].bucket = other_scope.snapshot();
    RetainedBucketWindow::from_snapshot(
        &snapshot,
        CanonicalDomain::Headers,
        ValueId([2; 32]),
        [3; 32],
        limits,
    )
    .unwrap_err();
    let mut snapshot = window.snapshot();
    snapshot.buckets = vec![snapshot.buckets[0].clone(); 2].into();
    RetainedBucketWindow::from_snapshot(
        &snapshot,
        CanonicalDomain::Headers,
        ValueId([2; 32]),
        [3; 32],
        limits,
    )
    .unwrap_err();
    let mut snapshot = window.snapshot();
    snapshot.buckets[0].day = 101;
    RetainedBucketWindow::from_snapshot(
        &snapshot,
        CanonicalDomain::Headers,
        ValueId([2; 32]),
        [3; 32],
        limits,
    )
    .unwrap_err();
    snapshot.buckets[0].day = 86;
    RetainedBucketWindow::from_snapshot(
        &snapshot,
        CanonicalDomain::Headers,
        ValueId([2; 32]),
        [3; 32],
        limits,
    )
    .unwrap_err();
    let limits = ProfileWindowLimits {
        retained_bytes: 0,
        ..limits
    };
    RetainedBucketWindow::from_snapshot(
        &window.snapshot(),
        CanonicalDomain::Headers,
        ValueId([2; 32]),
        [3; 32],
        limits,
    )
    .unwrap_err();
}

#[test]
fn default_window_saturation_counts_the_next_observation_and_drop() {
    let limits = ProfileWindowLimits::default();
    let policy = HeaderCapturePolicy::default();
    let mut window =
        RetainedBucketWindow::new(CanonicalDomain::Headers, ValueId([2; 32]), [3; 32], limits)
            .unwrap();
    let mut sequence = 0u64;
    let mut last = None;
    for day in 100..=113 {
        for _ in 0..200 {
            sequence += 1;
            let mut bytes = vec![b'a'; kib(15)];
            bytes[..16].copy_from_slice(format!("{sequence:016x}").as_bytes());
            let mut headers = HeaderMap::new();
            headers.insert("accept", HeaderValue::from_bytes(&bytes).unwrap());
            let value = policy
                .capture(
                    ProfileCaptureCompleteness::Complete,
                    Version::HTTP_11,
                    &headers,
                    None,
                )
                .unwrap()
                .canonical(&policy)
                .unwrap();
            window
                .observe(day, day, observation(sequence), &value)
                .unwrap();
            last = Some(value);
        }
    }
    let before = window.select(113, 14).unwrap().snapshot();
    assert_eq!(before.counts.total, sequence);
    assert!(before.counts.losses.retention > 0);
    window
        .observe(113, 113, observation(sequence + 1), &last.unwrap())
        .unwrap();
    let after = window.select(113, 14).unwrap().snapshot();
    assert_eq!(after.counts.total, sequence + 1);
    assert_eq!(
        after.counts.losses.retention,
        before.counts.losses.retention + 1
    );
    assert!(window.retained_bytes() <= limits.retained_bytes);
    let restored = RetainedBucketWindow::from_snapshot(
        &window.snapshot(),
        CanonicalDomain::Headers,
        ValueId([2; 32]),
        [3; 32],
        limits,
    )
    .unwrap();
    assert_eq!(encoded(&window), encoded(&restored));
}

#[test]
fn window_restoration_requires_expected_identity_even_without_day_buckets() {
    let limits = ProfileWindowLimits::default();
    let scope = ValueId([2; 32]);
    let mut window =
        RetainedBucketWindow::new(CanonicalDomain::Headers, scope, [3; 32], limits).unwrap();
    for populated in [false, true] {
        if populated {
            window
                .observe(100, 100, observation(1), &value("A"))
                .unwrap();
        }
        let snapshot = window.snapshot();
        RetainedBucketWindow::from_snapshot(
            &snapshot,
            CanonicalDomain::Headers,
            ValueId([9; 32]),
            [3; 32],
            limits,
        )
        .unwrap_err();
        RetainedBucketWindow::from_snapshot(
            &snapshot,
            CanonicalDomain::Order,
            scope,
            [3; 32],
            limits,
        )
        .unwrap_err();
        let restored = RetainedBucketWindow::from_snapshot(
            &snapshot,
            CanonicalDomain::Headers,
            scope,
            [3; 32],
            limits,
        )
        .unwrap();
        assert_eq!(encoded(&restored), encoded(&window));
    }
}

#[test]
fn version_one_snapshot_layouts_keep_numeric_domains_and_explicit_coverage() {
    let limits = ProfileWindowLimits::default();
    let scope = ValueId([2; 32]);
    let window =
        RetainedBucketWindow::new(CanonicalDomain::Headers, scope, [3; 32], limits).unwrap();
    let bucket =
        CountedObservationBucket::new(CanonicalDomain::Headers, scope, [3; 32], limits.bucket)
            .unwrap();
    let bucket_json = r#"{"format_version":1,"domain":1,"scope":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"counts":{"total":0,"untracked":0,"values":[],"losses":{"oversize":0,"retention":0,"history_known":true},"untracked_distinct":{"values":[],"saturated":false,"history_known":true}},"samples":[],"values":[]}"#;
    let window_json = r#"{"format_version":1,"domain":1,"scope":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"last_day":0,"buckets":[]}"#;
    assert_eq!(
        serde_json::to_string(&bucket.snapshot()).unwrap(),
        bucket_json
    );
    assert_eq!(
        serde_json::to_string(&window.snapshot()).unwrap(),
        window_json
    );
    let restored = CountedObservationBucket::from_snapshot(
        &serde_json::from_str(bucket_json).unwrap(),
        CanonicalDomain::Headers,
        scope,
        [3; 32],
        limits.bucket,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_string(&restored.snapshot()).unwrap(),
        bucket_json
    );
    let restored = RetainedBucketWindow::from_snapshot(
        &serde_json::from_str(window_json).unwrap(),
        CanonicalDomain::Headers,
        scope,
        [3; 32],
        limits,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_string(&restored.snapshot()).unwrap(),
        window_json
    );
}
