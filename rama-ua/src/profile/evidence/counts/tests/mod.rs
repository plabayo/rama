use super::*;

fn value(number: u8) -> ValueId {
    ValueId([number; 32])
}
fn encoded(counts: &LiteralCounters) -> Vec<u8> {
    serde_json::to_vec(&counts.snapshot()).unwrap()
}

#[test]
fn literal_counters_keep_exact_totals_with_bounded_retention() {
    let mut counts = LiteralCounters::new(2);
    for index in 0..10_000 {
        counts.observe(value((index % 5) as u8)).unwrap();
    }
    let snapshot = counts.snapshot();
    assert_eq!(snapshot.total, 10_000);
    assert_eq!(snapshot.untracked, 6000);
    assert_eq!(snapshot.values.len(), 2);
    assert!(matches!(
        counts.weight(value(0)),
        ObservationWeight::LowerBound {
            observed: 2000,
            unassigned: 6000
        }
    ));
    assert!(matches!(
        counts.weight(value(9)),
        ObservationWeight::LowerBound {
            observed: 0,
            unassigned: 6000
        }
    ));
    let restored = LiteralCounters::from_snapshot(&snapshot, 2).unwrap();
    assert_eq!(encoded(&counts), encoded(&restored));
    let mut fixed = LiteralCounters::new(2);
    for _ in 0..10_000 {
        fixed.observe(value(1)).unwrap();
    }
    assert!(matches!(
        fixed.weight(value(1)),
        ObservationWeight::Exact(10_000)
    ));
    assert!(matches!(
        fixed.weight(value(2)),
        ObservationWeight::Exact(0)
    ));
    let mut disabled = LiteralCounters::new(0);
    disabled.observe(value(1)).unwrap();
    assert_eq!(disabled.snapshot().untracked, 1);
}

#[test]
fn coarsening_sums_counts_without_claiming_unretained_history_is_exact() {
    let mut left = LiteralCounters::new(2);
    let mut right = LiteralCounters::new(2);
    for number in [1, 2, 1, 3] {
        left.observe(value(number)).unwrap();
    }
    for number in [3, 2, 1, 3] {
        right.observe(value(number)).unwrap();
    }
    let merged = left.merge(&right).unwrap();
    assert_eq!(encoded(&merged), encoded(&right.merge(&left).unwrap()));
    assert_eq!(merged.snapshot().total, 8);
    assert_eq!(merged.snapshot().untracked, 3);
    assert!(matches!(
        merged.weight(value(1)),
        ObservationWeight::LowerBound {
            observed: 3,
            unassigned: 3
        }
    ));
    assert!(matches!(
        merged.weight(value(2)),
        ObservationWeight::LowerBound {
            observed: 2,
            unassigned: 3
        }
    ));
    // Untracked values remain explicitly separate from the retained counts.
    let mut a = LiteralCounters::new(4);
    let mut b = LiteralCounters::new(4);
    for number in [1, 2, 1, 3] {
        a.observe(value(number)).unwrap();
    }
    for number in [3, 2, 1, 3] {
        b.observe(value(number)).unwrap();
    }
    let complete = a.merge(&b).unwrap();
    assert!(matches!(
        complete.weight(value(1)),
        ObservationWeight::Exact(3)
    ));
    assert!(matches!(
        complete.weight(value(2)),
        ObservationWeight::Exact(2)
    ));
    assert!(matches!(
        complete.weight(value(3)),
        ObservationWeight::Exact(3)
    ));
    a.merge(&left).unwrap_err();
}

#[test]
fn literal_bottom_k_is_independent_of_delivery_and_partitioning() {
    for capacity in [0, 1, 2, 3] {
        let mut expected = None;
        for order in [
            [1, 2, 3],
            [1, 3, 2],
            [2, 1, 3],
            [2, 3, 1],
            [3, 1, 2],
            [3, 2, 1],
        ] {
            let mut counts = LiteralCounters::new(capacity);
            for number in order {
                for _ in 0..number {
                    counts.observe(value(number)).unwrap();
                }
            }
            if let Some(expected) = &expected {
                assert_eq!(&encoded(&counts), expected);
            } else {
                expected = Some(encoded(&counts));
            }
        }
        let mut all = LiteralCounters::new(capacity);
        let mut left = LiteralCounters::new(capacity);
        let mut right = LiteralCounters::new(capacity);
        for (index, number) in [3, 1, 2, 1, 2, 3, 1, 2].into_iter().enumerate() {
            all.observe(value(number)).unwrap();
            if index < 4 {
                left.observe(value(number)).unwrap();
            } else {
                right.observe(value(number)).unwrap();
            }
        }
        assert_eq!(encoded(&left.merge(&right).unwrap()), encoded(&all));
    }
}

#[test]
fn coarsening_preserves_exact_day_counts_and_is_associative() {
    let mut a = LiteralCounters::new(1);
    let mut b = LiteralCounters::new(1);
    let mut c = LiteralCounters::new(1);
    for _ in 0..1000 {
        a.observe(value(3)).unwrap();
    }
    b.observe(value(1)).unwrap();
    c.observe(value(2)).unwrap();
    let ab = a.coarsen(&b).unwrap();
    assert!(matches!(
        ab.weight(value(3)),
        ObservationWeight::Exact(1000)
    ));
    assert!(matches!(ab.weight(value(1)), ObservationWeight::Exact(1)));
    assert_eq!(
        encoded(&ab.coarsen(&c).unwrap()),
        encoded(&a.coarsen(&b.coarsen(&c).unwrap()).unwrap())
    );
    let mut all = LiteralCounters::new(3);
    for _ in 0..1000 {
        all.observe(value(3)).unwrap();
    }
    for number in [1, 2] {
        all.observe(value(number)).unwrap();
    }
    assert_eq!(encoded(&ab.coarsen(&c).unwrap()), encoded(&all));
}

#[test]
fn counters_reject_corrupt_snapshots_and_bigint_overflow_without_mutation() {
    let snapshot = CounterSnapshot {
        untracked_distinct: UntrackedDistinctSnapshot::default(),
        losses: ObservationLosses {
            history_known: true,
            ..ObservationLosses::default()
        },
        total: MAXIMUM_COUNT,
        untracked: 0,
        values: vec![LiteralCount {
            value: value(1),
            count: MAXIMUM_COUNT,
        }]
        .into(),
    };
    let mut full = LiteralCounters::from_snapshot(&snapshot, 2).unwrap();
    let before = encoded(&full);
    full.observe(value(1)).unwrap_err();
    full.observe(value(2)).unwrap_err();
    assert_eq!(before, encoded(&full));
    full.merge(&full).unwrap_err();
    assert_eq!(before, encoded(&full));
    let mut invalid = snapshot;
    invalid.total -= 1;
    LiteralCounters::from_snapshot(&invalid, 2).unwrap_err();
    invalid.total = 0;
    invalid.values[0].count = 0;
    LiteralCounters::from_snapshot(&invalid, 2).unwrap_err();
    invalid.values[0].count = u64::MAX;
    invalid.total = u64::MAX;
    LiteralCounters::from_snapshot(&invalid, 2).unwrap_err();
    let mut duplicate = CounterSnapshot {
        untracked_distinct: UntrackedDistinctSnapshot::default(),
        losses: ObservationLosses {
            history_known: true,
            ..ObservationLosses::default()
        },
        total: 2,
        untracked: 0,
        values: vec![
            LiteralCount {
                value: value(1),
                count: 1
            };
            2
        ]
        .into(),
    };
    LiteralCounters::from_snapshot(&duplicate, 2).unwrap_err();
    duplicate.values[1].value = value(2);
    LiteralCounters::from_snapshot(&duplicate, 1).unwrap_err();
    duplicate.values.reverse();
    LiteralCounters::from_snapshot(&duplicate, 2).unwrap_err();
}

#[test]
fn loss_counts_validate_merge_and_preserve_unknown_import_history() {
    let mut a = LiteralCounters::new(1);
    a.observe(value(1)).unwrap();
    a.observe_unretained(value(2), ObservationLoss::Oversize)
        .unwrap();
    let mut b = LiteralCounters::new(1);
    b.observe_unretained(value(2), ObservationLoss::Retention)
        .unwrap();
    let merged = a.coarsen(&b).unwrap();
    let snapshot = merged.snapshot();
    assert_eq!(snapshot.total, 3);
    assert_eq!(snapshot.untracked, 2);
    assert_eq!(snapshot.losses.oversize, 1);
    assert_eq!(snapshot.losses.retention, 1);
    assert!(snapshot.losses.history_known);
    assert!(matches!(
        merged.weight(value(1)),
        ObservationWeight::LowerBound {
            observed: 1,
            unassigned: 2
        }
    ));
    let mut corrupt = snapshot.clone();
    corrupt.losses.retention = 2;
    LiteralCounters::from_snapshot(&corrupt, 2).unwrap_err();
    corrupt.losses.oversize = u64::MAX;
    LiteralCounters::from_snapshot(&corrupt, 2).unwrap_err();
    let mut old = serde_json::to_value(snapshot).unwrap();
    old.as_object_mut().unwrap().remove("losses");
    let imported =
        LiteralCounters::from_snapshot(&serde_json::from_value(old).unwrap(), 2).unwrap();
    assert!(matches!(
        imported.weight(value(1)),
        ObservationWeight::UnknownHistory {
            observed: 1,
            unassigned: 2
        }
    ));
    assert!(
        !imported
            .coarsen(&b)
            .unwrap()
            .snapshot()
            .losses
            .history_known
    );
    let full = CounterSnapshot {
        untracked_distinct: UntrackedDistinctSnapshot::default(),
        total: MAXIMUM_COUNT,
        untracked: MAXIMUM_COUNT,
        values: Box::default(),
        losses: ObservationLosses {
            retention: MAXIMUM_COUNT,
            history_known: true,
            ..ObservationLosses::default()
        },
    };
    let mut full = LiteralCounters::from_snapshot(&full, 1).unwrap();
    let before = encoded(&full);
    full.observe_unretained(value(2), ObservationLoss::Retention)
        .unwrap_err();
    full.observe_unretained(value(2), ObservationLoss::Oversize)
        .unwrap_err();
    assert_eq!(before, encoded(&full));
}

#[test]
fn untracked_distinct_includes_evicted_values_and_losses_without_counting_repeats() {
    let mut counts = LiteralCounters::new(1);
    for _ in 0..10_000 {
        counts.observe(value(3)).unwrap();
    }
    assert!(matches!(
        counts.untracked_distinct(),
        UntrackedDistinctCount::Exact(0)
    ));
    counts.observe(value(1)).unwrap();
    assert!(matches!(
        counts.untracked_distinct(),
        UntrackedDistinctCount::Exact(1)
    ));
    counts.observe(value(3)).unwrap();
    assert!(matches!(
        counts.untracked_distinct(),
        UntrackedDistinctCount::Exact(1)
    ));
    counts
        .observe_unretained(value(2), ObservationLoss::Oversize)
        .unwrap();
    counts
        .observe_unretained(value(2), ObservationLoss::Retention)
        .unwrap();
    assert!(matches!(
        counts.untracked_distinct(),
        UntrackedDistinctCount::Exact(2)
    ));
    let mut lower = LiteralCounters::new(1);
    lower.observe(value(0)).unwrap();
    assert!(matches!(
        counts.merge(&lower).unwrap().untracked_distinct(),
        UntrackedDistinctCount::Exact(3)
    ));
    assert!(matches!(
        counts.coarsen(&lower).unwrap().untracked_distinct(),
        UntrackedDistinctCount::Exact(2)
    ));
    assert!(matches!(
        LiteralCounters::from_snapshot(&counts.snapshot(), 1)
            .unwrap()
            .untracked_distinct(),
        UntrackedDistinctCount::Exact(2)
    ));
}

#[test]
fn old_counter_snapshots_never_acquire_complete_distinct_history() {
    let mut counts = LiteralCounters::new(0);
    counts.observe(value(1)).unwrap();
    let mut json = serde_json::to_value(counts.snapshot()).unwrap();
    json.as_object_mut().unwrap().remove("untracked_distinct");
    let old = LiteralCounters::from_snapshot(&serde_json::from_value(json).unwrap(), 0).unwrap();
    assert!(matches!(
        old.untracked_distinct(),
        UntrackedDistinctCount::UnknownHistory { at_least: 0 }
    ));
    assert!(matches!(
        old.merge(&counts).unwrap().untracked_distinct(),
        UntrackedDistinctCount::UnknownHistory { at_least: 1 }
    ));
    let mut corrupt = counts.snapshot();
    corrupt.untracked_distinct.values = vec![value(1), value(2)].into();
    LiteralCounters::from_snapshot(&corrupt, 0).unwrap_err();
}
