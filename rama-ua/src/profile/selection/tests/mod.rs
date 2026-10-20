use super::order::OrderDrawError;
use std::{hint::black_box, num::NonZeroU64};

use super::*;
use crate::profile::{
    analysis::order::{
        AnalyzedLiteralOrder, AnalyzedOrderElement, AnalyzedOrderWeight, DerivedOrderRule,
        ObservedReservedPlacement, OrderAnalysis, OrderAnalysisDisposition, OrderModeEvidence,
        OrderRuleEvidence, PinnedOrderElement,
    },
    capture::order::{OrderNamespace, OrderedProtocolField, ProtocolValue},
    evidence::counts::ObservationWeight,
};

fn context() -> ProfileDrawContext {
    ProfileDrawContext {
        profile: ValueId([2; 32]),
        analysis_revision: 7,
        scope: ValueId([3; 32]),
        key: DrawKey([4; 32]),
        domain: DrawDomain::Connection,
        slot: 5,
    }
}

#[test]
fn chacha20_draw_has_a_versioned_golden_vector() {
    let mut draw = ProfileDraw::new(ProfileSeed([1; 32]), context());
    let actual = std::array::from_fn(|_index| draw.next_u64());
    assert_eq!(
        actual,
        [
            2_281_322_134_139_863_126,
            7_311_668_242_501_946_354,
            6_891_968_154_096_852_601,
            13_481_633_485_905_223_987,
        ]
    );
}

#[test]
fn profile_seed_debug_is_redacted() {
    let formatted = format!("{:?}", ProfileSeed([0x5a; 32]));
    assert_eq!(formatted, "ProfileSeed(<redacted>)");
    assert!(!formatted.contains("90"));
}

#[test]
fn every_coordinate_domain_separates_the_stream() {
    let baseline = ProfileDraw::new(ProfileSeed([1; 32]), context()).next_u64();
    let variants = [
        (ProfileSeed([9; 32]), context()),
        (
            ProfileSeed([1; 32]),
            ProfileDrawContext {
                profile: ValueId([9; 32]),
                ..context()
            },
        ),
        (
            ProfileSeed([1; 32]),
            ProfileDrawContext {
                analysis_revision: 8,
                ..context()
            },
        ),
        (
            ProfileSeed([1; 32]),
            ProfileDrawContext {
                scope: ValueId([9; 32]),
                ..context()
            },
        ),
        (
            ProfileSeed([1; 32]),
            ProfileDrawContext {
                key: DrawKey([9; 32]),
                ..context()
            },
        ),
        (
            ProfileSeed([1; 32]),
            ProfileDrawContext {
                domain: DrawDomain::Request,
                ..context()
            },
        ),
        (
            ProfileSeed([1; 32]),
            ProfileDrawContext {
                slot: 6,
                ..context()
            },
        ),
    ];
    for (seed, context) in variants {
        assert_ne!(ProfileDraw::new(seed, context).next_u64(), baseline);
    }
}

#[test]
fn identical_logical_draws_ignore_interleaving() {
    let mut first = ProfileDraw::new(ProfileSeed([1; 32]), context());
    let expected = [first.next_u64(), first.next_u64(), first.next_u64()];

    let mut unrelated = ProfileDraw::new(
        ProfileSeed([1; 32]),
        ProfileDrawContext {
            slot: 99,
            ..context()
        },
    );
    for _index in 0..1_000 {
        black_box(unrelated.next_u64());
    }

    let mut second = ProfileDraw::new(ProfileSeed([1; 32]), context());
    assert_eq!(
        [second.next_u64(), second.next_u64(), second.next_u64()],
        expected
    );
}

#[test]
fn bounded_draw_rejects_the_biased_prefix() {
    let upper = NonZeroU64::new((1_u64 << 63) + 1).unwrap();
    let mut values = [0, u64::MAX].into_iter();
    let selected = sample_below_with(upper, || values.next().unwrap());
    assert_eq!(selected, (1_u64 << 63) - 2);
    assert_eq!(values.next(), None);
}

#[test]
fn weighted_draw_skips_zeroes_and_rejects_invalid_totals() {
    let mut draw = ProfileDraw::new(ProfileSeed([1; 32]), context());
    for _index in 0..128 {
        assert_eq!(draw.weighted_index(&[0, 7, 0]).unwrap(), 1);
    }
    assert_eq!(
        draw.weighted_index(&[0, 0]),
        Err(ProfileDrawError::EmptyWeights)
    );
    assert_eq!(
        draw.weighted_index(&[u64::MAX, 1]),
        Err(ProfileDrawError::WeightOverflow)
    );
}

#[test]
fn shuffle_has_a_stable_result_without_shared_state() {
    let mut values = [0, 1, 2, 3, 4, 5, 6, 7];
    ProfileDraw::new(ProfileSeed([1; 32]), context()).shuffle(&mut values);
    assert_eq!(values, [7, 4, 5, 0, 2, 1, 3, 6]);
}

fn analyzed(rule: DerivedOrderRule) -> OrderAnalysis {
    OrderAnalysis {
        classifier_revision: 2,
        namespace: OrderNamespace::QuicParameter,
        total: 1,
        retained_samples: 0,
        sample_values: Box::default(),
        normalized_distinct_orders: 1,
        positions: Box::default(),
        dictionary: Box::default(),
        observed: Box::default(),
        derived: Some(rule),
        disposition: OrderAnalysisDisposition::DerivedHeuristic,
    }
}

fn literal(id: u64) -> AnalyzedOrderElement {
    AnalyzedOrderElement::Literal { id, occurrence: 0 }
}

fn draw() -> ProfileDraw {
    ProfileDraw::new(ProfileSeed([1; 32]), context())
}

#[test]
fn relative_and_sorted_rules_apply_generated_reserved_values() {
    let relative = analyzed(DerivedOrderRule::Relative {
        literals: vec![literal(1), literal(2)].into(),
        placements: vec![ObservedReservedPlacement {
            indices: vec![1].into(),
            sample_count: 4,
        }]
        .into(),
    });
    assert_eq!(
        relative.draw_order(&[27], &mut draw()).unwrap().as_ref(),
        &[1, 27, 2]
    );

    let sorted = analyzed(DerivedOrderRule::Sorted {
        elements: vec![
            literal(5),
            AnalyzedOrderElement::Reserved { occurrence: 0 },
            literal(1),
        ]
        .into(),
    });
    assert_eq!(
        sorted.draw_order(&[3], &mut draw()).unwrap().as_ref(),
        &[1, 3, 5]
    );
}

#[test]
fn shuffled_rule_keeps_pinned_occurrences_in_place() {
    let shuffled = analyzed(DerivedOrderRule::Shuffled {
        elements: vec![literal(1), literal(2), literal(3), literal(4)].into(),
        pinned: vec![PinnedOrderElement {
            element: literal(2),
            index: 1,
        }]
        .into(),
    });
    let selected = shuffled.draw_order(&[], &mut draw()).unwrap();
    assert_eq!(selected[1], 2);
    let mut sorted = selected.into_vec();
    sorted.sort_unstable();
    assert_eq!(sorted, [1, 2, 3, 4]);
}

fn literal_mode(
    elements: &[u64],
    sample_indices: &[usize],
    sample_size: usize,
) -> OrderModeEvidence {
    OrderModeEvidence {
        elements: elements.iter().copied().map(literal).collect(),
        sample_indices: sample_indices.into(),
        sample_count: sample_indices.len(),
        sample_size,
        evidence: Box::new(OrderRuleEvidence {
            normalized_distinct_orders: 1,
            positions: Box::default(),
            derived: None,
            disposition: OrderAnalysisDisposition::Literal,
        }),
    }
}

#[test]
fn mixtures_select_only_observed_correlated_orders() {
    let first = ValueId([11; 32]);
    let second = ValueId([12; 32]);
    let mut analysis = analyzed(DerivedOrderRule::Mixture {
        modes: vec![
            literal_mode(&[1, 2], &[0], 3),
            literal_mode(&[1, 2], &[1, 2], 3),
        ]
        .into(),
    });
    analysis.sample_values = vec![first, second, second].into();
    analysis.dictionary = vec![
        OrderedProtocolField {
            id: 1,
            value: ProtocolValue::Literal(Box::default()),
        },
        OrderedProtocolField {
            id: 2,
            value: ProtocolValue::Literal(Box::default()),
        },
    ]
    .into();
    analysis.observed = vec![
        AnalyzedLiteralOrder {
            value: first,
            elements: vec![0, 1].into(),
            weight: AnalyzedOrderWeight::Counted(ObservationWeight::Exact(1)),
        },
        AnalyzedLiteralOrder {
            value: second,
            elements: vec![1, 0].into(),
            weight: AnalyzedOrderWeight::Counted(ObservationWeight::Exact(2)),
        },
    ]
    .into();

    let mut seen = [false; 2];
    for slot in 0..128 {
        let mut draw = ProfileDraw::new(
            ProfileSeed([1; 32]),
            ProfileDrawContext { slot, ..context() },
        );
        match analysis.draw_order(&[], &mut draw).unwrap().as_ref() {
            [1, 2] => seen[0] = true,
            [2, 1] => seen[1] = true,
            value => panic!("unobserved correlated order: {value:?}"),
        }
    }
    assert_eq!(seen, [true, true]);
}

#[test]
fn malformed_rules_fail_without_partial_output() {
    let duplicate = analyzed(DerivedOrderRule::Relative {
        literals: vec![literal(1)].into(),
        placements: vec![ObservedReservedPlacement {
            indices: vec![0, 0].into(),
            sample_count: 1,
        }]
        .into(),
    });
    assert_eq!(
        duplicate.draw_order(&[27, 58], &mut draw()),
        Err(OrderDrawError::InvalidAnalysis(
            "duplicate reserved placement index"
        ))
    );

    let missing = analyzed(DerivedOrderRule::Sorted {
        elements: vec![AnalyzedOrderElement::Reserved { occurrence: 1 }].into(),
    });
    assert_eq!(
        missing.draw_order(&[27], &mut draw()),
        Err(OrderDrawError::MissingReservedOccurrence(1))
    );
}
