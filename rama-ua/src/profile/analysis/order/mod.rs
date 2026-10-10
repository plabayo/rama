//! Capture-derived order evidence. These rules do not authorize independent
//! payload generation or factorization of correlated connection components.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use rama_utils::octets::mib;
use serde::Serialize;

use crate::profile::{
    CanonicalDomain, CountedObservationBucket, CounterSnapshot, ObservationLosses,
    ObservationWeight, OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture,
    OrderedProtocolField, ProfileDataError, ValueId,
};

#[derive(Debug, Clone, Copy)]
pub struct OrderAnalysisConfig {
    pub minimum_samples: usize,
    pub distinct_numerator: usize,
    pub distinct_denominator: usize,
    pub maximum_samples: usize,
    pub maximum_literals: usize,
    pub maximum_elements: usize,
    pub maximum_bytes: usize,
    /// Normalized element visits, shared by all paths and recursive modes.
    pub maximum_work: usize,
    /// Retained element-position counters, including recursive mode evidence.
    pub maximum_positions: usize,
}

impl Default for OrderAnalysisConfig {
    fn default() -> Self {
        Self {
            minimum_samples: 32,
            distinct_numerator: 7,
            distinct_denominator: 8,
            maximum_samples: 256,
            maximum_literals: 16,
            maximum_elements: 256,
            maximum_bytes: mib(8),
            maximum_work: mib(4),
            maximum_positions: 16_384,
        }
    }
}

/// Full-history counters and reservoir frequencies have different meanings.
#[derive(Debug, Clone, Serialize)]
pub enum AnalyzedOrderWeight {
    Counted(ObservationWeight),
    Sample {
        observed: usize,
        sample_size: usize,
        /// Observations eligible for the retained reservoir, excluding recorded losses.
        population: u64,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalyzedLiteralOrder {
    pub value: ValueId,
    /// Indices into the canonical element dictionary, never database identifiers.
    pub elements: Box<[u16]>,
    pub weight: AnalyzedOrderWeight,
}

/// Occurrences remain distinct even when an identifier occurs more than once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum AnalyzedOrderElement {
    Literal { id: u64, occurrence: u16 },
    Reserved { occurrence: u16 },
}

#[derive(Debug, Clone, Serialize)]
pub struct PinnedOrderElement {
    pub element: AnalyzedOrderElement,
    pub index: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObservedReservedPlacement {
    /// Final indices of all reserved occurrences in one observed joint placement.
    pub indices: Box<[usize]>,
    pub sample_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub enum DerivedOrderRule {
    /// Disjoint observed element sets retain their frequency and their own rule.
    Mixture { modes: Box<[OrderModeEvidence]> },
    /// Reserved identifiers participate in numeric sorting after they are chosen.
    Sorted {
        elements: Box<[AnalyzedOrderElement]>,
    },
    /// Literal relative order is fixed; reserved placements remain joint samples.
    Relative {
        literals: Box<[AnalyzedOrderElement]>,
        placements: Box<[ObservedReservedPlacement]>,
    },
    Shuffled {
        elements: Box<[AnalyzedOrderElement]>,
        pinned: Box<[PinnedOrderElement]>,
    },
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum OrderAnalysisDisposition {
    Literal,
    InsufficientSamples,
    UnknownHistory,
    IncompleteRetention,
    UnstableElements,
    DerivedHeuristic,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrderAnalysis {
    pub classifier_revision: u16,
    pub namespace: OrderNamespace,
    pub total: u64,
    pub retained_samples: usize,
    pub sample_values: Box<[ValueId]>,
    pub normalized_distinct_orders: usize,
    pub positions: Box<[OrderPositionCount]>,
    pub dictionary: Box<[OrderedProtocolField]>,
    pub observed: Box<[AnalyzedLiteralOrder]>,
    pub derived: Option<DerivedOrderRule>,
    /// Thresholds describe a heuristic; they are not statistical confidence.
    pub disposition: OrderAnalysisDisposition,
}

impl OrderAnalysisConfig {
    pub(super) fn validate(self) -> Result<(), ProfileDataError> {
        if self.minimum_samples == 0
            || self.distinct_denominator == 0
            || self.distinct_numerator == 0
            || self.distinct_numerator > self.distinct_denominator
            || self.maximum_samples < self.minimum_samples
            || self.maximum_elements > usize::from(u16::MAX)
        {
            return Err(ProfileDataError::Invalid("order analysis configuration"));
        }
        self.maximum_samples
            .checked_add(self.maximum_literals)
            .ok_or(ProfileDataError::LimitExceeded("order analysis values"))?;
        self.maximum_samples
            .checked_mul(self.maximum_elements)
            .ok_or(ProfileDataError::LimitExceeded("order analysis elements"))?;
        Ok(())
    }
}

/// Analyze one already validated structural bucket. Its exact total is preserved;
/// generated-order evidence comes only from the unbiased retained reservoir.
pub fn analyze_protocol_order(
    bucket: &CountedObservationBucket,
    config: OrderAnalysisConfig,
) -> Result<OrderAnalysis, ProfileDataError> {
    config.validate()?;
    if bucket.retained_bytes() > config.maximum_bytes {
        return Err(ProfileDataError::LimitExceeded("order analysis bytes"));
    }
    let snapshot = bucket.snapshot();
    if snapshot.domain != CanonicalDomain::Order {
        return Err(ProfileDataError::Invalid("order analysis domain"));
    }
    if snapshot.counts.values.len() > config.maximum_literals
        || snapshot.samples.len() > config.maximum_samples
        || snapshot.values.len()
            > config
                .maximum_samples
                .saturating_add(config.maximum_literals)
    {
        return Err(ProfileDataError::LimitExceeded("order analysis samples"));
    }
    let mut values = BTreeMap::new();
    let mut dictionary = BTreeSet::new();
    let mut namespace: Option<OrderNamespace> = None;
    for value in &snapshot.values {
        let capture = OrderedProtocolCapture::from_canonical(
            value,
            OrderCaptureLimits {
                elements: config.maximum_elements,
                bytes: config.maximum_bytes,
            },
        )?;
        if let Some(previous) = namespace {
            if previous.tag() != capture.namespace.tag() {
                return Err(ProfileDataError::Invalid("mixed order namespaces"));
            }
        } else {
            namespace = Some(capture.namespace);
        }
        for field in &capture.fields {
            dictionary.insert((field.id, field.value.clone()));
        }
        values.insert(value.id, capture);
    }
    let namespace = namespace.ok_or(ProfileDataError::Incomplete("order analysis evidence"))?;
    if dictionary.len() > usize::from(u16::MAX) {
        return Err(ProfileDataError::LimitExceeded("order element dictionary"));
    }
    let dictionary: Vec<_> = dictionary
        .into_iter()
        .map(|(id, value)| OrderedProtocolField { id, value })
        .collect();
    let mut frequencies = BTreeMap::<ValueId, usize>::new();
    let mut samples = Vec::new();
    for sample in &snapshot.samples {
        let value = values
            .get(&sample.value)
            .ok_or(ProfileDataError::Invalid("missing order sample"))?;
        samples.push(value);
        *frequencies.entry(sample.value).or_default() += 1;
    }
    let mut observed = Vec::new();
    for (id, capture) in &values {
        let count = snapshot
            .counts
            .values
            .iter()
            .find(|count| count.value == *id);
        let weight = if snapshot.counts.untracked == 0 {
            let count = count.ok_or(ProfileDataError::Invalid("uncounted complete order"))?;
            AnalyzedOrderWeight::Counted(if snapshot.counts.losses.history_known {
                ObservationWeight::Exact(count.count)
            } else {
                ObservationWeight::UnknownHistory {
                    observed: count.count,
                    unassigned: 0,
                }
            })
        } else if let Some(count) = frequencies.get(id) {
            AnalyzedOrderWeight::Sample {
                observed: *count,
                sample_size: samples.len(),
                population: sampling_population(&snapshot.counts)?,
            }
        } else {
            // A tracked literal outside this reservoir cannot be mixed into its
            // sampled weights without counting part of the population twice.
            continue;
        };
        let order = capture
            .fields
            .iter()
            .map(|field| {
                dictionary
                    .binary_search(field)
                    .map(|index| index as u16)
                    .map_err(|_error| ProfileDataError::Invalid("missing dictionary element"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        observed.push(AnalyzedLiteralOrder {
            value: *id,
            elements: order.into(),
            weight,
        });
    }
    let mut result = OrderAnalysis {
        classifier_revision: 1,
        namespace,
        total: snapshot.counts.total,
        retained_samples: samples.len(),
        sample_values: snapshot.samples.iter().map(|sample| sample.value).collect(),
        normalized_distinct_orders: 0,
        positions: Box::default(),
        dictionary: dictionary.into(),
        observed: observed.into(),
        derived: None,
        disposition: OrderAnalysisDisposition::Literal,
    };
    let identifiers: Vec<Vec<u64>> = samples
        .iter()
        .map(|sample| sample.fields.iter().map(|field| field.id).collect())
        .collect();
    let evidence = analyze_identifiers(&identifiers, &snapshot.counts.losses, config, |id| {
        namespace.reserved_candidate(id)
    })?;
    result.normalized_distinct_orders = evidence.normalized_distinct_orders;
    result.derived = evidence.derived;
    result.disposition = evidence.disposition;
    result.positions = evidence.positions;
    Ok(result)
}

#[derive(Debug, Clone, Serialize)]
pub struct OrderPositionCount {
    pub element: AnalyzedOrderElement,
    pub index: usize,
    pub sample_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrderModeEvidence {
    pub elements: Box<[AnalyzedOrderElement]>,
    /// Indices into the parent evidence sample axis, preserving mode membership.
    pub sample_indices: Box<[usize]>,
    pub sample_count: usize,
    pub sample_size: usize,
    pub evidence: Box<OrderRuleEvidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrderRuleEvidence {
    pub normalized_distinct_orders: usize,
    pub positions: Box<[OrderPositionCount]>,
    pub derived: Option<DerivedOrderRule>,
    pub disposition: OrderAnalysisDisposition,
}

#[derive(Debug)]
pub(super) struct OrderWorkBudget {
    elements: usize,
    positions: usize,
    initial_elements: usize,
}

impl OrderWorkBudget {
    pub(super) fn new(config: OrderAnalysisConfig) -> Self {
        Self {
            elements: config.maximum_work,
            positions: config.maximum_positions,
            initial_elements: config.maximum_work,
        }
    }

    pub(super) fn used(&self) -> usize {
        self.initial_elements - self.elements
    }

    fn charge(&mut self, elements: usize) -> Result<(), ProfileDataError> {
        self.elements = self
            .elements
            .checked_sub(elements)
            .ok_or(ProfileDataError::LimitExceeded("order analysis work"))?;
        Ok(())
    }
}

pub(super) fn analyze_identifiers(
    samples: &[Vec<u64>],
    losses: &ObservationLosses,
    config: OrderAnalysisConfig,
    reserved_candidate: impl Fn(u64) -> bool,
) -> Result<OrderRuleEvidence, ProfileDataError> {
    let samples: Vec<_> = samples.iter().map(Vec::as_slice).collect();
    analyze_identifiers_with_budget(
        &samples,
        losses,
        config,
        reserved_candidate,
        &mut OrderWorkBudget::new(config),
    )
}

pub(super) fn analyze_identifiers_with_budget(
    samples: &[&[u64]],
    losses: &ObservationLosses,
    config: OrderAnalysisConfig,
    reserved_candidate: impl Fn(u64) -> bool,
    budget: &mut OrderWorkBudget,
) -> Result<OrderRuleEvidence, ProfileDataError> {
    analyze_identifiers_at_depth(samples, losses, config, &reserved_candidate, 0, budget)
}

fn analyze_identifiers_at_depth(
    samples: &[&[u64]],
    losses: &ObservationLosses,
    config: OrderAnalysisConfig,
    reserved_candidate: &impl Fn(u64) -> bool,
    depth: usize,
    budget: &mut OrderWorkBudget,
) -> Result<OrderRuleEvidence, ProfileDataError> {
    config.validate()?;
    if samples.len() > config.maximum_samples
        || samples
            .iter()
            .any(|sample| sample.len() > config.maximum_elements)
    {
        return Err(ProfileDataError::LimitExceeded("order evidence elements"));
    }
    let mut result = OrderRuleEvidence {
        normalized_distinct_orders: 0,
        positions: Box::default(),
        derived: None,
        disposition: OrderAnalysisDisposition::Literal,
    };
    if !losses.history_known {
        result.disposition = OrderAnalysisDisposition::UnknownHistory;
        return Ok(result);
    }
    if losses.oversize != 0 || losses.retention != 0 {
        result.disposition = OrderAnalysisDisposition::IncompleteRetention;
        return Ok(result);
    }
    if samples.len() < config.minimum_samples {
        result.disposition = OrderAnalysisDisposition::InsufficientSamples;
        return Ok(result);
    }
    let mut constant_reserved: BTreeSet<_> = samples[0]
        .iter()
        .copied()
        .filter(|id| reserved_candidate(*id))
        .collect();
    let unique: BTreeSet<_> = samples.iter().copied().collect();
    for sample in &unique {
        constant_reserved.retain(|id| sample.contains(id));
    }
    let mut normalized_values = BTreeMap::new();
    for sample in unique {
        budget.charge(sample.len())?;
        let mut occurrences = BTreeMap::<u64, u16>::new();
        let mut reserved = 0_u16;
        let mut order = Vec::new();
        for &id in sample {
            if reserved_candidate(id) && !constant_reserved.contains(&id) {
                order.push(AnalyzedOrderElement::Reserved {
                    occurrence: reserved,
                });
                reserved = reserved
                    .checked_add(1)
                    .ok_or(ProfileDataError::LimitExceeded("reserved occurrences"))?;
            } else {
                let occurrence = occurrences.entry(id).or_default();
                order.push(AnalyzedOrderElement::Literal {
                    id,
                    occurrence: *occurrence,
                });
                *occurrence = occurrence
                    .checked_add(1)
                    .ok_or(ProfileDataError::LimitExceeded("literal occurrences"))?;
            }
        }
        normalized_values.insert(sample, Arc::<[AnalyzedOrderElement]>::from(order));
    }
    let normalized: Vec<_> = samples
        .iter()
        .map(|sample| normalized_values[*sample].clone())
        .collect();
    let mut frequencies = BTreeMap::new();
    for order in &normalized {
        *frequencies.entry(order.clone()).or_insert(0usize) += 1;
    }
    result.normalized_distinct_orders = frequencies.len();
    let mut positions = BTreeMap::new();
    for (order, frequency) in &frequencies {
        budget.charge(order.len())?;
        for (index, element) in order.iter().enumerate() {
            if !positions.contains_key(&(*element, index)) {
                budget.positions = budget
                    .positions
                    .checked_sub(1)
                    .ok_or(ProfileDataError::LimitExceeded("order analysis positions"))?;
            }
            *positions.entry((*element, index)).or_insert(0_usize) += frequency;
        }
    }
    result.positions = positions
        .into_iter()
        .map(|((element, index), sample_count)| OrderPositionCount {
            element,
            index,
            sample_count,
        })
        .collect();
    let mut elements = normalized[0].to_vec();
    elements.sort_unstable();
    let sorted: BTreeMap<_, _> = frequencies
        .keys()
        .map(|order| {
            let mut key = order.to_vec();
            key.sort_unstable();
            (order, key)
        })
        .collect();
    let mut modes = BTreeMap::<Vec<AnalyzedOrderElement>, Vec<usize>>::new();
    for (index, order) in normalized.iter().enumerate() {
        let key = &sorted[order];
        if let Some(indices) = modes.get_mut(key) {
            indices.push(index);
        } else {
            modes.insert(key.clone(), vec![index]);
        }
    }
    if modes.len() > 1 {
        if modes.len() > config.maximum_literals || depth >= 8 {
            result.disposition = OrderAnalysisDisposition::UnstableElements;
            return Ok(result);
        }
        let mut analyzed_modes = Vec::new();
        for (elements, indices) in &modes {
            let members: Vec<_> = indices.iter().map(|index| samples[*index]).collect();
            let evidence = analyze_identifiers_at_depth(
                &members,
                losses,
                config,
                reserved_candidate,
                depth + 1,
                budget,
            )?;
            analyzed_modes.push(OrderModeEvidence {
                elements: elements.clone().into(),
                sample_indices: indices.clone().into(),
                sample_count: members.len(),
                sample_size: samples.len(),
                evidence: Box::new(evidence),
            });
        }
        result.derived = Some(DerivedOrderRule::Mixture {
            modes: analyzed_modes.into(),
        });
        result.disposition = OrderAnalysisDisposition::DerivedHeuristic;
        return Ok(result);
    }
    let varying_reserved = elements
        .iter()
        .any(|element| matches!(element, AnalyzedOrderElement::Reserved { .. }));
    if varying_reserved
        && samples
            .iter()
            .all(|sample| sample.windows(2).all(|pair| pair[0] <= pair[1]))
    {
        result.derived = Some(DerivedOrderRule::Sorted {
            elements: elements.into(),
        });
    } else {
        let literals: Vec<_> = normalized[0]
            .iter()
            .copied()
            .filter(|element| matches!(element, AnalyzedOrderElement::Literal { .. }))
            .collect();
        if varying_reserved
            && frequencies.keys().all(|order| {
                order
                    .iter()
                    .copied()
                    .filter(|element| matches!(element, AnalyzedOrderElement::Literal { .. }))
                    .eq(literals.iter().copied())
            })
        {
            let mut placements = BTreeMap::<Vec<usize>, usize>::new();
            for (order, frequency) in &frequencies {
                let indices = order
                    .iter()
                    .enumerate()
                    .filter_map(|(index, element)| {
                        matches!(element, AnalyzedOrderElement::Reserved { .. }).then_some(index)
                    })
                    .collect();
                *placements.entry(indices).or_default() += frequency;
            }
            result.derived = Some(DerivedOrderRule::Relative {
                literals: literals.into(),
                placements: placements
                    .into_iter()
                    .map(|(indices, sample_count)| ObservedReservedPlacement {
                        indices: indices.into(),
                        sample_count,
                    })
                    .collect(),
            });
        } else if (result.normalized_distinct_orders as u128)
            * (config.distinct_denominator as u128)
            >= (samples.len() as u128) * (config.distinct_numerator as u128)
        {
            let pinned = normalized[0]
                .iter()
                .enumerate()
                .filter_map(|(index, element)| {
                    frequencies
                        .keys()
                        .all(|order| order[index] == *element)
                        .then_some(PinnedOrderElement {
                            element: *element,
                            index,
                        })
                })
                .collect();
            result.derived = Some(DerivedOrderRule::Shuffled {
                elements: elements.into(),
                pinned,
            });
        }
    }
    if result.derived.is_some() {
        result.disposition = OrderAnalysisDisposition::DerivedHeuristic;
    }
    Ok(result)
}

#[cfg(test)]
mod tests;

pub(super) fn sampling_population(counts: &CounterSnapshot) -> Result<u64, ProfileDataError> {
    counts
        .total
        .checked_sub(counts.losses.oversize)
        .and_then(|total| total.checked_sub(counts.losses.retention))
        .ok_or(ProfileDataError::Invalid("sampling loss count"))
}
