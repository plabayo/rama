use std::{error::Error, fmt, num::NonZeroU64};

use super::{ProfileDraw, ProfileDrawError};
use crate::profile::{
    AnalyzedOrderElement, AnalyzedOrderWeight, DerivedOrderRule, OrderAnalysis, OrderModeEvidence,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderDrawError {
    Draw(ProfileDrawError),
    InvalidAnalysis(&'static str),
    MissingReservedOccurrence(u16),
}

impl fmt::Display for OrderDrawError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Draw(error) => error.fmt(f),
            Self::InvalidAnalysis(value) => write!(f, "invalid analyzed order: {value}"),
            Self::MissingReservedOccurrence(occurrence) => {
                write!(f, "missing reserved order occurrence {occurrence}")
            }
        }
    }
}

impl Error for OrderDrawError {}

impl From<ProfileDrawError> for OrderDrawError {
    fn from(value: ProfileDrawError) -> Self {
        Self::Draw(value)
    }
}

impl OrderAnalysis {
    /// Draw a concrete identifier order from retained evidence and a validated rule.
    /// Generated reserved values are supplied by the protocol's own generator.
    pub fn draw_order(
        &self,
        reserved: &[u64],
        draw: &mut ProfileDraw,
    ) -> Result<Box<[u64]>, OrderDrawError> {
        match &self.derived {
            Some(rule) => {
                let sample_axis: Vec<_> = (0..self.sample_values.len()).collect();
                draw_rule(self, rule, &sample_axis, reserved, draw)
            }
            None => draw_observed(self, draw),
        }
    }
}

fn draw_rule(
    analysis: &OrderAnalysis,
    rule: &DerivedOrderRule,
    sample_axis: &[usize],
    reserved: &[u64],
    draw: &mut ProfileDraw,
) -> Result<Box<[u64]>, OrderDrawError> {
    match rule {
        DerivedOrderRule::Mixture { modes } => {
            draw_mixture(analysis, modes, sample_axis, reserved, draw)
        }
        DerivedOrderRule::Sorted { elements } => {
            let mut values = resolve_elements(elements, reserved)?;
            values.sort_unstable();
            Ok(values.into())
        }
        DerivedOrderRule::Relative {
            literals,
            placements,
        } => {
            let weights: Result<Vec<_>, _> = placements
                .iter()
                .map(|placement| {
                    u64::try_from(placement.sample_count)
                        .map_err(|_error| OrderDrawError::InvalidAnalysis("placement weight"))
                })
                .collect();
            let placement = placements
                .get(draw.weighted_index(&weights?)?)
                .ok_or(OrderDrawError::InvalidAnalysis("selected placement"))?;
            if placement.indices.len() != reserved.len() {
                return Err(OrderDrawError::InvalidAnalysis(
                    "reserved placement cardinality",
                ));
            }
            let literal_values = resolve_elements(literals, reserved)?;
            let length = literal_values
                .len()
                .checked_add(reserved.len())
                .ok_or(OrderDrawError::InvalidAnalysis("relative order length"))?;
            let mut result = vec![None; length];
            for (occurrence, index) in placement.indices.iter().copied().enumerate() {
                let slot = result
                    .get_mut(index)
                    .ok_or(OrderDrawError::InvalidAnalysis("reserved placement index"))?;
                if slot.replace(reserved[occurrence]).is_some() {
                    return Err(OrderDrawError::InvalidAnalysis(
                        "duplicate reserved placement index",
                    ));
                }
            }
            let mut literals = literal_values.into_iter();
            for slot in &mut result {
                if slot.is_none() {
                    *slot = literals.next();
                }
            }
            if literals.next().is_some() || result.iter().any(Option::is_none) {
                return Err(OrderDrawError::InvalidAnalysis("relative order shape"));
            }
            result
                .into_iter()
                .map(|value| value.ok_or(OrderDrawError::InvalidAnalysis("relative order hole")))
                .collect::<Result<Vec<_>, _>>()
                .map(Vec::into_boxed_slice)
        }
        DerivedOrderRule::Shuffled { elements, pinned } => {
            let values = resolve_elements(elements, reserved)?;
            let mut result = vec![None; values.len()];
            let mut floating = Vec::new();
            for (element, value) in elements.iter().zip(values) {
                if let Some(pin) = pinned.iter().find(|pin| pin.element == *element) {
                    let slot = result
                        .get_mut(pin.index)
                        .ok_or(OrderDrawError::InvalidAnalysis("pinned order index"))?;
                    if slot.replace(value).is_some() {
                        return Err(OrderDrawError::InvalidAnalysis("duplicate pinned index"));
                    }
                } else {
                    floating.push(value);
                }
            }
            draw.shuffle(&mut floating);
            let mut floating = floating.into_iter();
            for slot in &mut result {
                if slot.is_none() {
                    *slot = floating.next();
                }
            }
            if floating.next().is_some() || result.iter().any(Option::is_none) {
                return Err(OrderDrawError::InvalidAnalysis("shuffled order shape"));
            }
            result
                .into_iter()
                .map(|value| value.ok_or(OrderDrawError::InvalidAnalysis("shuffled order hole")))
                .collect::<Result<Vec<_>, _>>()
                .map(Vec::into_boxed_slice)
        }
    }
}

fn draw_mixture(
    analysis: &OrderAnalysis,
    modes: &[OrderModeEvidence],
    sample_axis: &[usize],
    reserved: &[u64],
    draw: &mut ProfileDraw,
) -> Result<Box<[u64]>, OrderDrawError> {
    let weights: Result<Vec<_>, _> = modes
        .iter()
        .map(|mode| {
            u64::try_from(mode.sample_count)
                .map_err(|_error| OrderDrawError::InvalidAnalysis("mode weight"))
        })
        .collect();
    let mode = modes
        .get(draw.weighted_index(&weights?)?)
        .ok_or(OrderDrawError::InvalidAnalysis("selected mode"))?;
    if mode.sample_size != sample_axis.len() {
        return Err(OrderDrawError::InvalidAnalysis("mode sample axis"));
    }
    let mode_axis: Result<Vec<_>, _> = mode
        .sample_indices
        .iter()
        .map(|index| {
            sample_axis
                .get(*index)
                .copied()
                .ok_or(OrderDrawError::InvalidAnalysis("mode sample index"))
        })
        .collect();
    let mode_axis = mode_axis?;
    match &mode.evidence.derived {
        Some(rule) => draw_rule(analysis, rule, &mode_axis, reserved, draw),
        None => draw_sample(analysis, &mode_axis, draw),
    }
}

fn draw_sample(
    analysis: &OrderAnalysis,
    sample_axis: &[usize],
    draw: &mut ProfileDraw,
) -> Result<Box<[u64]>, OrderDrawError> {
    let upper = u64::try_from(sample_axis.len())
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or(OrderDrawError::InvalidAnalysis("empty sample mode"))?;
    let selected = draw.index(upper) as usize;
    let sample = sample_axis
        .get(selected)
        .and_then(|index| analysis.sample_values.get(*index))
        .ok_or(OrderDrawError::InvalidAnalysis("selected sample"))?;
    let observed = analysis
        .observed
        .iter()
        .find(|order| order.value == *sample)
        .ok_or(OrderDrawError::InvalidAnalysis("sample literal"))?;
    resolve_observed(analysis, &observed.elements)
}

fn draw_observed(
    analysis: &OrderAnalysis,
    draw: &mut ProfileDraw,
) -> Result<Box<[u64]>, OrderDrawError> {
    let weights = analysis
        .observed
        .iter()
        .map(|order| match order.weight {
            AnalyzedOrderWeight::Counted(weight) => match weight {
                crate::profile::ObservationWeight::Exact(value)
                | crate::profile::ObservationWeight::UnknownHistory {
                    observed: value, ..
                }
                | crate::profile::ObservationWeight::LowerBound {
                    observed: value, ..
                } => value,
            },
            AnalyzedOrderWeight::Sample { observed, .. } => observed as u64,
        })
        .collect::<Vec<_>>();
    let observed = analysis
        .observed
        .get(draw.weighted_index(&weights)?)
        .ok_or(OrderDrawError::InvalidAnalysis("selected literal"))?;
    resolve_observed(analysis, &observed.elements)
}

fn resolve_observed(
    analysis: &OrderAnalysis,
    elements: &[u16],
) -> Result<Box<[u64]>, OrderDrawError> {
    elements
        .iter()
        .map(|index| {
            analysis
                .dictionary
                .get(usize::from(*index))
                .map(|field| field.id)
                .ok_or(OrderDrawError::InvalidAnalysis("literal dictionary index"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Vec::into_boxed_slice)
}

fn resolve_elements(
    elements: &[AnalyzedOrderElement],
    reserved: &[u64],
) -> Result<Vec<u64>, OrderDrawError> {
    elements
        .iter()
        .map(|element| match *element {
            AnalyzedOrderElement::Literal { id, .. } => Ok(id),
            AnalyzedOrderElement::Reserved { occurrence } => reserved
                .get(usize::from(occurrence))
                .copied()
                .ok_or(OrderDrawError::MissingReservedOccurrence(occurrence)),
        })
        .collect()
}
