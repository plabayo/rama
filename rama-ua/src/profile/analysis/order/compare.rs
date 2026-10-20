//! Identifier-order membership under capture-derived rules. Values and layout
//! require their own comparison; accepting an order alone never proves a profile.

use super::*;

impl OrderAnalysis {
    /// Test a wire identifier sequence against this analysis's retained orders
    /// or derived rule. A constant reserved identifier remains literal; only
    /// observed variation can authorize a generated reserved position.
    ///
    /// This compares identifiers and their positions only, not field values,
    /// connection layout, frequencies, or correlations with other components.
    pub fn accepts_identifiers(&self, identifiers: &[u64]) -> Result<bool, ProfileDataError> {
        if identifiers.len() > usize::from(u16::MAX) {
            return Err(ProfileDataError::LimitExceeded("comparison order elements"));
        }
        let axis: Vec<_> = (0..self.sample_values.len()).collect();
        match &self.derived {
            Some(rule) => matches_rule(self, rule, &axis, identifiers),
            None => Ok(self
                .observed
                .iter()
                .any(|order| matches_literal(self, order, identifiers))),
        }
    }
}

fn matches_literal(analysis: &OrderAnalysis, order: &AnalyzedLiteralOrder, ids: &[u64]) -> bool {
    order.elements.len() == ids.len()
        && order.elements.iter().zip(ids).all(|(index, id)| {
            analysis
                .dictionary
                .get(usize::from(*index))
                .is_some_and(|field| field.id == *id)
        })
}

fn matches_rule(
    analysis: &OrderAnalysis,
    rule: &DerivedOrderRule,
    axis: &[usize],
    ids: &[u64],
) -> Result<bool, ProfileDataError> {
    if let DerivedOrderRule::Mixture { modes } = rule {
        for mode in modes {
            if mode.sample_size != axis.len() {
                return Err(ProfileDataError::Invalid("comparison mode sample axis"));
            }
            let child = mode
                .sample_indices
                .iter()
                .map(|index| {
                    axis.get(*index)
                        .copied()
                        .ok_or(ProfileDataError::Invalid("comparison mode index"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let accepted = if let Some(rule) = &mode.evidence.derived {
                matches_rule(analysis, rule, &child, ids)?
            } else {
                child.iter().any(|index| {
                    analysis.sample_values.get(*index).is_some_and(|value| {
                        analysis.observed.iter().any(|order| {
                            order.value == *value && matches_literal(analysis, order, ids)
                        })
                    })
                })
            };
            if accepted {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    let literals: BTreeSet<_> = match rule {
        DerivedOrderRule::Sorted { elements } | DerivedOrderRule::Shuffled { elements, .. } => {
            elements
        }
        DerivedOrderRule::Relative { literals, .. } => literals,
        DerivedOrderRule::Mixture { .. } => {
            return Err(ProfileDataError::Invalid("unresolved comparison mixture"));
        }
    }
    .iter()
    .filter_map(|element| match element {
        AnalyzedOrderElement::Literal { id, .. } => Some(*id),
        AnalyzedOrderElement::Reserved { .. } => None,
    })
    .collect();
    let normalized = normalize_identifiers(ids, &literals, |id| {
        analysis.namespace.reserved_candidate(id)
    })?;
    let same_elements = |elements: &[AnalyzedOrderElement]| {
        let mut expected = elements.to_vec();
        let mut actual = normalized.clone();
        expected.sort_unstable();
        actual.sort_unstable();
        expected == actual
    };
    Ok(match rule {
        DerivedOrderRule::Sorted { elements } => {
            same_elements(elements) && ids.windows(2).all(|pair| pair[0] <= pair[1])
        }
        DerivedOrderRule::Shuffled { elements, pinned } => {
            same_elements(elements)
                && pinned
                    .iter()
                    .all(|pin| normalized.get(pin.index) == Some(&pin.element))
        }
        DerivedOrderRule::Relative {
            literals,
            placements,
        } => {
            let actual_literals: Vec<_> = normalized
                .iter()
                .copied()
                .filter(|value| matches!(value, AnalyzedOrderElement::Literal { .. }))
                .collect();
            let positions: Vec<_> = normalized
                .iter()
                .enumerate()
                .filter_map(|(index, value)| {
                    matches!(value, AnalyzedOrderElement::Reserved { .. }).then_some(index)
                })
                .collect();
            actual_literals.as_slice() == literals.as_ref()
                && placements
                    .iter()
                    .any(|placement| placement.indices.as_ref() == positions.as_slice())
        }
        DerivedOrderRule::Mixture { .. } => {
            return Err(ProfileDataError::Invalid("unresolved comparison mixture"));
        }
    })
}
