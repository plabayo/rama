use std::{collections::BTreeSet, num::NonZeroU64};

use serde::Serialize;

use crate::profile::{
    AnalyzedOrderElement, CanonicalDomain, CanonicalValue, CaptureOrderPath,
    CountedCaptureAnalysis, DerivedOrderRule, OrderCaptureLimits, OrderNamespace,
    OrderedProtocolCapture, ProfileDataError, ProfileDraw, ProtocolValue, ValueId,
};

/// Evidence bound to one selected SETTINGS tuple. Only a variance-derived
/// reserved position receives a generator; constant and undersampled tuples
/// retain their literal values. Serialized analyses are rederived on import.
#[derive(Debug, Clone, Serialize)]
pub struct H3SettingsReplayEvidence {
    capture: ValueId,
    sorted: bool,
    generators: Box<[Option<ReservedSettingGenerator>]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReservedSettingGenerator {
    ordinal_upper: u64,
    value_upper: Option<u64>,
}

impl H3SettingsReplayEvidence {
    /// Derive the selected tuple's generators from its own SETTINGS bucket.
    /// An ambiguous mixture or a selected value absent from the sampled mode
    /// yields no authorization, rather than borrowing another mode's rule.
    pub fn from_analysis(
        analysis: &CountedCaptureAnalysis,
        selected: &CanonicalValue,
    ) -> Result<Option<Self>, ProfileDataError> {
        if analysis.domain != CanonicalDomain::Order {
            return Err(ProfileDataError::Invalid("HTTP/3 SETTINGS analysis domain"));
        }
        let capture = settings(selected)?;
        if !analysis
            .variants
            .iter()
            .any(|variant| variant.value.id == selected.id && variant.value.bytes == selected.bytes)
        {
            return Err(ProfileDataError::Incomplete(
                "selected HTTP/3 SETTINGS evidence",
            ));
        }
        let order = analysis
            .orders
            .iter()
            .find(|order| order.path == CaptureOrderPath::Http3Settings)
            .ok_or(ProfileDataError::Incomplete(
                "HTTP/3 SETTINGS order evidence",
            ))?;
        let Some(rule) = &order.evidence.derived else {
            return Ok(Some(Self {
                capture: selected.id,
                sorted: false,
                generators: vec![None; capture.fields.len()].into(),
            }));
        };
        let mut leaves = Vec::new();
        let axis: Vec<_> = (0..analysis.sample_values.len()).collect();
        selected_leaves(
            rule,
            &axis,
            &analysis.sample_values,
            selected.id,
            &mut leaves,
        )?;
        if leaves.is_empty() {
            return Ok(None);
        }
        let mut result = None;
        for (rule, axis) in leaves {
            let sorted = matches!(rule, Some(DerivedOrderRule::Sorted { .. }));
            let literals: BTreeSet<_> = match rule {
                Some(
                    DerivedOrderRule::Sorted { elements }
                    | DerivedOrderRule::Shuffled { elements, .. },
                ) => elements.as_ref(),
                Some(DerivedOrderRule::Relative { literals, .. }) => literals.as_ref(),
                None => {
                    let literal = (vec![None; capture.fields.len()], false);
                    if result.as_ref().is_some_and(|previous| previous != &literal) {
                        return Ok(None);
                    }
                    result = Some(literal);
                    continue;
                }
                Some(DerivedOrderRule::Mixture { .. }) => {
                    return Err(ProfileDataError::Invalid(
                        "unresolved SETTINGS evidence mixture",
                    ));
                }
            }
            .iter()
            .filter_map(|element| match element {
                AnalyzedOrderElement::Literal { id, .. } => Some(*id),
                AnalyzedOrderElement::Reserved { .. } => None,
            })
            .collect();
            let sampled: BTreeSet<_> = axis
                .iter()
                .map(|index| analysis.sample_values[*index])
                .collect();
            let captures = analysis
                .variants
                .iter()
                .filter(|variant| sampled.contains(&variant.value.id))
                .map(|variant| settings(&variant.value))
                .collect::<Result<Vec<_>, _>>()?;
            let mut generators = vec![None; capture.fields.len()];
            let mut occurrence = 0;
            for (index, field) in capture.fields.iter().enumerate() {
                if literals.contains(&field.id)
                    || !OrderNamespace::Http3Setting.reserved_candidate(field.id)
                {
                    continue;
                }
                let mut ordinals = BTreeSet::new();
                let mut values = BTreeSet::new();
                for sample in &captures {
                    let Some(sample) = sample
                        .fields
                        .iter()
                        .filter(|field| {
                            !literals.contains(&field.id)
                                && OrderNamespace::Http3Setting.reserved_candidate(field.id)
                        })
                        .nth(occurrence)
                    else {
                        return Ok(None);
                    };
                    ordinals.insert((sample.id - 33) / 31);
                    values.insert(setting_value(&sample.value)?);
                }
                if ordinals.len() < 2 {
                    return Ok(None);
                }
                let ordinal_max = *ordinals
                    .last()
                    .ok_or(ProfileDataError::Incomplete("SETTINGS ordinal samples"))?;
                let value_max = *values
                    .last()
                    .ok_or(ProfileDataError::Incomplete("SETTINGS value samples"))?;
                generators[index] = Some(ReservedSettingGenerator {
                    // The smallest power-of-two range covering the observed
                    // ordinals/values is a generic bounded-width heuristic.
                    ordinal_upper: (ordinal_max + 1)
                        .next_power_of_two()
                        .min(((1_u64 << 62) - 1 - 33) / 31 + 1),
                    value_upper: {
                        let thresholds = crate::profile::OrderAnalysisConfig::default();
                        (axis.len() >= thresholds.minimum_samples
                            && values.len() * thresholds.distinct_denominator
                                >= axis.len() * thresholds.distinct_numerator)
                            .then(|| (value_max + 1).next_power_of_two())
                    },
                });
                occurrence += 1;
            }
            let candidate = (generators, sorted);
            if result
                .as_ref()
                .is_some_and(|previous| previous != &candidate)
            {
                return Ok(None);
            }
            result = Some(candidate);
        }
        Ok(result.map(|(generators, sorted)| Self {
            capture: selected.id,
            sorted,
            generators: generators.into(),
        }))
    }

    pub(super) fn compile(
        &self,
        capture: &OrderedProtocolCapture,
        draw: &mut ProfileDraw,
    ) -> Result<Vec<(u64, u64)>, ProfileDataError> {
        if capture.canonical(OrderCaptureLimits::default())?.id != self.capture
            || capture.fields.len() != self.generators.len()
        {
            return Err(ProfileDataError::Invalid(
                "HTTP/3 SETTINGS evidence binding",
            ));
        }
        let mut output = Vec::with_capacity(capture.fields.len());
        for (field, generator) in capture.fields.iter().zip(&self.generators) {
            let mut id = field.id;
            let mut value = setting_value(&field.value)?;
            if let Some(generator) = generator {
                let upper = NonZeroU64::new(generator.ordinal_upper)
                    .ok_or(ProfileDataError::Invalid("SETTINGS ordinal range"))?;
                let first = draw.index(upper);
                let mut ordinal = first;
                loop {
                    id = 33 + 31 * ordinal;
                    if !capture
                        .fields
                        .iter()
                        .zip(&self.generators)
                        .any(|(field, generator)| generator.is_none() && field.id == id)
                        && !output.iter().any(|(used, _)| *used == id)
                    {
                        break;
                    }
                    ordinal = (ordinal + 1) % generator.ordinal_upper;
                    if ordinal == first {
                        return Err(ProfileDataError::LimitExceeded(
                            "SETTINGS reserved identifier space",
                        ));
                    }
                }
                if let Some(upper) = generator.value_upper {
                    value = draw.index(
                        NonZeroU64::new(upper)
                            .ok_or(ProfileDataError::Invalid("SETTINGS value range"))?,
                    );
                }
            }
            output.push((id, value));
        }
        if self.sorted {
            output.sort_unstable_by_key(|(id, _)| *id);
        }
        Ok(output)
    }
}

fn settings(value: &CanonicalValue) -> Result<OrderedProtocolCapture, ProfileDataError> {
    let capture = OrderedProtocolCapture::from_canonical(value, OrderCaptureLimits::default())?;
    if !matches!(capture.namespace, OrderNamespace::Http3Setting) {
        return Err(ProfileDataError::Invalid("HTTP/3 SETTINGS namespace"));
    }
    Ok(capture)
}

pub(super) fn setting_value(value: &ProtocolValue) -> Result<u64, ProfileDataError> {
    let ProtocolValue::Literal(bytes) = value else {
        return Err(ProfileDataError::Invalid("HTTP/3 SETTINGS ownership"));
    };
    Ok(u64::from_be_bytes(bytes.as_ref().try_into().map_err(
        |_error| ProfileDataError::Invalid("HTTP/3 SETTINGS value encoding"),
    )?))
}

type EvidenceLeaf<'a> = (Option<&'a DerivedOrderRule>, Vec<usize>);
fn selected_leaves<'a>(
    rule: &'a DerivedOrderRule,
    axis: &[usize],
    samples: &[ValueId],
    selected: ValueId,
    output: &mut Vec<EvidenceLeaf<'a>>,
) -> Result<(), ProfileDataError> {
    if !axis
        .iter()
        .any(|index| samples.get(*index) == Some(&selected))
    {
        return Ok(());
    }
    if let DerivedOrderRule::Mixture { modes } = rule {
        for mode in modes {
            if mode.sample_size != axis.len() {
                return Err(ProfileDataError::Invalid("SETTINGS mixture sample axis"));
            }
            let child = mode
                .sample_indices
                .iter()
                .map(|index| {
                    axis.get(*index)
                        .copied()
                        .ok_or(ProfileDataError::Invalid("SETTINGS mixture index"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if let Some(rule) = &mode.evidence.derived {
                selected_leaves(rule, &child, samples, selected, output)?;
            } else if child
                .iter()
                .any(|index| samples.get(*index) == Some(&selected))
            {
                output.push((None, child));
            }
        }
    } else {
        output.push((Some(rule), axis.to_vec()));
    }
    Ok(())
}

impl H3SettingsReplayEvidence {
    pub(crate) fn for_profile(
        analysis: &crate::profile::AnalyzedProfile,
        selected_scope: &crate::profile::AnalyzedProfileScope,
        selected: &CanonicalValue,
    ) -> Result<Option<Self>, ProfileDataError> {
        use crate::profile::{CapturedSlotKind, JointCapture, JointCaptureLimits};
        let joint = JointCapture::from_canonical(selected, JointCaptureLimits::default())?;
        let Some(slot) = joint
            .slots
            .iter()
            .find(|slot| slot.kind == CapturedSlotKind::Http3Settings)
        else {
            return Ok(None);
        };
        let scope = analysis.scopes.iter().find(|scope| {
            scope.context.flow.is_none()
                && scope.context.authorized == selected_scope.context.authorized
                && scope.context.connection == selected_scope.context.connection
                && scope.observations.domain == CanonicalDomain::Order
                && scope.observations.variants.iter().any(|variant| {
                    variant.value.id == slot.value.id && variant.value.bytes == slot.value.bytes
                })
        });
        match scope {
            Some(scope) => Self::from_analysis(&scope.observations, &slot.value),
            None => Ok(None),
        }
    }
}
