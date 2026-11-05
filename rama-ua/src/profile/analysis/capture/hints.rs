//! Per-request network quality hints, kept apart from the variants that send them.

use std::{
    collections::{BTreeMap, BTreeSet},
    mem,
};

use super::{
    CountedCaptureAnalysis, NETWORK_HINT_NAMES, NetworkHintVariant,
    merge::{merge_rewritten, merge_weights},
};
use crate::profile::{
    analysis::order::OrderAnalysisConfig,
    capture::{
        headers::{HeaderCapture, HeaderCapturePolicy, HeaderValueSource},
        joint::{CapturedSlotKind, JointCapture, JointCaptureLimits},
    },
    format::canonical::{CanonicalDomain, CanonicalValue, ProfileDataError, ValueId},
};

type HintFields = Box<[(Box<str>, Box<[u8]>)]>;

fn policy(config: OrderAnalysisConfig) -> HeaderCapturePolicy {
    HeaderCapturePolicy {
        fields: config.maximum_elements,
        bytes: config.maximum_bytes,
        overrides: Box::default(),
    }
}

fn joint_limits(config: OrderAnalysisConfig) -> JointCaptureLimits {
    JointCaptureLimits {
        value_bytes: config.maximum_bytes,
        bytes: config.maximum_bytes,
        ..JointCaptureLimits::default()
    }
}

/// Take the hint values out of `capture`, leaving empty placeholders.
fn take_hints(capture: &mut HeaderCapture) -> Vec<(Box<str>, Box<[u8]>)> {
    let mut taken = Vec::new();
    for field in &mut capture.fields {
        if !NETWORK_HINT_NAMES.contains(&field.name.as_str()) {
            continue;
        }
        if let HeaderValueSource::Profile(value) | HeaderValueSource::CaptureSafeProfile(value) =
            &mut field.value
        {
            taken.push((field.name.as_str().into(), mem::take(value)));
        }
    }
    taken
}

/// `value` with placeholders for its hints, and the hints it carried.
fn separate(
    value: &CanonicalValue,
    domain: CanonicalDomain,
    config: OrderAnalysisConfig,
) -> Result<(CanonicalValue, HintFields), ProfileDataError> {
    match domain {
        CanonicalDomain::Headers => {
            let mut capture = HeaderCapture::from_canonical(value, &policy(config))?;
            let hints = take_hints(&mut capture);
            Ok((capture.canonical(&policy(config))?, hints.into()))
        }
        CanonicalDomain::Joint => {
            let mut joint = JointCapture::from_canonical(value, joint_limits(config))?;
            let mut hints = Vec::new();
            for slot in &mut joint.slots {
                if slot.kind == CapturedSlotKind::Headers {
                    let mut capture = HeaderCapture::from_canonical(&slot.value, &policy(config))?;
                    hints.extend(take_hints(&mut capture));
                    slot.value = capture.canonical(&policy(config))?;
                }
            }
            Ok((joint.canonical(joint_limits(config))?, hints.into()))
        }
        _ => Ok((value.clone(), Box::default())),
    }
}

/// Move network hint values out of the variants into `analysis.network_hints`.
pub(super) fn separate_network_hints(
    analysis: &mut CountedCaptureAnalysis,
    config: OrderAnalysisConfig,
    preserved: &BTreeSet<ValueId>,
) -> Result<(), ProfileDataError> {
    if !matches!(
        analysis.domain,
        CanonicalDomain::Headers | CanonicalDomain::Joint
    ) {
        return Ok(());
    }
    let mut combinations = BTreeMap::<HintFields, _>::new();
    for variant in &analysis.variants {
        // A preserved variant sends its own values; they are not drawn for others.
        if preserved.contains(&variant.value.id()) {
            continue;
        }
        let (_, hints) = separate(&*variant.value.canonical()?, analysis.domain, config)?;
        if hints.is_empty() {
            continue;
        }
        let weight = match combinations.remove(&hints) {
            Some(weight) => merge_weights(&weight, &variant.weight)?,
            None => variant.weight.clone(),
        };
        combinations.insert(hints, weight);
    }
    if combinations.is_empty() {
        return Ok(());
    }
    let domain = analysis.domain;
    merge_rewritten(analysis, config, preserved, |value| {
        separate(value, domain, config).map(|(read, _)| read)
    })?;
    analysis.network_hints = combinations
        .into_iter()
        .map(|(fields, weight)| NetworkHintVariant { fields, weight })
        .collect();
    Ok(())
}
