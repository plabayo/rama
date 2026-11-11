//! Captured values without per-connection noise, so evidence of any age compacts alike.

use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "tls")]
use crate::profile::capture::tls::{TlsCapture, TlsCaptureLimits};
use crate::profile::{
    analysis::profile::{
        ProfileAnalysisLimits,
        reserved_slots::{ReservedSlots, ReservedSurvey},
    },
    capture::{
        headers::{HeaderCapture, HeaderCapturePolicy},
        http3::{
            H3ClientSequenceCapture, H3SequenceCaptureLimits,
            bootstrap::{H3BootstrapCapture, H3BootstrapLimits},
        },
        joint::{CapturedSlotKind, JointCapture, JointCaptureLimits},
        order::{OrderCaptureLimits, OrderedProtocolCapture},
        pseudo_headers::PseudoHeaderCapture,
        quic::{QuicFlightCapture, QuicFlightCaptureLimits},
    },
    compare::mode::project_dynamic_indexes,
    evidence::{
        ProfileEvidence, bucket::CountedBucketSnapshot, counts::LiteralCount,
        window::RetainedBucketsSnapshot,
    },
    format::canonical::{CanonicalDomain, CanonicalValue, ProfileDataError, ValueId},
};

/// Decoding bounds for the values a read rewrites.
#[derive(Debug, Clone, Copy)]
pub(super) struct ReadLimits {
    pub(super) joint: JointCaptureLimits,
    /// Elements per TLS list, as configured for capture analysis.
    #[cfg_attr(not(feature = "tls"), expect(dead_code, reason = "bounds TLS lists"))]
    pub(super) elements: usize,
}

impl ReadLimits {
    fn headers(self) -> HeaderCapturePolicy {
        HeaderCapturePolicy {
            bytes: self.joint.value_bytes,
            fields: self.joint.value_bytes,
            overrides: Box::default(),
        }
    }

    fn order(self) -> OrderCaptureLimits {
        OrderCaptureLimits {
            bytes: self.joint.value_bytes,
            elements: self.joint.value_bytes,
        }
    }

    fn flight(self) -> QuicFlightCaptureLimits {
        QuicFlightCaptureLimits {
            bytes: self.joint.value_bytes,
            ..QuicFlightCaptureLimits::default()
        }
    }

    fn sequence(self) -> H3SequenceCaptureLimits {
        H3SequenceCaptureLimits {
            bytes: self.joint.value_bytes,
            ..H3SequenceCaptureLimits::default()
        }
    }
}

#[cfg(feature = "tls")]
fn read_tls(
    value: &CanonicalValue,
    limits: ReadLimits,
) -> Result<CanonicalValue, ProfileDataError> {
    let limits = TlsCaptureLimits {
        elements: limits.elements,
        bytes: limits.joint.value_bytes,
    };
    TlsCapture::from_canonical(value, limits)?
        .with_grease_placeholders()?
        .canonical(limits)
}

#[cfg(not(feature = "tls"))]
fn read_tls(
    value: &CanonicalValue,
    _limits: ReadLimits,
) -> Result<CanonicalValue, ProfileDataError> {
    Ok(value.clone())
}

/// The value as profiles read it: what a client draws afresh per connection
/// becomes a slot, and positions in a connection's own dynamic table are dropped.
fn read_value(
    value: &CanonicalValue,
    limits: ReadLimits,
    slots: &ReservedSlots,
) -> Result<CanonicalValue, ProfileDataError> {
    let read = match value.domain_tag(limits.joint.value_bytes)? {
        CanonicalDomain::Tls => return read_tls(value, limits),
        CanonicalDomain::Headers => {
            let policy = limits.headers();
            let mut capture = HeaderCapture::from_canonical(value, &policy)?;
            project_dynamic_indexes(
                capture
                    .fields
                    .iter_mut()
                    .map(|field| &mut field.representation),
            )
            .then(|| capture.canonical(&policy))
        }
        CanonicalDomain::PseudoHeaders => {
            let bytes = limits.joint.value_bytes;
            let mut capture = PseudoHeaderCapture::from_canonical(value, bytes)?;
            project_dynamic_indexes(
                capture
                    .fields
                    .iter_mut()
                    .map(|field| &mut field.representation),
            )
            .then(|| capture.canonical(bytes))
        }
        CanonicalDomain::Order if !slots.is_empty() => {
            let mut capture = OrderedProtocolCapture::from_canonical(value, limits.order())?;
            slots
                .order(&mut capture)?
                .then(|| capture.canonical(limits.order()))
        }
        CanonicalDomain::QuicFlight if !slots.is_empty() => {
            let mut capture = QuicFlightCapture::from_canonical(value, limits.flight())?;
            slots
                .flight(&mut capture)
                .then(|| capture.canonical(limits.flight()))
        }
        CanonicalDomain::H3Sequence if !slots.is_empty() => {
            let mut capture = H3ClientSequenceCapture::from_canonical(value, limits.sequence())?;
            slots
                .sequence(&mut capture)
                .then(|| capture.canonical(limits.sequence()))
        }
        CanonicalDomain::Joint => {
            let mut joint = JointCapture::from_canonical(value, limits.joint)?;
            let mut changed = false;
            for slot in &mut joint.slots {
                let read = read_value(&slot.value, limits, slots)?;
                if read.id != slot.value.id {
                    slot.value = read;
                    changed = true;
                }
            }
            changed.then(|| joint.canonical(limits.joint))
        }
        _ => None,
    };
    read.unwrap_or_else(|| Ok(value.clone()))
}

fn survey_value(
    survey: &mut ReservedSurvey,
    value: &CanonicalValue,
    limits: ReadLimits,
) -> Result<(), ProfileDataError> {
    match value.domain_tag(limits.joint.value_bytes)? {
        CanonicalDomain::Order => {
            survey.order(&OrderedProtocolCapture::from_canonical(
                value,
                limits.order(),
            )?)?;
        }
        CanonicalDomain::QuicFlight => {
            survey.flight(&QuicFlightCapture::from_canonical(value, limits.flight())?);
        }
        CanonicalDomain::H3Sequence => survey.sequence(&H3ClientSequenceCapture::from_canonical(
            value,
            limits.sequence(),
        )?),
        CanonicalDomain::Joint => {
            for slot in &JointCapture::from_canonical(value, limits.joint)?.slots {
                survey_value(survey, &slot.value, limits)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Reserved identifiers the profile's client generates per connection.
pub(super) fn reserved_slots(
    evidence: &ProfileEvidence,
    limits: ReadLimits,
    preserved: &BTreeSet<ValueId>,
) -> Result<ReservedSlots, ProfileDataError> {
    let mut survey = ReservedSurvey::default();
    for scope in &evidence.scopes {
        for day in &scope.window.buckets {
            for value in &day.bucket.values {
                if !preserved.contains(&value.id) {
                    survey_value(&mut survey, value, limits)?;
                }
            }
        }
    }
    Ok(survey.slots())
}

fn read_bucket(
    bucket: &CountedBucketSnapshot,
    limits: ReadLimits,
    preserved: &BTreeSet<ValueId>,
    slots: &ReservedSlots,
) -> Result<CountedBucketSnapshot, ProfileDataError> {
    let mut renamed = BTreeMap::new();
    let mut values = BTreeMap::new();
    for value in &bucket.values {
        let read = if preserved.contains(&value.id) {
            value.clone()
        } else {
            read_value(value, limits, slots)?
        };
        renamed.insert(value.id, read.id);
        values.insert(read.id, read);
    }
    let rename = |id: ValueId| {
        renamed
            .get(&id)
            .copied()
            .ok_or(ProfileDataError::Invalid("unretained bucket value"))
    };
    let mut counts = BTreeMap::<ValueId, u64>::new();
    for literal in &bucket.counts.values {
        let count = counts.entry(rename(literal.value)?).or_default();
        *count = count
            .checked_add(literal.count)
            .ok_or(ProfileDataError::LimitExceeded("literal counter total"))?;
    }
    let mut read = bucket.clone();
    read.counts.values = counts
        .into_iter()
        .map(|(value, count)| LiteralCount { value, count })
        .collect();
    for sample in &mut read.samples {
        sample.value = rename(sample.value)?;
    }
    read.values = values.into_values().collect();
    Ok(read)
}

impl ReadLimits {
    pub(super) fn for_analysis(limits: &ProfileAnalysisLimits) -> Self {
        Self {
            joint: JointCaptureLimits {
                value_bytes: limits.window.bucket.input_bytes,
                bytes: limits.window.bucket.input_bytes,
                ..JointCaptureLimits::default()
            },
            elements: limits.order.maximum_elements,
        }
    }
}

/// Requests an HTTP/3 bootstrap names: their exact values bind its recipe, so they stay as captured.
pub(super) fn bootstrap_requests(
    evidence: &ProfileEvidence,
    limits: ReadLimits,
) -> Result<BTreeSet<ValueId>, ProfileDataError> {
    let bootstrap = H3BootstrapLimits {
        bytes: limits.joint.value_bytes,
        ..H3BootstrapLimits::default()
    };
    let mut requests = BTreeSet::new();
    for scope in &evidence.scopes {
        for day in &scope.window.buckets {
            for value in &day.bucket.values {
                match scope.window.domain {
                    CanonicalDomain::H3Bootstrap => {
                        requests
                            .insert(H3BootstrapCapture::from_canonical(value, bootstrap)?.request);
                    }
                    CanonicalDomain::Joint => {
                        let joint = JointCapture::from_canonical(value, limits.joint)?;
                        for slot in &joint.slots {
                            if slot.kind == CapturedSlotKind::Http3Bootstrap {
                                requests.insert(
                                    H3BootstrapCapture::from_canonical(&slot.value, bootstrap)?
                                        .request,
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(requests)
}

/// Rewrite a window's values to their read form; values that become equal merge.
pub(super) fn read_window(
    window: &RetainedBucketsSnapshot,
    limits: ReadLimits,
    preserved: &BTreeSet<ValueId>,
    slots: &ReservedSlots,
) -> Result<RetainedBucketsSnapshot, ProfileDataError> {
    let mut read = window.clone();
    for day in &mut read.buckets {
        day.bucket = read_bucket(&day.bucket, limits, preserved, slots)?;
    }
    Ok(read)
}
