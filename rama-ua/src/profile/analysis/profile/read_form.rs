//! Captured values without per-connection noise, so evidence of any age compacts alike.

use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "tls")]
use crate::profile::capture::tls::{TlsCapture, TlsCaptureLimits};
use crate::profile::{
    analysis::profile::ProfileAnalysisLimits,
    capture::{
        http3::bootstrap::{H3BootstrapCapture, H3BootstrapLimits},
        joint::{CapturedSlotKind, JointCapture, JointCaptureLimits},
    },
    evidence::{
        ProfileEvidence, bucket::CountedBucketSnapshot, counts::LiteralCount,
        window::RetainedBucketsSnapshot,
    },
    format::canonical::{CanonicalDomain, CanonicalValue, ProfileDataError, ValueId},
};

/// Decoding bounds for the values a read rewrites.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(
    not(feature = "tls"),
    expect(dead_code, reason = "only TLS values are rewritten")
)]
pub(super) struct ReadLimits {
    pub(super) joint: JointCaptureLimits,
    /// Elements per TLS list, as configured for capture analysis.
    pub(super) elements: usize,
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

/// The value as profiles read it: GREASE values become numbered slots.
#[cfg(feature = "tls")]
fn read_value(
    value: &CanonicalValue,
    domain: CanonicalDomain,
    limits: ReadLimits,
) -> Result<CanonicalValue, ProfileDataError> {
    match domain {
        CanonicalDomain::Tls => read_tls(value, limits),
        CanonicalDomain::Joint => {
            let mut joint = JointCapture::from_canonical(value, limits.joint)?;
            for slot in &mut joint.slots {
                if matches!(
                    slot.kind,
                    CapturedSlotKind::TcpTls | CapturedSlotKind::QuicTls
                ) {
                    slot.value = read_tls(&slot.value, limits)?;
                }
            }
            joint.canonical(limits.joint)
        }
        _ => Ok(value.clone()),
    }
}

#[cfg(not(feature = "tls"))]
fn read_value(
    value: &CanonicalValue,
    _domain: CanonicalDomain,
    _limits: ReadLimits,
) -> Result<CanonicalValue, ProfileDataError> {
    Ok(value.clone())
}

fn read_bucket(
    bucket: &CountedBucketSnapshot,
    limits: ReadLimits,
    preserved: &BTreeSet<ValueId>,
) -> Result<CountedBucketSnapshot, ProfileDataError> {
    let mut renamed = BTreeMap::new();
    let mut values = BTreeMap::new();
    for value in &bucket.values {
        let read = if preserved.contains(&value.id) {
            value.clone()
        } else {
            read_value(value, bucket.domain, limits)?
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
) -> Result<RetainedBucketsSnapshot, ProfileDataError> {
    if !matches!(window.domain, CanonicalDomain::Tls | CanonicalDomain::Joint) {
        return Ok(window.clone());
    }
    let mut read = window.clone();
    for day in &mut read.buckets {
        day.bucket = read_bucket(&day.bucket, limits, preserved)?;
    }
    Ok(read)
}
