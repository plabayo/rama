//! Conservative, offline comparison of retained complete capture tuples.

use clap::Args;
use rama::{
    error::{BoxError, BoxErrorExt as _},
    ua::profile::*,
};
use serde::Serialize;
use std::{
    fs::File,
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
};

#[derive(Debug, Args)]
pub(super) struct CompareCommand {
    /// Counted reference archive, exported by `rama ua export`.
    reference: PathBuf,
    /// Counted observations from the replay.
    observed: PathBuf,
    /// Require complete retained tuple membership. Generated variants are not accepted.
    #[arg(long, required = true)]
    literal: bool,
    /// Read the authorized partition in both archives.
    #[arg(long)]
    authorized: bool,
    /// Compare only exercised contexts and report unexercised reference contexts.
    #[arg(long)]
    allow_partial_coverage: bool,
}

fn read(path: &Path, authorized: bool) -> Result<Box<[CompiledProfileArchiveEntry]>, BoxError> {
    let limits = ProfileArchiveLimits::default();
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limits.bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    load_profile_archive_snapshot(&bytes, authorized, limits)
}

#[derive(Debug, Serialize)]
struct Comparison {
    profile: ValueId,
    scope: ValueId,
    comparison: RetainedCaptureComparison,
}

#[derive(Debug, Serialize)]
struct Report {
    mode: &'static str,
    literal_match: bool,
    reference_coverage_complete: bool,
    partial_coverage_allowed: bool,
    comparisons: Vec<Comparison>,
    missing_reference_scopes: Vec<ValueId>,
    unrecognized_observed_scopes: Vec<ValueId>,
    limitations: &'static str,
}

fn equivalent_context(a: &AnalyzedProfileScope, b: &AnalyzedProfileScope) -> bool {
    a.context.profile == b.context.profile
        && a.context.flow == b.context.flow
        && a.context.authorized == b.context.authorized
        && a.context.connection == b.context.connection
        && a.observations.domain == b.observations.domain
}

pub(super) fn run(command: &CompareCommand) -> Result<(), BoxError> {
    if !command.literal {
        return Err(BoxError::from_static_str(
            "select --literal comparison explicitly",
        ));
    }
    let reference = read(&command.reference, command.authorized)?;
    let observed = read(&command.observed, command.authorized)?;
    let report = compare_with_coverage(&reference, &observed, command.allow_partial_coverage)?;
    let encoded = serde_json::to_vec_pretty(&report)?;
    if encoded.len() > 8 * 1024 * 1024 {
        return Err(BoxError::from_static_str("comparison report byte limit"));
    }
    let mut output = io::stdout().lock();
    output.write_all(&encoded)?;
    output.write_all(b"\n")?;
    if report.literal_match {
        Ok(())
    } else {
        Err(BoxError::from_static_str(
            "retained capture comparison differs; see JSON report",
        ))
    }
}

fn compare_with_coverage(
    reference: &[CompiledProfileArchiveEntry],
    observed: &[CompiledProfileArchiveEntry],
    allow_partial_coverage: bool,
) -> Result<Report, BoxError> {
    const MAX_COMPARISONS: usize = 256;
    if reference.is_empty() || observed.is_empty() {
        return Err(BoxError::from_static_str(
            "comparison requires nonempty archives",
        ));
    }
    if reference
        .iter()
        .map(|p| p.analysis.scopes.len())
        .sum::<usize>()
        > MAX_COMPARISONS
        || observed
            .iter()
            .map(|p| p.analysis.scopes.len())
            .sum::<usize>()
            > MAX_COMPARISONS
    {
        return Err(BoxError::from_static_str("comparison scope limit"));
    }
    // Standalone component matches cannot establish joint correlations.
    for profile in reference.iter().chain(observed) {
        for scope in &profile.analysis.scopes {
            if !profile.analysis.scopes.iter().any(|joint| {
                joint.observations.domain == CanonicalDomain::Joint
                    && joint.context.profile == scope.context.profile
                    && joint.context.flow == scope.context.flow
                    && joint.context.connection == scope.context.connection
                    && joint.context.authorized == scope.context.authorized
            }) {
                return Err(BoxError::from_static_str(
                    "comparison requires complete joint capture evidence",
                ));
            }
        }
    }
    let mut report = Report {
        mode: "complete-retained-literal",
        literal_match: true,
        reference_coverage_complete: true,
        partial_coverage_allowed: allow_partial_coverage,
        comparisons: Vec::new(),
        missing_reference_scopes: Vec::new(),
        unrecognized_observed_scopes: Vec::new(),
        limitations: "Exact retained tuple membership and context coverage only. No generated-order, value-distribution, population, or wire-equivalence claim. Request and connection-owned values retain their canonical bindings, not the original secret or destination bytes.",
    };
    let mut budget = CaptureComparisonLimits::default().work;
    for profile in observed {
        if profile.analysis.scopes.is_empty() {
            return Err(BoxError::from_static_str("empty observed profile"));
        }
        for scope in &profile.analysis.scopes {
            if scope.observations.variants.is_empty() {
                return Err(BoxError::from_static_str("empty observed scope"));
            }
            let candidates: Vec<_> = reference
                .iter()
                .filter(|p| p.analysis.id == profile.analysis.id)
                .flat_map(|p| p.analysis.scopes.iter())
                .filter(|candidate| equivalent_context(candidate, scope))
                .flat_map(|candidate| {
                    candidate
                        .observations
                        .variants
                        .iter()
                        .map(|v| v.value.clone())
                })
                .collect();
            if candidates.is_empty() {
                if report.unrecognized_observed_scopes.len() == MAX_COMPARISONS {
                    return Err(BoxError::from_static_str("comparison scope limit"));
                }
                report.unrecognized_observed_scopes.push(scope.id);
                report.literal_match = false;
                continue;
            }
            for variant in &scope.observations.variants {
                if report.comparisons.len() == MAX_COMPARISONS {
                    return Err(BoxError::from_static_str("comparison variant limit"));
                }
                let comparison = compare_retained_captures(
                    &candidates,
                    &variant.value,
                    CaptureComparisonLimits {
                        work: budget,
                        ..Default::default()
                    },
                )?;
                budget = budget
                    .checked_sub(comparison.work_units)
                    .ok_or_else(|| BoxError::from_static_str("comparison work limit"))?;
                report.literal_match &= comparison.literal_match;
                report.comparisons.push(Comparison {
                    profile: profile.analysis.id,
                    scope: scope.id,
                    comparison,
                });
            }
        }
    }
    // Require every reference context/domain to be exercised. Variants remain
    // alternatives; a single replay need not exercise every retained variant.
    for profile in reference {
        if profile.analysis.scopes.is_empty() {
            return Err(BoxError::from_static_str("empty reference profile"));
        }
        for scope in &profile.analysis.scopes {
            if scope.observations.variants.is_empty() {
                return Err(BoxError::from_static_str("empty reference scope"));
            }
            if !observed
                .iter()
                .filter(|p| p.analysis.id == profile.analysis.id)
                .flat_map(|p| p.analysis.scopes.iter())
                .any(|candidate| equivalent_context(scope, candidate))
            {
                if report.missing_reference_scopes.len() == MAX_COMPARISONS {
                    return Err(BoxError::from_static_str("comparison scope limit"));
                }
                report.missing_reference_scopes.push(scope.id);
                report.reference_coverage_complete = false;
                if !allow_partial_coverage {
                    report.literal_match = false;
                }
            }
        }
    }
    if report.comparisons.is_empty() {
        report.literal_match = false;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn compare(
        reference: &[CompiledProfileArchiveEntry],
        observed: &[CompiledProfileArchiveEntry],
    ) -> Result<Report, BoxError> {
        compare_with_coverage(reference, observed, false)
    }
    fn archive(value: u64) -> Vec<u8> {
        let profile = ProfileKey::new("comparison-test");
        let settings = OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::Http3Setting,
            [(33, value.to_be_bytes())],
            OrderCaptureLimits::default(),
        )
        .unwrap()
        .canonical(OrderCaptureLimits::default())
        .unwrap();
        let capture = ProfileCapture {
            profile: profile.clone(),
            flow: None,
            connection: ConnectionContext::default(),
            joint: JointCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                level: CaptureLevel::Connection,
                slots: vec![CapturedSlot {
                    kind: CapturedSlotKind::Http3Settings,
                    value: settings,
                }]
                .into(),
            },
        };
        let prepared = capture
            .prepare(false, JointCaptureLimits::default())
            .unwrap();
        let mut scopes = Vec::new();
        for input in prepared.buckets {
            let mut window = RetainedBucketWindow::new(
                input.value.validated_domain(65536).unwrap(),
                input.scope.id,
                [3; 32],
                ProfileWindowLimits::default(),
            )
            .unwrap();
            window
                .observe(
                    100,
                    100,
                    ObservationId {
                        run: [1; 16],
                        sequence: 1,
                    },
                    &input.value,
                )
                .unwrap();
            scopes.push(ProfileScopeEvidence {
                scope: input.scope,
                flow: prepared.flow.clone(),
                structure: input.structure,
                window: window.snapshot(),
            });
        }
        scopes.sort_unstable_by_key(|scope| scope.scope.id);
        ProfileArchiveWriter::new(Vec::new(), false, 100, 14, ProfileArchiveLimits::default())
            .unwrap()
            .write_profile(ProfileArchiveEntry {
                evidence: ProfileEvidence {
                    format_version: 1,
                    profile: profile.canonical(65536).unwrap(),
                    scopes: scopes.into(),
                },
                sampler_seed: [3; 32],
            })
            .unwrap()
            .finish()
            .unwrap()
    }
    fn loaded(value: u64) -> Box<[CompiledProfileArchiveEntry]> {
        load_profile_archive_snapshot(&archive(value), false, ProfileArchiveLimits::default())
            .unwrap()
    }
    #[test]
    fn compare_archives_requires_values_and_all_contexts() {
        let reference = loaded(17);
        let mut observed = loaded(17);
        assert!(compare(&reference, &observed).unwrap().literal_match);
        assert!(!compare(&reference, &loaded(18)).unwrap().literal_match);
        observed[0].analysis.scopes = observed[0]
            .analysis
            .scopes
            .iter()
            .filter(|scope| scope.observations.domain == CanonicalDomain::Joint)
            .cloned()
            .collect();
        let report = compare(&reference, &observed).unwrap();
        assert!(!report.literal_match);
        assert_eq!(report.missing_reference_scopes.len(), 1);
        let partial = compare_with_coverage(&reference, &observed, true).unwrap();
        assert!(partial.literal_match);
        assert!(!partial.reference_coverage_complete);
        assert_eq!(partial.missing_reference_scopes.len(), 1);
        observed[0].analysis.scopes[0]
            .context
            .connection
            .token_present = Some(true);
        assert!(!compare(&reference, &observed).unwrap().literal_match);
        compare(&[], &observed).unwrap_err();
        compare(&reference, &[]).unwrap_err();
        observed[0].analysis.scopes = Box::default();
        compare(&reference, &observed).unwrap_err();
    }
    #[test]
    fn compare_archives_requires_matching_connection_context() {
        let reference = loaded(17);
        let mut observed = loaded(17);
        assert!(compare(&reference, &observed).unwrap().literal_match);
        for scope in &mut observed[0].analysis.scopes {
            scope.context.connection.token_present = Some(true);
        }
        let report = compare(&reference, &observed).unwrap();
        assert!(!report.literal_match);
        assert!(!report.unrecognized_observed_scopes.is_empty());
        assert!(!report.missing_reference_scopes.is_empty());
    }

    #[test]
    fn compare_archives_requires_joint_evidence() {
        let reference = loaded(17);
        let mut observed = loaded(17);
        observed[0].analysis.scopes = observed[0]
            .analysis
            .scopes
            .iter()
            .filter(|scope| scope.observations.domain != CanonicalDomain::Joint)
            .cloned()
            .collect();
        compare(&reference, &observed).unwrap_err();
    }

    #[test]
    fn compare_archives_bounds_scope_work() {
        let reference = loaded(17);
        let mut observed = loaded(17);
        let joint = observed[0]
            .analysis
            .scopes
            .iter()
            .find(|scope| scope.observations.domain == CanonicalDomain::Joint)
            .unwrap()
            .clone();
        observed[0].analysis.scopes = vec![joint; 257].into();
        compare(&reference, &observed).unwrap_err();
    }
    #[test]
    fn compare_archive_loading_ignores_forged_derived_analysis() {
        let mut document: serde_json::Value = serde_json::from_slice(&archive(18)).unwrap();
        document["profiles"][0]["analysis"] =
            serde_json::to_value(&loaded(17)[0].analysis).unwrap();
        let observed = load_profile_archive_snapshot(
            &serde_json::to_vec(&document).unwrap(),
            false,
            ProfileArchiveLimits::default(),
        )
        .unwrap();
        assert!(!compare(&loaded(17), &observed).unwrap().literal_match);
    }
}
