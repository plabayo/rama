//! Conservative, offline comparison of retained complete capture tuples.

use clap::Args;
use rama::{
    error::{BoxError, BoxErrorExt as _},
    ua::profile::{
        analysis::profile::AnalyzedProfileScope,
        compare::{
            CaptureComparisonLimits, RetainedCaptureComparison, compare_retained_captures,
            mode::ComparisonMode,
        },
        format::{
            archive::{
                CompiledProfileArchiveEntry, ProfileArchiveLimits, load_profile_archive_snapshot,
            },
            canonical::{CanonicalDomain, ValueId},
        },
    },
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
    #[arg(long, required_unless_present = "replay", conflicts_with = "replay")]
    literal: bool,
    /// Compare replay-preserved fields, excluding peer-driven H2 SETTINGS acknowledgements.
    #[arg(long)]
    replay: bool,
    /// Read the authorized partition in both archives.
    #[arg(long)]
    authorized: bool,
    /// Compare only exercised contexts and report unexercised reference contexts.
    #[arg(long)]
    allow_partial_coverage: bool,
}

impl CompareCommand {
    fn mode(&self) -> Result<ComparisonMode, BoxError> {
        match (self.literal, self.replay) {
            (true, false) => Ok(ComparisonMode::Literal),
            (false, true) => Ok(ComparisonMode::Replay),
            _ => Err(BoxError::from_static_str(
                "select exactly one of --literal or --replay",
            )),
        }
    }
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
    mode: ComparisonMode,
    excluded_events: &'static [&'static str],
    matched: bool,
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
    let mode = command.mode()?;
    let reference = read(&command.reference, command.authorized)?;
    let observed = read(&command.observed, command.authorized)?;
    let report =
        compare_with_coverage(&reference, &observed, command.allow_partial_coverage, mode)?;
    let encoded = serde_json::to_vec_pretty(&report)?;
    if encoded.len() > 8 * 1024 * 1024 {
        return Err(BoxError::from_static_str("comparison report byte limit"));
    }
    let mut output = io::stdout().lock();
    output.write_all(&encoded)?;
    output.write_all(b"\n")?;
    if report.matched {
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
    mode: ComparisonMode,
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
        mode,
        excluded_events: mode.excluded_events(),
        matched: true,
        reference_coverage_complete: true,
        partial_coverage_allowed: allow_partial_coverage,
        comparisons: Vec::new(),
        missing_reference_scopes: Vec::new(),
        unrecognized_observed_scopes: Vec::new(),
        limitations: concat!(
            "Complete retained tuples and context coverage under the reported exclusions. ",
            "No wire-equivalence, generator or distribution claim. ",
            "Bound values do not retain original secrets or destinations.",
        ),
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
                report.matched = false;
                continue;
            }
            for variant in &scope.observations.variants {
                if report.comparisons.len() == MAX_COMPARISONS {
                    return Err(BoxError::from_static_str("comparison variant limit"));
                }
                let comparison = compare_retained_captures(
                    &candidates,
                    &variant.value,
                    mode,
                    CaptureComparisonLimits {
                        work: budget,
                        ..Default::default()
                    },
                )?;
                budget = budget
                    .checked_sub(comparison.work_units)
                    .ok_or_else(|| BoxError::from_static_str("comparison work limit"))?;
                report.matched &= comparison.matched;
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
                    report.matched = false;
                }
            }
        }
    }
    if report.comparisons.is_empty() {
        report.matched = false;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::ua::profile::{
        capture::{
            completeness::ProfileCaptureCompleteness,
            joint::{
                CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits,
            },
            observation::ProfileCapture,
            order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture},
        },
        evidence::{
            ProfileEvidence, ProfileScopeEvidence,
            ingestion::ObservationId,
            window::{ProfileWindowLimits, RetainedBucketWindow},
        },
        format::archive::{ProfileArchiveEntry, ProfileArchiveWriter},
        model::identity::{ConnectionContext, ProfileKey},
    };
    #[test]
    fn cli_requires_one_explicit_comparison_mode() {
        use crate::cmd::ua::UaSubcommand;
        use crate::{Cli, CliCommands};
        use clap::Parser as _;

        for (flag, mode) in [
            ("--literal", ComparisonMode::Literal),
            ("--replay", ComparisonMode::Replay),
        ] {
            let cli = Cli::try_parse_from([
                "rama",
                "ua",
                "compare",
                flag,
                "reference.json",
                "observed.json",
            ])
            .unwrap();
            let Some(CliCommands::Ua(command)) = cli.cmds else {
                panic!("expected UA command")
            };
            let UaSubcommand::Compare(command) = command.command else {
                panic!("expected comparison")
            };
            assert_eq!(command.mode().unwrap(), mode);
        }
        Cli::try_parse_from(["rama", "ua", "compare", "reference.json", "observed.json"])
            .unwrap_err();
        Cli::try_parse_from([
            "rama",
            "ua",
            "compare",
            "--literal",
            "--replay",
            "reference.json",
            "observed.json",
        ])
        .unwrap_err();
    }

    fn compare(
        reference: &[CompiledProfileArchiveEntry],
        observed: &[CompiledProfileArchiveEntry],
    ) -> Result<Report, BoxError> {
        compare_with_coverage(reference, observed, false, ComparisonMode::Literal)
    }
    #[test]
    fn replay_mode_uses_the_same_coverage_gate_and_reports_its_exclusions() {
        use rama::ua::profile::capture::http2::{
            H2Capture, H2CaptureLimits, H2CapturedFrame, H2CapturedSetting,
        };
        let archive = |ack| {
            let mut frames = vec![H2CapturedFrame::Settings {
                ack: false,
                entries: vec![H2CapturedSetting { id: 1, value: 4096 }].into(),
            }];
            if ack {
                frames.push(H2CapturedFrame::Settings {
                    ack: true,
                    entries: Box::default(),
                });
            }
            let joint = JointCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                level: CaptureLevel::Connection,
                slots: vec![CapturedSlot {
                    kind: CapturedSlotKind::Http2EarlyFrames,
                    value: H2Capture {
                        completeness: ProfileCaptureCompleteness::Complete,
                        frames: frames.into(),
                    }
                    .canonical(H2CaptureLimits::default())
                    .unwrap(),
                }]
                .into(),
            };
            load_profile_archive_snapshot(
                &archive_joint(joint, ConnectionContext::default()),
                false,
                ProfileArchiveLimits::default(),
            )
            .unwrap()
        };
        let reference = archive(true);
        let observed = archive(false);
        assert!(
            !compare_with_coverage(&reference, &observed, false, ComparisonMode::Literal)
                .unwrap()
                .matched
        );
        let report =
            compare_with_coverage(&reference, &observed, false, ComparisonMode::Replay).unwrap();
        assert!(report.matched);
        assert!(report.reference_coverage_complete);
        assert!(!report.excluded_events.is_empty());
    }

    fn archive(value: u64) -> Vec<u8> {
        archive_for_connection(value, ConnectionContext::default())
    }
    fn archive_for_connection(value: u64, connection: ConnectionContext) -> Vec<u8> {
        let settings = OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::Http3Setting,
            [(33, value.to_be_bytes())],
            OrderCaptureLimits::default(),
        )
        .unwrap()
        .canonical(OrderCaptureLimits::default())
        .unwrap();
        archive_joint(
            JointCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                level: CaptureLevel::Connection,
                slots: vec![CapturedSlot {
                    kind: CapturedSlotKind::Http3Settings,
                    value: settings,
                }]
                .into(),
            },
            connection,
        )
    }

    fn archive_joint(joint: JointCapture, connection: ConnectionContext) -> Vec<u8> {
        let profile = ProfileKey::new("comparison-test");
        let capture = ProfileCapture {
            profile: profile.clone(),
            flow: None,
            connection,
            joint,
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
        assert!(compare(&reference, &observed).unwrap().matched);
        assert!(!compare(&reference, &loaded(18)).unwrap().matched);
        observed[0].analysis.scopes = observed[0]
            .analysis
            .scopes
            .iter()
            .filter(|scope| scope.observations.domain == CanonicalDomain::Joint)
            .cloned()
            .collect();
        let report = compare(&reference, &observed).unwrap();
        assert!(!report.matched);
        assert_eq!(report.missing_reference_scopes.len(), 1);
        let partial =
            compare_with_coverage(&reference, &observed, true, ComparisonMode::Literal).unwrap();
        assert!(partial.matched);
        assert!(!partial.reference_coverage_complete);
        assert_eq!(partial.missing_reference_scopes.len(), 1);
        observed[0].analysis.scopes[0]
            .context
            .connection
            .token_present = Some(true);
        assert!(!compare(&reference, &observed).unwrap().matched);
        compare(&[], &observed).unwrap_err();
        compare(&reference, &[]).unwrap_err();
        observed[0].analysis.scopes = Box::default();
        compare(&reference, &observed).unwrap_err();
    }
    #[test]
    fn compare_archives_requires_matching_connection_context() {
        let reference = loaded(17);
        let mut observed = loaded(17);
        assert!(compare(&reference, &observed).unwrap().matched);
        for scope in &mut observed[0].analysis.scopes {
            scope.context.connection.token_present = Some(true);
        }
        let report = compare(&reference, &observed).unwrap();
        assert!(!report.matched);
        assert!(!report.unrecognized_observed_scopes.is_empty());
        assert!(!report.missing_reference_scopes.is_empty());
    }

    #[test]
    fn compare_archives_rejects_unknown_context_beside_matching_captures() {
        let reference = loaded(17);
        let mut observed = loaded(17);
        let unknown = load_profile_archive_snapshot(
            &archive_for_connection(
                17,
                ConnectionContext {
                    token_present: Some(true),
                    ..Default::default()
                },
            ),
            false,
            ProfileArchiveLimits::default(),
        )
        .unwrap();
        let unknown_scopes: Vec<_> = unknown[0]
            .analysis
            .scopes
            .iter()
            .map(|scope| scope.id)
            .collect();
        observed[0].analysis.scopes = observed[0]
            .analysis
            .scopes
            .iter()
            .chain(unknown[0].analysis.scopes.iter())
            .cloned()
            .collect();
        for allow_partial_coverage in [false, true] {
            let report = compare_with_coverage(
                &reference,
                &observed,
                allow_partial_coverage,
                ComparisonMode::Literal,
            )
            .unwrap();
            assert!(!report.comparisons.is_empty());
            assert!(
                report
                    .comparisons
                    .iter()
                    .all(|item| item.comparison.matched)
            );
            assert!(report.missing_reference_scopes.is_empty());
            assert!(report.reference_coverage_complete);
            assert_eq!(report.unrecognized_observed_scopes, unknown_scopes);
            assert!(
                !report.matched,
                "unknown contexts must fail even beside matching covered contexts"
            );
        }
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
        assert!(!compare(&loaded(17), &observed).unwrap().matched);
    }
}
