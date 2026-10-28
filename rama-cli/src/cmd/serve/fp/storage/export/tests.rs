use super::*;
use rama::ua::profile::{
    evidence::ProfileEvidence, format::compiled::try_load_compiled_profiles,
    model::identity::ProfileKey,
};

#[test]
fn export_publishes_complete_json_and_does_not_clobber_without_replace() {
    let parent = TempDir::new().unwrap();
    let output = parent.path().join("profiles.json");
    StagedExport::create(
        output.clone(),
        false,
        false,
        100,
        14,
        ProfileArchiveLimits {
            bytes: kib(4),
            ..ProfileArchiveLimits::default()
        },
    )
    .unwrap()
    .finish()
    .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(value["format_version"], 1);
    assert_eq!(value["profiles"].as_array().unwrap().len(), 0);
    fs::write(&output, b"prior content").unwrap();
    StagedExport::create(
        output.clone(),
        false,
        false,
        100,
        14,
        ProfileArchiveLimits {
            bytes: kib(4),
            ..ProfileArchiveLimits::default()
        },
    )
    .unwrap()
    .finish()
    .unwrap_err();
    assert_eq!(fs::read(&output).unwrap(), b"prior content");
    StagedExport::create(
        output.clone(),
        true,
        false,
        100,
        14,
        ProfileArchiveLimits {
            bytes: kib(4),
            ..ProfileArchiveLimits::default()
        },
    )
    .unwrap()
    .finish()
    .unwrap();
    serde_json::from_slice::<serde_json::Value>(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 1);
}

#[test]
fn bounded_or_invalid_exports_publish_nothing_and_remove_staging() {
    let parent = TempDir::new().unwrap();
    let output = parent.path().join("profiles.json");
    match StagedExport::create(
        output.clone(),
        false,
        false,
        100,
        14,
        ProfileArchiveLimits {
            bytes: 1,
            ..ProfileArchiveLimits::default()
        },
    ) {
        Err(_error) => (),
        Ok(_export) => panic!("archive byte bound was ignored"),
    }
    assert!(!output.exists());
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    let mut profile = ProfileKey::new("library").canonical(kib(16)).unwrap();
    profile.id.0[0] ^= 1;
    let evidence = ProfileEvidence {
        format_version: 1,
        profile,
        scopes: Box::default(),
    };
    let error = StagedExport::create(
        output.clone(),
        false,
        false,
        100,
        14,
        ProfileArchiveLimits {
            bytes: kib(4),
            ..ProfileArchiveLimits::default()
        },
    )
    .unwrap()
    .write(ProfileArchiveEntry {
        evidence,
        sampler_seed: [0; 32],
    });
    match error {
        Err(_error) => (),
        Ok(_export) => panic!("invalid evidence was accepted"),
    }
    assert!(!output.exists());
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[test]
fn embed_publishes_a_bounded_compiled_set() {
    let parent = TempDir::new().unwrap();
    let input = parent.path().join("profiles.json");
    let output = parent.path().join("embed_profiles.bin");
    StagedExport::create(
        input.clone(),
        false,
        false,
        100,
        14,
        ProfileArchiveLimits::default(),
    )
    .unwrap()
    .write(ProfileArchiveEntry {
        evidence: ProfileEvidence {
            format_version: 1,
            profile: ProfileKey::new("library").canonical(kib(16)).unwrap(),
            scopes: Box::default(),
        },
        sampler_seed: [0; 32],
    })
    .unwrap()
    .finish()
    .unwrap();
    let command = |max_input_bytes, max_output_bytes| CompactProfilesCommand {
        input: input.clone(),
        output: output.clone(),
        replace: false,
        include_legacy: false,
        exclude_user_agents: Vec::new(),
        max_input_bytes,
        max_output_bytes,
    };
    compact_profile_archive(&command(4, kib(64))).unwrap_err();
    assert!(!output.exists());
    // An empty set does not load, so nothing is published.
    publish_compiled(&output, false, kib(64), &[]).unwrap_err();
    assert!(!output.exists());
    compact_profile_archive(&command(kib(64), kib(64))).unwrap();
    let compiled = fs::read(&output).unwrap();
    let profiles = try_load_compiled_profiles(&compiled).unwrap();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].key.client.as_ref(), "library");
    // The output bound applies to the compiled bytes.
    fs::remove_file(&output).unwrap();
    compact_profile_archive(&command(kib(64), compiled.len() - 1)).unwrap_err();
    assert!(!output.exists());
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 1);
}

#[test]
fn compact_recompiles_a_compiled_set_without_excluded_user_agents() {
    let parent = TempDir::new().unwrap();
    let input = parent.path().join("profiles.json");
    let compiled = parent.path().join("embed_profiles.bin");
    let filtered = parent.path().join("filtered.bin");
    let entry = |user_agent: &str| ProfileArchiveEntry {
        evidence: ProfileEvidence {
            format_version: 1,
            profile: ProfileKey {
                user_agent: Some(user_agent.into()),
                ..ProfileKey::new("library")
            }
            .canonical(kib(16))
            .unwrap(),
            scopes: Box::default(),
        },
        sampler_seed: [0; 32],
    };
    StagedExport::create(
        input.clone(),
        false,
        false,
        100,
        14,
        ProfileArchiveLimits::default(),
    )
    .unwrap()
    .write(entry("kept/1"))
    .unwrap()
    .write(entry("dropped/1"))
    .unwrap()
    .finish()
    .unwrap();
    let command = |input: &Path, output: &Path, exclude: &[&str]| CompactProfilesCommand {
        input: input.to_owned(),
        output: output.to_owned(),
        replace: false,
        include_legacy: false,
        exclude_user_agents: exclude.iter().copied().map(Into::into).collect(),
        max_input_bytes: kib(64),
        max_output_bytes: kib(64),
    };
    compact_profile_archive(&command(&input, &compiled, &[])).unwrap();
    compact_profile_archive(&command(&compiled, &filtered, &["dropped/1"])).unwrap();
    let profiles = try_load_compiled_profiles(&fs::read(&filtered).unwrap()).unwrap();
    let user_agents: Vec<_> = profiles
        .iter()
        .map(|profile| profile.key.user_agent.as_deref().unwrap())
        .collect();
    assert_eq!(user_agents, ["kept/1"]);
}

#[test]
fn export_orders_selected_scopes_canonically() {
    use rama::ua::profile::{
        analysis::profile::ProfileAnalysisLimits,
        capture::{
            completeness::ProfileCaptureCompleteness,
            joint::{CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture},
            observation::ProfileCapture,
            order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture},
        },
        evidence::{collector::ProfileEvidenceCollector, transaction::CaptureRunId},
        model::identity::ConnectionContext,
    };
    let profile = ProfileKey::new("export-order");
    let mut collector = ProfileEvidenceCollector::new(
        &profile,
        false,
        CaptureRunId::new(100, [1; 12]),
        [2; 32],
        100,
        ProfileAnalysisLimits::default(),
    )
    .unwrap();
    let limits = OrderCaptureLimits::default();
    for setting in [1, 7] {
        collector
            .observe(
                100,
                &ProfileCapture {
                    profile: profile.clone(),
                    flow: None,
                    connection: ConnectionContext::default(),
                    joint: JointCapture {
                        completeness: ProfileCaptureCompleteness::Complete,
                        level: CaptureLevel::Connection,
                        slots: Box::new([CapturedSlot {
                            kind: CapturedSlotKind::Http3Settings,
                            value: OrderedProtocolCapture::capture(
                                ProfileCaptureCompleteness::Complete,
                                OrderNamespace::Http3Setting,
                                [(setting, 1u64.to_be_bytes())],
                                limits,
                            )
                            .unwrap()
                            .canonical(limits)
                            .unwrap(),
                        }]),
                    },
                },
            )
            .unwrap();
    }
    let mut evidence = collector.finish();
    assert!(evidence.scopes.len() >= 2);
    evidence
        .scopes
        .sort_unstable_by_key(|scope| std::cmp::Reverse(scope.scope.id));
    let parent = TempDir::new().unwrap();
    let output = parent.path().join("profiles.json");
    StagedExport::create(
        output.clone(),
        false,
        false,
        100,
        14,
        ProfileArchiveLimits::default(),
    )
    .unwrap()
    .write(ProfileArchiveEntry {
        evidence,
        sampler_seed: [2; 32],
    })
    .unwrap()
    .finish()
    .unwrap();
    let loaded = rama::ua::profile::format::archive::load_profile_archive_snapshot(
        &fs::read(output).unwrap(),
        false,
        ProfileArchiveLimits::default(),
    )
    .unwrap();
    assert_eq!(loaded.len(), 1);
    assert!(
        loaded[0]
            .evidence
            .scopes
            .windows(2)
            .all(|pair| pair[0].scope.id < pair[1].scope.id)
    );
}

#[test]
fn only_profiles_without_captured_flows_count_as_legacy_only() {
    use CanonicalDomain::{Headers, Joint, LegacyField, Tls};
    assert!(legacy_only([LegacyField, LegacyField]));
    assert!(legacy_only([LegacyField, Tls]));
    assert!(!legacy_only([LegacyField, Joint]));
    assert!(!legacy_only([Joint, Headers]));
    assert!(!legacy_only([]));
}
