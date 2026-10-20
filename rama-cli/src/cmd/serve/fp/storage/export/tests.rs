use super::*;
use rama::ua::profile::{
    evidence::ProfileEvidence, format::compressed::decompress_profile_archive,
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
fn embed_exports_publish_validated_compressed_evidence_only() {
    let parent = TempDir::new().unwrap();
    let output = parent.path().join("profiles.json.zst");
    let entry = || ProfileArchiveEntry {
        evidence: ProfileEvidence {
            format_version: 1,
            profile: ProfileKey::new("library").canonical(kib(16)).unwrap(),
            scopes: Box::default(),
        },
        sampler_seed: [0; 32],
    };
    let export = |bytes| {
        StagedExport::create(
            output.clone(),
            true,
            true,
            false,
            100,
            14,
            ProfileArchiveLimits {
                bytes,
                ..ProfileArchiveLimits::default()
            },
        )
    };
    // An empty archive does not load, so nothing is published.
    export(kib(4)).unwrap().finish().unwrap_err();
    assert!(!output.exists());
    export(kib(4))
        .unwrap()
        .write(entry())
        .unwrap()
        .finish()
        .unwrap();
    let compressed = fs::read(&output).unwrap();
    let profiles = try_load_compressed_profiles(&compressed).unwrap();
    assert_eq!(profiles.len(), 1);
    let json = decompress_profile_archive(&compressed, kib(64)).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert!(value["profiles"][0].get("analysis").is_none());
    assert!(value["profiles"][0].get("evidence").is_some());
    // The output bound applies to the compressed bytes.
    fs::remove_file(&output).unwrap();
    let bounded = export(compressed.len() - 1)
        .and_then(|export| export.write(entry()))
        .and_then(StagedExport::finish);
    assert!(bounded.is_err());
    assert!(!output.exists());
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[test]
fn compaction_rewrites_an_archive_without_analysis() {
    let parent = TempDir::new().unwrap();
    let input = parent.path().join("profiles.json");
    let output = parent.path().join("profiles.json.zst");
    StagedExport::create(
        input.clone(),
        false,
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
    let command = |max_input_bytes| CompactProfilesCommand {
        input: input.clone(),
        output: output.clone(),
        replace: false,
        max_input_bytes,
        max_output_bytes: kib(64),
    };
    compact_profile_archive(command(4)).unwrap_err();
    assert!(!output.exists());
    compact_profile_archive(command(kib(64))).unwrap();
    let profiles = try_load_compressed_profiles(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].key.client.as_ref(), "library");
}
