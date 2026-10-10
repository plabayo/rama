use super::*;
use rama::ua::profile::ProfileKey;

#[test]
fn export_publishes_complete_json_and_does_not_clobber_without_replace() {
    let parent = TempDir::new().unwrap();
    let output = parent.path().join("profiles.json");
    StagedExport::create(output.clone(), false, kib(4), 100, 14)
        .unwrap()
        .finish()
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(value["format_version"], 1);
    assert_eq!(value["profiles"].as_array().unwrap().len(), 0);
    fs::write(&output, b"prior content").unwrap();
    StagedExport::create(output.clone(), false, kib(4), 100, 14)
        .unwrap()
        .finish()
        .unwrap_err();
    assert_eq!(fs::read(&output).unwrap(), b"prior content");
    StagedExport::create(output.clone(), true, kib(4), 100, 14)
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
    StagedExport::create(output.clone(), false, 1, 100, 14)
        .unwrap()
        .finish()
        .unwrap_err();
    assert!(!output.exists());
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    let mut profile = ProfileKey::new("library").canonical(kib(16)).unwrap();
    profile.id.0[0] ^= 1;
    let evidence = ProfileEvidence {
        format_version: 1,
        profile,
        scopes: Box::default(),
    };
    let error = StagedExport::create(output.clone(), false, kib(4), 100, 14)
        .unwrap()
        .write(
            evidence,
            [0; 32],
            false,
            100,
            14,
            ProfileAnalysisLimits::default(),
        );
    match error {
        Err(_error) => (),
        Ok(_export) => panic!("invalid evidence was accepted"),
    }
    assert!(!output.exists());
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}
