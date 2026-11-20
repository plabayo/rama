use super::*;
use crate::native_certs::tests::TestDir;

#[test]
fn observes_atomically_replaced_bundle_and_in_place_directory_changes() {
    let dir = TestDir::new("reload-metadata");
    let bundle = dir.0.join("bundle.pem");
    let replacement = dir.0.join("replacement.pem");
    let extra_dir = dir.0.join("extra");
    let extra_anchor = extra_dir.join("anchor.pem");
    fs::create_dir(&extra_dir).unwrap();
    fs::write(&bundle, b"first").unwrap();
    fs::write(&extra_anchor, b"first").unwrap();
    let base = CertPaths {
        file: Some(bundle.clone()),
        dirs: Vec::new(),
    };
    let extra = CertPaths {
        file: None,
        dirs: vec![extra_dir],
    };
    let mut changes = NativeCertsChanges::new(Duration::from_secs(60));
    let now = Instant::now();
    assert!(changes.probe_due());
    assert!(!changes.probe_files(&base, &extra, now));
    fs::write(&replacement, b"other").unwrap();
    fs::rename(&replacement, &bundle).unwrap();
    assert!(!changes.probe_due());
    assert!(changes.probe_files(&base, &extra, now));
    assert!(!changes.probe_files(&base, &extra, now));
    fs::write(&extra_anchor, b"different").unwrap();
    assert!(changes.probe_files(&base, &extra, now));
}
