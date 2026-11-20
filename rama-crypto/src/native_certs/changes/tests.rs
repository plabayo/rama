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
    assert!(!changes.probe_files(Some(&base), &extra, now));
    fs::write(&replacement, b"other").unwrap();
    fs::rename(&replacement, &bundle).unwrap();
    assert!(!changes.probe_due());
    assert!(changes.probe_files(Some(&base), &extra, now));
    assert!(!changes.probe_files(Some(&base), &extra, now));
    fs::write(&extra_anchor, b"different").unwrap();
    assert!(changes.probe_files(Some(&base), &extra, now));
}

#[test]
fn extra_only_probes_file_and_directory_without_resolving_native_paths() {
    let dir = TestDir::new("reload-extra-metadata");
    let extra_file = dir.0.join("extra.pem");
    let extra_dir = dir.0.join("extra");
    let extra_anchor = extra_dir.join("anchor.pem");
    fs::create_dir(&extra_dir).unwrap();
    fs::write(&extra_file, b"first").unwrap();
    fs::write(&extra_anchor, b"first").unwrap();
    let extra = CertPaths {
        file: Some(extra_file.clone()),
        dirs: vec![extra_dir],
    };
    let mut changes = NativeCertsChanges::extra_only(Duration::ZERO);
    let native = || panic!("extra-root probes must not resolve native paths");
    let mut probe = || changes.probe_sources(&extra, native, Instant::now());

    assert!(!probe());
    fs::write(&extra_file, b"second").unwrap();
    assert!(probe());
    assert!(!probe());
    fs::remove_file(&extra_anchor).unwrap();
    assert!(probe());
    assert!(!probe());
    #[cfg(target_os = "macos")]
    assert!(changes.notifications.is_none());
}

#[cfg(target_os = "macos")]
#[test]
fn resuming_native_notifications_refreshes_once_across_the_gap() {
    let system = CertPaths {
        file: None,
        dirs: Vec::new(),
    };
    let mut changes = NativeCertsChanges::new(Duration::ZERO);
    assert!(!changes.check_store(&system));
    changes.probed_at = Some(Instant::now());
    changes
        .notifications
        .as_mut()
        .unwrap()
        .invalidate_token_for_test();
    assert!(changes.check_store(&system));
    assert!(!changes.check_store(&system));
}
