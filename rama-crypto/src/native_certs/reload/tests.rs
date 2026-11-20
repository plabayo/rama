use super::*;
use crate::native_certs::tests::TestDir;
use std::fs;

#[test]
fn explicit_empty_file_differs_from_invalid_pem() {
    let dir = TestDir::new("reload-empty");
    let file = dir.0.join("bundle.pem");
    let paths = CertPaths {
        file: Some(file.clone()),
        dirs: Vec::new(),
    };
    drop(checked_load_paths(&paths).unwrap_err());
    fs::write(&file, "broken trust bundle").unwrap();
    drop(checked_load_paths(&paths).unwrap_err());
    fs::write(&file, " \n").unwrap();
    assert!(checked_load_paths(&paths).unwrap().is_empty());
}

#[test]
fn a_successful_empty_system_store_clears_live_roots() {
    use crate::pem::PemEncode as _;

    let dir = TestDir::new("reload-empty-system");
    let bundle = dir.0.join("system.pem");
    let extra_file = dir.0.join("extra.pem");
    let system = CertPaths {
        file: Some(bundle.clone()),
        dirs: Vec::new(),
    };
    let extra = CertPaths {
        file: Some(extra_file.clone()),
        dirs: Vec::new(),
    };
    let unset = CertPaths {
        file: None,
        dirs: Vec::new(),
    };
    let refresh = |extra: &CertPaths, fallback| {
        load_from_sources(&unset, extra, fallback, || checked_load_paths(&system))
    };

    fs::write(&bundle, b"").unwrap();
    let (initial, bundled) = refresh(&unset, true).unwrap();
    assert!(bundled);
    assert!(initial.contains(&crate::native_certs::bundled_root_certs()[0]));

    let roots = crate::native_certs::bundled_root_certs();
    fs::write(&bundle, roots[0].to_pem()).unwrap();
    fs::write(&extra_file, roots[1].to_pem()).unwrap();
    let (live, bundled) = refresh(&extra, bundled).unwrap();
    assert!(!bundled);
    assert_eq!(live.len(), 2);
    assert!(live.contains(&roots[0]));
    assert!(live.contains(&roots[1]));

    fs::write(&bundle, b"").unwrap();
    let (extra_only, bundled) = refresh(&extra, bundled).unwrap();
    assert!(!bundled);
    assert_eq!(extra_only, &[roots[1].clone()]);
    let (empty, bundled) = refresh(&unset, bundled).unwrap();
    assert!(!bundled);
    assert!(empty.is_empty());

    fs::remove_file(&bundle).unwrap();
    let error = refresh(&extra, bundled)
        .unwrap_err()
        .downcast::<crate::native_certs::Error>()
        .unwrap();
    assert!(matches!(
        error.kind,
        crate::native_certs::ErrorKind::Io { inner, .. }
            if inner.kind() == io::ErrorKind::NotFound
    ));
}
