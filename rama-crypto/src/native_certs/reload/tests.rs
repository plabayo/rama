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

#[test]
fn extra_reload_ignores_replacement_paths_and_deduplicates_extra_roots() {
    use crate::{native_certs::bundled_root_certs, pem::PemEncode as _};
    use std::{env, process::Command};

    const CHILD: &str = "RAMA_TEST_RELOAD_EXTRA_CERTS";
    let roots = bundled_root_certs();
    if env::var_os(CHILD).is_some() {
        let loaded = load_reloadable_extra_certs().unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains(&roots[0]));
        assert!(loaded.contains(&roots[1]));
        assert!(loaded[0].cmp(&loaded[1]).is_lt());
        return;
    }

    let dir = TestDir::new("reload-extra-env");
    let extra_dir = dir.0.join("extras");
    let extra_file = dir.0.join("extra.pem");
    fs::create_dir(&extra_dir).unwrap();
    fs::write(&extra_file, roots[1].to_pem()).unwrap();
    fs::write(extra_dir.join("duplicate.pem"), roots[1].to_pem()).unwrap();
    fs::write(extra_dir.join("another.pem"), roots[0].to_pem()).unwrap();

    let status = Command::new(env::current_exe().unwrap())
        .args([
            "--exact",
            "native_certs::reload::tests::extra_reload_ignores_replacement_paths_and_deduplicates_extra_roots",
        ])
        .env(CHILD, "1")
        .env("SSL_CERT_FILE", dir.0.join("missing-native.pem"))
        .env("SSL_CERT_DIR", dir.0.join("missing-native-dir"))
        .env(ENV_EXTRA_CERT_FILE, &extra_file)
        .env(ENV_EXTRA_CERT_DIR, &extra_dir)
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn system_entries_can_be_skipped_but_explicit_directories_stay_strict() {
    use crate::{native_certs::bundled_root_certs, pem::PemEncode as _};

    let dir = TestDir::new("reload-system-entries");
    let valid = bundled_root_certs()[0].clone();
    fs::write(dir.0.join("valid.pem"), valid.to_pem()).unwrap();
    fs::write(
        dir.0.join("bad.pem"),
        b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    fs::write(
        dir.0.join("bad-der.pem"),
        CertificateDer::from(vec![1, 2, 3]).to_pem(),
    )
    .unwrap();

    let paths = CertPaths {
        file: None,
        dirs: vec![dir.0.clone()],
    };
    assert_eq!(load_system_paths(&paths).unwrap(), [valid]);
    drop(checked_load_paths(&paths).unwrap_err());
}

#[test]
fn unreadable_system_sources_prevent_fallback_even_when_other_roots_exist() {
    use crate::{native_certs::bundled_root_certs, pem::PemEncode as _};

    let dir = TestDir::new("reload-system-source-failure");
    let root = bundled_root_certs()[0].clone();
    fs::write(dir.0.join("valid.pem"), root.to_pem()).unwrap();
    let unset = CertPaths {
        file: None,
        dirs: Vec::new(),
    };
    let system = CertPaths {
        file: None,
        dirs: vec![dir.0.clone(), dir.0.join("missing")],
    };
    let read = || load_system_paths(&system);
    drop(load_from_sources(&unset, &unset, true, read).unwrap_err());
}

#[test]
fn all_malformed_system_entries_do_not_enable_bundled_fallback() {
    let unset = CertPaths {
        file: None,
        dirs: Vec::new(),
    };
    let result = load_from_sources(&unset, &unset, true, || {
        let mut system = CertificateResult::default();
        system.certs.push(CertificateDer::from(vec![1, 2, 3]));
        checked_system_load(system)
    });
    drop(result.unwrap_err());
}
