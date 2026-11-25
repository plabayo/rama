use std::{
    env, fs,
    fs::{File, Permissions},
    os::unix::fs::PermissionsExt as _,
    path::PathBuf,
    process::Command,
};

use super::*;
use crate::{
    native_certs::{Error, ErrorKind, bundled_root_certs, tests::TestDir},
    pem::PemEncode as _,
};

const MALFORMED_CERT: &[u8] = b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n";

fn dirs_only(dir: &Path) -> CertPaths {
    CertPaths {
        file: None,
        dirs: vec![dir.to_owned()],
    }
}

fn file_only(file: PathBuf) -> CertPaths {
    CertPaths {
        file: Some(file),
        dirs: Vec::new(),
    }
}

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
    assert!(initial.contains(&bundled_root_certs()[0]));

    let roots = bundled_root_certs();
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
        .downcast::<Error>()
        .unwrap();
    assert!(matches!(
        error.kind,
        ErrorKind::Io { inner, .. }
            if inner.kind() == io::ErrorKind::NotFound
    ));
}

#[test]
fn extra_reload_ignores_replacement_paths_and_deduplicates_extra_roots() {
    const CHILD: &str = "RAMA_TEST_RELOAD_EXTRA_CERTS";
    let roots = bundled_root_certs();
    if env::var_os(CHILD).is_some() {
        let loaded = load_validated_extra_certs().unwrap();
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
            "native_certs::load::tests::extra_reload_ignores_replacement_paths_and_deduplicates_extra_roots",
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
fn invalid_directory_entries_are_skipped_by_system_and_explicit_reads() {
    let dir = TestDir::new("reload-system-entries");
    let valid = bundled_root_certs()[0].clone();
    fs::write(dir.0.join("valid.pem"), valid.to_pem()).unwrap();
    fs::write(dir.0.join("bad.pem"), MALFORMED_CERT).unwrap();
    fs::write(
        dir.0.join("bad-der.pem"),
        CertificateDer::from(vec![1, 2, 3]).to_pem(),
    )
    .unwrap();

    let paths = dirs_only(&dir.0);
    let expected = [valid];
    assert_eq!(load_system_paths(&paths).unwrap(), expected);
    assert_eq!(checked_load_paths(&paths).unwrap(), expected);
}

#[test]
fn explicit_directory_skips_crl_links_and_non_pem_files() {
    let dir = TestDir::new("reload-dir-crl");
    let valid = bundled_root_certs()[0].clone();
    fs::write(dir.0.join("01234567.0"), valid.to_pem()).unwrap();
    fs::write(
        dir.0.join("01234567.r0"),
        b"-----BEGIN X509 CRL-----\nAQID\n-----END X509 CRL-----\n",
    )
    .unwrap();
    fs::write(dir.0.join("README"), b"certificates managed by the host").unwrap();

    assert_eq!(checked_load_paths(&dirs_only(&dir.0)).unwrap(), [valid]);
}

#[test]
fn explicit_directory_skips_unreadable_entries() {
    let dir = TestDir::new("reload-dir-eacces");
    let valid = bundled_root_certs()[0].clone();
    let locked = bundled_root_certs()[1].clone();
    fs::write(dir.0.join("valid.pem"), valid.to_pem()).unwrap();
    let locked_path = dir.0.join("locked.pem");
    fs::write(&locked_path, locked.to_pem()).unwrap();
    fs::set_permissions(&locked_path, Permissions::from_mode(0o000)).unwrap();
    // Privileged users bypass file modes; the entry is then read as usual.
    let readable = File::open(&locked_path).is_ok();

    let loaded = checked_load_paths(&dirs_only(&dir.0)).unwrap();
    fs::set_permissions(&locked_path, Permissions::from_mode(0o600)).unwrap();
    assert!(loaded.contains(&valid));
    assert_eq!(loaded.contains(&locked), readable);
}

#[test]
fn explicit_directory_without_valid_entries_fails_unless_empty() {
    let dir = TestDir::new("reload-dir-garbage");
    let paths = dirs_only(&dir.0);
    assert!(checked_load_paths(&paths).unwrap().is_empty());
    fs::write(
        dir.0.join("crl.r0"),
        b"-----BEGIN X509 CRL-----\nAQID\n-----END X509 CRL-----\n",
    )
    .unwrap();
    assert!(checked_load_paths(&paths).unwrap().is_empty());
    fs::write(dir.0.join("bad.pem"), MALFORMED_CERT).unwrap();
    drop(checked_load_paths(&paths).unwrap_err());
}

#[test]
fn explicit_bundle_file_stays_strict() {
    let dir = TestDir::new("reload-bundle-strict");
    let file = dir.0.join("bundle.pem");
    let valid = bundled_root_certs()[0].to_pem();
    let paths = file_only(file.clone());

    fs::write(&file, [valid.as_bytes(), MALFORMED_CERT].concat()).unwrap();
    drop(checked_load_paths(&paths).unwrap_err());
    let bad_der = CertificateDer::from(vec![1, 2, 3]).to_pem();
    fs::write(&file, [valid.as_bytes(), bad_der.as_bytes()].concat()).unwrap();
    drop(checked_load_paths(&paths).unwrap_err());

    // A bad directory entry next to the bundle does not hide a strict failure.
    let certs = dir.0.join("certs");
    fs::create_dir(&certs).unwrap();
    fs::write(certs.join("valid.pem"), &valid).unwrap();
    let both = CertPaths {
        file: Some(file),
        dirs: vec![certs],
    };
    drop(checked_load_paths(&both).unwrap_err());
}

#[test]
fn unreadable_system_sources_prevent_fallback_even_when_other_roots_exist() {
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

/// Writes `cert` with its mode cleared; `Ok(false)` when the user bypasses file modes.
fn write_unreadable(path: &Path, cert: &CertificateDer<'static>) -> io::Result<bool> {
    fs::write(path, cert.to_pem())?;
    fs::set_permissions(path, Permissions::from_mode(0o000))?;
    Ok(File::open(path).is_err())
}

fn restore_mode(path: &Path) -> io::Result<()> {
    fs::set_permissions(path, Permissions::from_mode(0o600))
}

#[test]
fn an_unreadable_directory_fails_without_bundled_fallback() {
    let dir = TestDir::new("reload-dir-all-eacces");
    let locked = dir.0.join("private-root.pem");
    if !write_unreadable(&locked, &bundled_root_certs()[0]).unwrap() {
        restore_mode(&locked).unwrap();
        return;
    }
    let unset = CertPaths {
        file: None,
        dirs: Vec::new(),
    };
    let system = dirs_only(&dir.0);
    let system_error = load_system_paths(&system).map(drop).unwrap_err();
    let fallback = load_from_sources(&unset, &unset, true, || load_system_paths(&system));
    let explicit = checked_load_paths(&system);
    restore_mode(&locked).unwrap();

    let error = system_error.downcast::<Error>().unwrap();
    assert!(matches!(
        error.kind,
        ErrorKind::Io { inner, .. } if inner.kind() == io::ErrorKind::PermissionDenied
    ));
    drop(fallback.unwrap_err());
    drop(explicit.unwrap_err());
}

#[test]
fn a_partly_unreadable_system_directory_loads_the_readable_certificates() {
    let dir = TestDir::new("reload-dir-some-eacces");
    let valid = bundled_root_certs()[0].clone();
    fs::write(dir.0.join("valid.pem"), valid.to_pem()).unwrap();
    let locked = dir.0.join("private-root.pem");
    let unreadable = write_unreadable(&locked, &bundled_root_certs()[1]).unwrap();
    let loaded = load_system_paths(&dirs_only(&dir.0));
    restore_mode(&locked).unwrap();

    let loaded = loaded.unwrap();
    assert!(loaded.contains(&valid));
    assert_eq!(loaded.len(), if unreadable { 1 } else { 2 });
}

#[test]
fn an_empty_system_directory_keeps_the_bundled_fallback() {
    let dir = TestDir::new("reload-dir-empty");
    let unset = CertPaths {
        file: None,
        dirs: Vec::new(),
    };
    let system = dirs_only(&dir.0);
    assert!(load_system_paths(&system).unwrap().is_empty());
    let (roots, bundled) =
        load_from_sources(&unset, &unset, true, || load_system_paths(&system)).unwrap();
    assert!(bundled);
    assert_eq!(roots.len(), bundled_root_certs().len());
    assert!(checked_load_paths(&system).unwrap().is_empty());
}
