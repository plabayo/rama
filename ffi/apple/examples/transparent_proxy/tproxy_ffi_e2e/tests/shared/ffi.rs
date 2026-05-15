use std::{
    env,
    path::{Path, PathBuf},
    ptr,
    sync::{Arc, OnceLock},
};

use rama::{
    net::tls::server::SelfSignedData,
    tls::boring::{
        core::x509::{X509, store::X509StoreBuilder},
        server::utils::self_signed_server_auth_gen_ca,
    },
};

use super::{bindings, types::BADGE_LABEL};

static MITM_CA: OnceLock<(String, String)> = OnceLock::new();

fn get_or_generate_mitm_ca() -> &'static (String, String) {
    MITM_CA.get_or_init(|| {
        let (cert, key) = self_signed_server_auth_gen_ca(&SelfSignedData {
            organisation_name: Some("Rama Transparent Proxy E2E Test Root CA".to_owned()),
            ..Default::default()
        })
        .expect("generate e2e test MITM CA");
        let cert_pem = String::from_utf8(cert.to_pem().expect("encode cert to PEM"))
            .expect("cert PEM is valid UTF-8");
        let key_pem = String::from_utf8(key.private_key_to_pem_pkcs8().expect("encode key to PEM"))
            .expect("key PEM is valid UTF-8");
        (cert_pem, key_pem)
    })
}

pub(crate) fn test_storage_dir() -> PathBuf {
    env::temp_dir().join("rama_tproxy_ffi_e2e")
}

pub(crate) fn initialize_ffi(storage_dir: &Path) {
    // Opt out of dial9 telemetry for the e2e suite. dial9's writer
    // task doesn't observe the engine's shutdown signal, so each
    // engine's tokio runtime drop leaks its worker-thread FDs;
    // production keeps dial9 on by default and this only affects
    // the test harness. Done at FFI init time so the env var is
    // visible to every engine the example library subsequently
    // constructs.
    //
    // SAFETY: `set_var` is unsound across threads only if another
    // thread reads the env concurrently. `initialize_ffi` is
    // called once from the test setup under a `OnceLock`, before
    // any engine exists, so no concurrent reader can race.
    unsafe {
        std::env::set_var("RAMA_TPROXY_DIAL9_DISABLED", "true");
    }

    // Raise the per-process soft FD limit. The e2e suite spins up
    // ~50 fresh transparent-proxy engines (each with its own
    // multi-thread tokio runtime, plus 6 spawned servers per test)
    // and the engine drop doesn't synchronously close every FD
    // before the next test starts. On the macOS-default
    // `ulimit -n` 256 the suite trips EMFILE around test 38 with
    // `Too many open files (os error 24)` from
    // `TransparentProxyEngineBuilder::create async runtime`.
    // `setrlimit` raises the soft limit up to the hard limit;
    // macOS's `kern.maxfilesperproc` is typically ~245760, so
    // 8192 is comfortably within range on any default-configured
    // host. Failures are best-effort: if the hard limit is also
    // capped, we just inherit it and the user sees the original
    // EMFILE.
    raise_fd_limit_best_effort(8192);

    let storage_bytes = storage_dir.to_string_lossy().into_owned().into_bytes();
    let cfg = bindings::RamaTransparentProxyInitConfig {
        storage_dir_utf8: storage_bytes.as_ptr().cast(),
        storage_dir_utf8_len: storage_bytes.len(),
        app_group_dir_utf8: ptr::null(),
        app_group_dir_utf8_len: 0,
    };
    let ok = unsafe { bindings::rama_transparent_proxy_initialize(&cfg) };
    assert!(ok, "ffi initialize should succeed");
}

#[cfg(unix)]
fn raise_fd_limit_best_effort(target_soft: u64) {
    // SAFETY: getrlimit/setrlimit have stable POSIX signatures;
    // we pass valid pointers to a `libc::rlimit` we own. Errors
    // are surfaced as a non-zero return and swallowed (best-effort).
    unsafe {
        let mut rl: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) != 0 {
            return;
        }
        let hard = rl.rlim_max;
        // Bump up to the hard limit; refuse to lower if already higher.
        let desired = target_soft.min(hard as u64) as libc::rlim_t;
        if rl.rlim_cur >= desired {
            return;
        }
        rl.rlim_cur = desired;
        let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &rl);
    }
}

#[cfg(not(unix))]
fn raise_fd_limit_best_effort(_target_soft: u64) {}

pub(crate) struct EngineHandle {
    pub(crate) raw: *mut bindings::RamaTransparentProxyEngine,
}

unsafe impl Send for EngineHandle {}
unsafe impl Sync for EngineHandle {}

impl EngineHandle {
    pub(crate) fn new_with_json(value: &serde_json::Value) -> Self {
        let json = serde_json::to_vec(value).expect("serialize engine config");
        let raw = unsafe {
            bindings::rama_transparent_proxy_engine_new_with_config(bindings::RamaBytesView {
                ptr: json.as_ptr(),
                len: json.len(),
            })
        };
        assert!(!raw.is_null(), "ffi engine allocation must succeed");

        Self { raw }
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        // The earlier no-op `drop` leaked every test's engine —
        // dial9 trace files stayed open, the engine's tokio
        // runtime threads + their per-flow file descriptors
        // stayed alive — and after ~33 tests the process ran out
        // of FDs (EMFILE), making every subsequent
        // `rama_transparent_proxy_engine_new_with_config` return
        // null with `ffi engine allocation must succeed`.
        //
        // `_stop` is the right teardown FFI (it consumes the
        // pointer, signals cooperative shutdown, and drops the
        // engine's internal tokio runtime). But `_stop` is
        // blocking and drops a tokio runtime — calling it from
        // within another tokio runtime's worker thread (where
        // tests' Arc<EngineHandle> typically gets its final
        // strong-count zero) trips tokio's "cannot drop runtime
        // in async context" guard with a non-unwinding panic
        // that aborts the test binary.
        //
        // Off-load to a dedicated OS thread and join. The join
        // blocks the calling thread (test thread, which IS in
        // tokio) but does NOT itself drop a tokio runtime in
        // tokio context — that drop now happens on the spawned
        // thread which has no tokio attribution. Brief block at
        // test teardown is acceptable; serial_test serializes
        // the suite anyway.
        let raw = std::mem::replace(&mut self.raw, std::ptr::null_mut());
        if raw.is_null() {
            return;
        }
        let raw_addr = raw as usize;
        let _ = std::thread::Builder::new()
            .name("rama-e2e-engine-stop".to_owned())
            .spawn(move || {
                let raw = raw_addr as *mut bindings::RamaTransparentProxyEngine;
                unsafe {
                    bindings::rama_transparent_proxy_engine_stop(raw, 0);
                }
            })
            .expect("spawn engine-stop thread")
            .join();
    }
}

pub(crate) fn default_engine() -> Arc<EngineHandle> {
    let (cert_pem, key_pem) = get_or_generate_mitm_ca();
    Arc::new(EngineHandle::new_with_json(&serde_json::json!({
        "html_badge_enabled": true,
        "html_badge_label": BADGE_LABEL,
        "peek_duration_s": 0.5,
        "exclude_domains": [],
        "ca_cert_pem": cert_pem,
        "ca_key_pem": key_pem,
    })))
}

pub(crate) fn load_mitm_ca_store() -> Arc<rama::tls::boring::core::x509::store::X509Store> {
    let (cert_pem, _) = get_or_generate_mitm_ca();
    let cert = X509::from_pem(cert_pem.as_bytes()).expect("parse e2e test MITM CA cert");
    let mut builder = X509StoreBuilder::new().expect("x509 store builder");
    builder.add_cert(cert).expect("add mitm ca cert");
    Arc::new(builder.build())
}
