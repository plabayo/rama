use std::{
    env,
    path::{Path, PathBuf},
    ptr,
    sync::Arc,
};

use rama::tls::boring::core::x509::{X509, store::X509StoreBuilder};

use super::{bindings, types::BADGE_LABEL};

pub(crate) fn test_storage_dir() -> PathBuf {
    env::temp_dir().join("rama_tproxy_ffi_e2e")
}

pub(crate) fn initialize_ffi(storage_dir: &Path) {
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

        let err = unsafe { bindings::rama_transparent_proxy_engine_start(raw) };
        if !err.ptr.is_null() && err.len > 0 {
            let bytes = unsafe { std::slice::from_raw_parts(err.ptr.cast::<u8>(), err.len) };
            let message = String::from_utf8_lossy(bytes).into_owned();
            unsafe { bindings::rama_owned_bytes_free(err) };
            panic!("ffi engine start failed: {message}");
        }

        Self { raw }
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {}
}

pub(crate) fn default_engine() -> Arc<EngineHandle> {
    Arc::new(EngineHandle::new_with_json(&serde_json::json!({
        "html_badge_enabled": true,
        "html_badge_label": BADGE_LABEL,
        "peek_duration_s": 0.5,
        "exclude_domains": [],
    })))
}

pub(crate) fn load_mitm_ca_store() -> Arc<rama::tls::boring::core::x509::store::X509Store> {
    let cert_pem = std::fs::read(test_storage_dir().join("mitm-root-ca-cert-pem.pem"))
        .expect("read mitm ca pem from filesystem storage");
    let cert = X509::from_pem(&cert_pem).expect("parse mitm ca pem");
    let mut builder = X509StoreBuilder::new().expect("x509 store builder");
    builder.add_cert(cert).expect("add mitm ca cert");
    Arc::new(builder.build())
}

pub(crate) fn ffi_config_has_rules() {
    let cfg = unsafe { bindings::rama_transparent_proxy_get_config() };
    assert!(!cfg.is_null(), "ffi config pointer");
    unsafe {
        assert!(
            (*cfg).rules_len >= 1,
            "config should contain at least one rule"
        );
        bindings::rama_transparent_proxy_config_free(cfg);
    }
}
