use std::{
    env,
    path::{Path, PathBuf},
    ptr,
    sync::Arc,
};

use rama::{
    net::apple::networkextension::system_keychain,
    tls::boring::core::x509::{X509, store::X509StoreBuilder},
};

use super::{bindings, types::BADGE_LABEL};

const CA_SERVICE_CERT: &str = "tls-root-selfsigned-ca-crt";
const CA_ACCOUNT: &str = "org.ramaproxy.example.tproxy";

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

/// Read the MITM CA certificate from the System Keychain.
///
/// The engine must be created first — engine creation triggers CA generation
/// and storage in the System Keychain if no CA is present yet.
pub(crate) fn load_mitm_ca_store() -> Arc<rama::tls::boring::core::x509::store::X509Store> {
    let cert_bytes = system_keychain::load_secret(CA_SERVICE_CERT, CA_ACCOUNT)
        .expect("load mitm ca cert from system keychain")
        .expect("mitm ca cert must exist in system keychain after engine creation");
    let cert = X509::from_pem(&cert_bytes).expect("parse mitm ca cert pem");
    let mut builder = X509StoreBuilder::new().expect("x509 store builder");
    builder.add_cert(cert).expect("add mitm ca cert");
    Arc::new(builder.build())
}
