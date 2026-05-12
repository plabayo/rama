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
