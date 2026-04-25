use std::{
    env,
    path::{Path, PathBuf},
    ptr,
    sync::Arc,
};

use rama::{
    net::{
        address::Domain,
        tls::server::SelfSignedData,
    },
    tls::boring::server::utils::self_signed_server_auth_gen_ca,
};
use rama::tls::boring::core::x509::{X509, store::X509StoreBuilder};

use super::{bindings, types::BADGE_LABEL};

const TEST_CA_CERT_SECRET_NAME: &str = "mitm-root-ca-cert-pem";
const TEST_CA_KEY_SECRET_NAME: &str = "mitm-root-ca-key-pem";
const TEST_CA_SECRET_ACCOUNT: &str = "rama-tproxy-ffi-e2e";

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
    test_mitm_ca();
    Arc::new(EngineHandle::new_with_json(&serde_json::json!({
        "html_badge_enabled": true,
        "html_badge_label": BADGE_LABEL,
        "peek_duration_s": 0.5,
        "exclude_domains": [],
        "ca_cert_secret_name": TEST_CA_CERT_SECRET_NAME,
        "ca_key_secret_name": TEST_CA_KEY_SECRET_NAME,
        "ca_secret_account": TEST_CA_SECRET_ACCOUNT,
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

fn test_mitm_ca() {
    let storage_dir = test_storage_dir();
    // cert_path is read by load_mitm_ca_store(); secret paths are read by the engine.
    let cert_path = storage_dir.join("mitm-root-ca-cert-pem.pem");
    let secret_dir = storage_dir.join("secrets").join(TEST_CA_SECRET_ACCOUNT);
    let cert_secret_path = secret_dir.join(format!("{TEST_CA_CERT_SECRET_NAME}.secret"));
    let key_secret_path = secret_dir.join(format!("{TEST_CA_KEY_SECRET_NAME}.secret"));

    if cert_path.exists() && cert_secret_path.exists() && key_secret_path.exists() {
        return;
    }

    let (root_cert, root_key) = self_signed_server_auth_gen_ca(&SelfSignedData {
        organisation_name: Some("Rama Transparent Proxy FFI E2E".to_owned()),
        common_name: Some(Domain::from_static("rama-tproxy-ffi-e2e.localhost")),
        ..Default::default()
    })
    .expect("generate ffi e2e mitm ca");

    let cert_pem = String::from_utf8(root_cert.to_pem().expect("encode ffi e2e mitm cert to pem"))
        .expect("ffi e2e cert pem utf8");
    let key_pem = String::from_utf8(
        root_key
            .private_key_to_pem_pkcs8()
            .expect("encode ffi e2e mitm key to pem"),
    )
    .expect("ffi e2e key pem utf8");

    std::fs::create_dir_all(&secret_dir).expect("create ffi e2e secret dir");
    std::fs::write(&cert_path, cert_pem.as_bytes()).expect("persist ffi e2e mitm cert");
    std::fs::write(&cert_secret_path, cert_pem.as_bytes()).expect("persist ffi e2e mitm cert secret");
    std::fs::write(&key_secret_path, key_pem.as_bytes()).expect("persist ffi e2e mitm key secret");
}
