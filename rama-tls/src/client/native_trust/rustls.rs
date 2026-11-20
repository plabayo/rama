use std::sync::{Arc, LazyLock};

use rama_core::{
    error::{BoxError, ErrorContext as _},
    telemetry::tracing::trace,
};
use rama_crypto::{native_certs, pki_types::CertificateDer};
use rustls::RootCertStore;

use super::StoreRoots;
use crate::client::TlsServerTrustAnchors;

static NATIVE: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
    Arc::new(builtin(
        &native_certs::shared_native_trust_anchors(),
        "native",
    ))
});
static WEBPKI: LazyLock<Arc<RootCertStore>> =
    LazyLock::new(|| Arc::new(builtin(native_certs::bundled_root_certs(), "WebPKI")));

pub(super) fn native() -> Arc<RootCertStore> {
    NATIVE.clone()
}

pub(super) fn native_ready() -> Option<Arc<RootCertStore>> {
    LazyLock::get(&NATIVE).cloned()
}

pub(super) fn webpki() -> Arc<RootCertStore> {
    WEBPKI.clone()
}

pub(super) fn webpki_ready() -> Option<Arc<RootCertStore>> {
    LazyLock::get(&WEBPKI).cloned()
}

fn builtin(anchors: &[CertificateDer<'static>], source: &'static str) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(anchors.iter().cloned());
    trace!(
        added,
        ignored, source, "initialised shared rustls root store"
    );
    roots
}

pub(super) fn derived(
    base: StoreRoots<'_>,
    additional: Option<&TlsServerTrustAnchors>,
) -> Result<Arc<RootCertStore>, BoxError> {
    let mut roots = match base {
        StoreRoots::Native => native().as_ref().clone(),
        StoreRoots::NativeCertificates(anchors) => {
            let mut roots = RootCertStore::empty();
            roots.add_parsable_certificates(anchors.iter().cloned());
            roots
        }
        StoreRoots::WebPki => webpki().as_ref().clone(),
        StoreRoots::Custom(anchors) => {
            let mut roots = RootCertStore::empty();
            add_configured_roots(&mut roots, anchors)?;
            roots
        }
    };
    if let Some(anchors) = additional {
        add_configured_roots(&mut roots, anchors)?;
    }
    Ok(Arc::new(roots))
}

fn add_configured_roots(
    roots: &mut RootCertStore,
    anchors: &TlsServerTrustAnchors,
) -> Result<(), BoxError> {
    for certificate in anchors.certificates() {
        roots
            .add(certificate.clone())
            .context("add configured server trust anchor to rustls root store")?;
    }
    Ok(())
}
