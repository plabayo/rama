use std::sync::{Arc, LazyLock};

use ahash::{HashSet, HashSetExt as _};
use rama_boring::{
    sha::sha256,
    x509::{
        X509,
        store::{X509Store, X509StoreBuilder},
        verify::X509VerifyFlags,
    },
};
use rama_core::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    telemetry::tracing::{debug, trace},
};
use rama_crypto::pki_types::CertificateDer;

use super::StoreRoots;
use crate::client::TlsServerTrustAnchors;

static NATIVE: LazyLock<Result<Arc<X509Store>, BoxError>> =
    LazyLock::new(build_os_default_verify_store);
static WEBPKI: LazyLock<Result<Arc<X509Store>, BoxError>> =
    LazyLock::new(build_webpki_verify_store);

const NATIVE_CONTEXT: &str = "shared default verify store";
const WEBPKI_CONTEXT: &str = "shared WebPKI verify store";

pub(super) fn native() -> Result<Arc<X509Store>, BoxError> {
    shared_store(&NATIVE, NATIVE_CONTEXT)
}

pub(super) fn native_ready() -> Option<Result<Arc<X509Store>, BoxError>> {
    LazyLock::get(&NATIVE).map(|store| shared_store(store, NATIVE_CONTEXT))
}

pub(super) fn webpki() -> Result<Arc<X509Store>, BoxError> {
    shared_store(&WEBPKI, WEBPKI_CONTEXT)
}

pub(super) fn webpki_ready() -> Option<Result<Arc<X509Store>, BoxError>> {
    LazyLock::get(&WEBPKI).map(|store| shared_store(store, WEBPKI_CONTEXT))
}

fn shared_store(
    store: &Result<Arc<X509Store>, BoxError>,
    context: &'static str,
) -> Result<Arc<X509Store>, BoxError> {
    store
        .as_ref()
        .cloned()
        .map_err(|error| error.to_string().context(context).into_box_error())
}

pub(super) fn derived(
    base: StoreRoots<'_>,
    additional: Option<&TlsServerTrustAnchors>,
) -> Result<Arc<X509Store>, BoxError> {
    let mut builder = X509StoreBuilder::new().context("create server trust store")?;
    // Custom roots intentionally include intermediate or end-entity trust
    // anchors, which require partial-chain verification in BoringSSL.
    builder.set_flags(X509VerifyFlags::PARTIAL_CHAIN);
    let mut added = HashSet::new();

    match base {
        StoreRoots::Native => add_builtin_trust_anchors(
            &mut builder,
            &mut added,
            &rama_crypto::native_certs::shared_native_trust_anchors(),
            "native",
        ),
        StoreRoots::NativeCertificates(anchors) => {
            add_builtin_trust_anchors(&mut builder, &mut added, anchors, "native");
        }
        StoreRoots::WebPki => add_builtin_trust_anchors(
            &mut builder,
            &mut added,
            rama_crypto::native_certs::bundled_root_certs(),
            "WebPKI",
        ),
        StoreRoots::Custom(anchors) => {
            add_configured_trust_anchors(&mut builder, &mut added, anchors)?;
        }
    }
    if let Some(anchors) = additional {
        add_configured_trust_anchors(&mut builder, &mut added, anchors)?;
    }

    if added.is_empty() && !matches!(base, StoreRoots::NativeCertificates(_)) {
        return Err(BoxError::from_static_str(
            "no server trust anchors could be added to the boring x509 verify store",
        ));
    }
    Ok(Arc::new(builder.build()))
}

fn add_configured_trust_anchors(
    builder: &mut X509StoreBuilder,
    added: &mut HashSet<[u8; 32]>,
    anchors: &TlsServerTrustAnchors,
) -> Result<(), BoxError> {
    for der in anchors.certificates() {
        let digest = sha256(der.as_ref());
        if added.contains(&digest) {
            continue;
        }
        let certificate =
            X509::from_der(der.as_ref()).context("parse configured server trust anchor")?;
        builder
            .add_cert(&certificate)
            .context("add configured server trust anchor to boring x509 store")?;
        added.insert(digest);
    }
    Ok(())
}

fn add_builtin_trust_anchors(
    builder: &mut X509StoreBuilder,
    added: &mut HashSet<[u8; 32]>,
    anchors: &[CertificateDer<'static>],
    kind: &'static str,
) {
    for der in anchors {
        let digest = sha256(der.as_ref());
        if added.contains(&digest) {
            continue;
        }
        match X509::from_der(der.as_ref()) {
            Ok(cert) => match builder.add_cert(&cert) {
                Ok(()) => {
                    added.insert(digest);
                }
                Err(err) => {
                    debug!(%err, trust_anchor_kind = kind, "boring connector: failed to add built-in trust anchor");
                }
            },
            Err(err) => {
                debug!(%err, trust_anchor_kind = kind, "boring connector: failed to parse built-in trust anchor");
            }
        }
    }
}

fn build_os_default_verify_store() -> Result<Arc<X509Store>, BoxError> {
    let anchors = rama_crypto::native_certs::shared_native_trust_anchors();
    trace!(
        anchor_count = anchors.len(),
        "boring connector: building shared verify store from native trust anchors"
    );
    build_builtin_verify_store(&anchors, "native")
}

fn build_webpki_verify_store() -> Result<Arc<X509Store>, BoxError> {
    let anchors = rama_crypto::native_certs::bundled_root_certs();
    trace!(
        anchor_count = anchors.len(),
        "boring connector: building shared verify store from bundled WebPKI roots"
    );
    build_builtin_verify_store(anchors, "WebPKI")
}

fn build_builtin_verify_store(
    anchors: &[CertificateDer<'static>],
    kind: &'static str,
) -> Result<Arc<X509Store>, BoxError> {
    let mut builder =
        X509StoreBuilder::new().context("create x509 store builder for built-in trust anchors")?;
    // Native trust stores can deliberately contain non-self-signed trust
    // anchors. WebPKI roots are self-signed, so the flag is inert there.
    builder.set_flags(X509VerifyFlags::PARTIAL_CHAIN);
    let mut added = HashSet::new();
    add_builtin_trust_anchors(&mut builder, &mut added, anchors, kind);

    trace!(
        added = added.len(),
        trust_anchor_kind = kind,
        "boring connector: shared verify store built"
    );

    if added.is_empty() {
        return Err(BoxError::from_static_str(
            "no built-in trust anchors could be added to the boring x509 verify store",
        ));
    }

    Ok(Arc::new(builder.build()))
}
