use std::sync::Arc;

use base64::Engine as _;
use rama::{
    bytes::Bytes,
    error::{BoxError, BoxErrorExt, ErrorContext},
    net::apple::xpc::{
        PeerSecurityRequirement, XpcListener, XpcListenerConfig, XpcMessageRouter, XpcServer,
    },
    rt::Executor,
    service::service_fn,
    telemetry::tracing,
    tls::boring::proxy::TlsMitmRelay,
    utils::str::arcstr::ArcStr,
};
use serde::{Deserialize, Serialize};

use crate::state::SharedState;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Payload for the `updateSettings:withReply:` selector.
///
/// All fields are optional on the wire; missing values keep the current setting.
#[derive(Debug, Deserialize)]
struct UpdateSettingsRequest {
    #[serde(default)]
    verify_upstream_certificates: Option<bool>,
    #[serde(default)]
    html_badge_enabled: Option<bool>,
    #[serde(default)]
    html_badge_label: Option<String>,
    #[serde(default)]
    exclude_domains: Option<Vec<String>>,
}

/// Reply for `updateSettings:withReply:`.
#[derive(Debug, Serialize)]
struct UpdateSettingsReply {
    ok: bool,
    verify_upstream_certificates: bool,
}

/// Empty payload for the CA-related XPC routes.
#[derive(Debug, Default, Deserialize)]
struct EmptyRequest {}

/// Payload for the `setTlsKeylog:withReply:` selector.
#[derive(Debug, Deserialize)]
struct SetTlsKeylogRequest {
    enabled: bool,
}

/// Reply shape for both `setTlsKeylog:withReply:` and
/// `getTlsKeylog:withReply:` — `enabled` is the state observed
/// *after* the call.
#[derive(Debug, Serialize)]
struct TlsKeylogReply {
    enabled: bool,
}

/// Shared reply shape for `installRootCA:withReply:` and
/// `uninstallRootCA:withReply:`.
///
/// `cert_der_b64` carries the DER-encoded MITM CA certificate (base64) so
/// the container app can set / remove the **admin** trust setting locally —
/// trust changes go through Authorization Services and need an interactive
/// admin auth dialog that the sysext daemon cannot present.
#[derive(Debug, Serialize)]
struct RootCaCommandReply {
    ok: bool,
    error: Option<String>,
    cert_der_b64: Option<String>,
}

impl RootCaCommandReply {
    fn ok_with_cert(cert_der: &[u8]) -> Self {
        Self {
            ok: true,
            error: None,
            cert_der_b64: Some(base64::engine::general_purpose::STANDARD.encode(cert_der)),
        }
    }

    fn ok_without_cert() -> Self {
        Self {
            ok: true,
            error: None,
            cert_der_b64: None,
        }
    }

    fn err(err: &BoxError) -> Self {
        Self {
            ok: false,
            error: Some(format!("{err:#}")),
            cert_der_b64: None,
        }
    }
}

/// Reply for `rotateRootCA:withReply:`. Carries both the previous DER
/// (so the container can drop its admin trust setting) and the new
/// DER (to set fresh admin trust on).
#[derive(Debug, Serialize)]
struct RotateRootCaReply {
    ok: bool,
    error: Option<String>,
    previous_cert_der_b64: Option<String>,
    new_cert_der_b64: Option<String>,
}

impl RotateRootCaReply {
    fn ok(previous: Option<&[u8]>, new: &[u8]) -> Self {
        Self {
            ok: true,
            error: None,
            previous_cert_der_b64: previous
                .map(|d| base64::engine::general_purpose::STANDARD.encode(d)),
            new_cert_der_b64: Some(base64::engine::general_purpose::STANDARD.encode(new)),
        }
    }

    fn err(err: &BoxError) -> Self {
        Self {
            ok: false,
            error: Some(format!("{err:#}")),
            previous_cert_der_b64: None,
            new_cert_der_b64: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn spawn_xpc_server(
    service_name: String,
    container_signing_identifier: Option<String>,
    state: SharedState,
    executor: Executor,
) -> Result<(), BoxError> {
    // SECURITY: pin the listener to the container app's signing identifier so that
    // only a binary signed by the **same Apple Developer team** *and* carrying that
    // exact bundle ID is allowed to talk to the install/uninstall/settings routes.
    // Equivalent to the new (macOS 26+) `XPCPeerRequirement.isFromSameTeam(
    // andMatchesSigningIdentifier:)` Swift API but works on macOS 11+ via the
    // underlying `xpc_connection_set_peer_team_identity_requirement` C primitive.
    //
    // Fail-closed: if the container did not provide its bundle ID through the
    // engine config, we refuse to bind. This avoids accidentally exposing the
    // routes to any local process when the wiring is broken.
    let signing_identifier = container_signing_identifier
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ArcStr::from)
        .ok_or_else(|| -> BoxError {
            tracing::error!(
                "xpc demo server: container_signing_identifier is missing or empty in engine \
                 config; refusing to bind XPC listener (fail-closed). Set it from the container \
                 app's `Bundle.main.bundleIdentifier`.",
            );
            BoxError::from_static_str(
                "xpc demo server: missing container_signing_identifier (fail-closed)",
            )
        })?;

    tracing::info!(
        %service_name,
        %signing_identifier,
        "xpc demo server: start config+spawn (peer pinned to same-team + signing identifier)",
    );

    let config = XpcListenerConfig::new(service_name.clone()).with_peer_requirement(
        PeerSecurityRequirement::TeamIdentity(Some(signing_identifier)),
    );

    let router = XpcMessageRouter::new()
        .with_typed_route::<EmptyRequest, crate::allocator::AllocatorStatsReply, _>(
            "getAllocatorStats:withReply:",
            service_fn(|_req: EmptyRequest| async move {
                Ok::<_, BoxError>(crate::allocator::snapshot())
            }),
        )
        .with_typed_route::<UpdateSettingsRequest, UpdateSettingsReply, _>(
            "updateSettings:withReply:",
            service_fn({
                let state = state.clone();
                move |req: UpdateSettingsRequest| {
                    let state = state.clone();
                    async move { apply_settings(&state, &req) }
                }
            }),
        )
        .with_typed_route::<EmptyRequest, RootCaCommandReply, _>(
            "installRootCA:withReply:",
            service_fn(|_req: EmptyRequest| async move {
                tracing::info!("xpc demo server: installRootCA:withReply: invoked");
                let reply = match crate::tls::install_root_ca() {
                    Ok(der) => {
                        tracing::info!(
                            der_len = der.len(),
                            "xpc demo server: installRootCA succeeded"
                        );
                        RootCaCommandReply::ok_with_cert(&der)
                    }
                    Err(err) => {
                        tracing::error!(error = %err, "xpc demo server: installRootCA failed");
                        RootCaCommandReply::err(&err)
                    }
                };
                Ok::<_, BoxError>(reply)
            }),
        )
        .with_typed_route::<EmptyRequest, RootCaCommandReply, _>(
            "uninstallRootCA:withReply:",
            service_fn(|_req: EmptyRequest| async move {
                tracing::info!("xpc demo server: uninstallRootCA:withReply: invoked");
                let reply = match crate::tls::uninstall_root_ca() {
                    Ok(Some(der)) => {
                        tracing::info!(
                            der_len = der.len(),
                            "xpc demo server: uninstallRootCA removed cert"
                        );
                        RootCaCommandReply::ok_with_cert(&der)
                    }
                    Ok(None) => {
                        tracing::info!(
                            "xpc demo server: uninstallRootCA found no stored CA (no-op)"
                        );
                        RootCaCommandReply::ok_without_cert()
                    }
                    Err(err) => {
                        tracing::error!(error = %err, "xpc demo server: uninstallRootCA failed");
                        RootCaCommandReply::err(&err)
                    }
                };
                Ok::<_, BoxError>(reply)
            }),
        )
        .with_typed_route::<EmptyRequest, RotateRootCaReply, _>(
            "rotateRootCA:withReply:",
            service_fn({
                let state = state.clone();
                move |_req: EmptyRequest| {
                    let state = state.clone();
                    async move {
                        tracing::info!("xpc demo server: rotateRootCA:withReply: invoked");
                        let reply = match rotate_and_swap(&state) {
                            Ok((previous, new)) => {
                                tracing::info!(
                                    new_der_len = new.len(),
                                    previous_present = previous.is_some(),
                                    "xpc demo server: rotateRootCA succeeded"
                                );
                                RotateRootCaReply::ok(previous.as_deref(), &new)
                            }
                            Err(err) => {
                                tracing::error!(error = %err, "xpc demo server: rotateRootCA failed");
                                RotateRootCaReply::err(&err)
                            }
                        };
                        Ok::<_, BoxError>(reply)
                    }
                }
            }),
        )
        .with_typed_route::<SetTlsKeylogRequest, TlsKeylogReply, _>(
            "setTlsKeylog:withReply:",
            service_fn({
                let state = state.clone();
                move |req: SetTlsKeylogRequest| {
                    let state = state.clone();
                    async move {
                        let toggle = state.load().tls_keylog_toggle.clone();
                        toggle.set(req.enabled);
                        let now = toggle.is_enabled();
                        tracing::info!(
                            requested = req.enabled,
                            now,
                            "xpc demo server: setTlsKeylog applied",
                        );
                        Ok::<_, BoxError>(TlsKeylogReply { enabled: now })
                    }
                }
            }),
        )
        .with_typed_route::<EmptyRequest, TlsKeylogReply, _>(
            "getTlsKeylog:withReply:",
            service_fn({
                let state = state;
                move |_req: EmptyRequest| {
                    let state = state.clone();
                    async move {
                        let enabled = state.load().tls_keylog_toggle.is_enabled();
                        Ok::<_, BoxError>(TlsKeylogReply { enabled })
                    }
                }
            }),
        );

    // XpcMessageRouter implements Service<XpcMessage, Output = Option<XpcMessage>, Error = BoxError>
    // so it can be passed directly to XpcServer.
    let server = XpcServer::new(router);

    let listener = XpcListener::bind(config)
        .context("bind xpc demo listener")
        .with_context_debug_field("serviceName", || service_name.clone())?;

    let exec2 = executor.clone();
    executor.spawn_cancellable_task(async move {
        tracing::info!(%service_name, "xpc demo server listener active");
        if let Err(err) = server.serve_listener(listener, exec2).await {
            tracing::error!(%service_name, %err, "xpc demo server error");
        }
    });

    Ok(())
}

// ---------------------------------------------------------------------------
// Handler logic
// ---------------------------------------------------------------------------

fn apply_settings(
    state: &SharedState,
    req: &UpdateSettingsRequest,
) -> Result<UpdateSettingsReply, BoxError> {
    let policy = if let Some(verify) = req.verify_upstream_certificates {
        let mut auth = state.load().server_auth.clone();
        auth.verify = verify;
        Some((auth.tcp()?, auth))
    } else {
        None
    };
    state.rcu(|current| {
        let mut next = (**current).clone();
        if let Some(enabled) = req.html_badge_enabled {
            next.html_badge_enabled = enabled;
        }
        if let Some(label) = req.html_badge_label.as_ref().filter(|s| !s.is_empty()) {
            next.html_badge_label = label.clone();
        }
        if let Some(domains) = &req.exclude_domains {
            next.exclude_domains = domains.clone();
        }
        if let Some((policy, auth)) = &policy {
            next.server_auth = auth.clone();
            next.tls_mitm_relay.set_egress_server_auth(policy.clone());
        }
        Arc::new(next)
    });
    Ok(UpdateSettingsReply {
        ok: true,
        verify_upstream_certificates: state.load().server_auth.verify,
    })
}

/// Mint a fresh CA, persist it, swap it into the live `LiveSettings` so
/// new flows pick it up without restart, and return `(previous_der, new_der)`.
fn rotate_and_swap(state: &SharedState) -> Result<(Option<Vec<u8>>, Vec<u8>), BoxError> {
    let rotated = crate::tls::rotate_root_ca()?;

    let cert_pem = rotated
        .cert
        .to_pem()
        .context("encode rotated MITM CA cert to PEM")?;

    let relay = TlsMitmRelay::new_cached_in_memory(rotated.cert, rotated.key);
    swap_issuer(state, &relay, &cert_pem);
    Ok((rotated.previous_der, rotated.der))
}

fn swap_issuer(state: &SharedState, relay: &crate::tls::DemoTlsMitmRelay, cert_pem: &[u8]) {
    state.rcu(|current| {
        let mut next = (**current).clone();
        let mut relay = relay.clone();
        relay.set_keylog_intent(current.tls_mitm_relay.keylog_intent_ref().clone());
        relay.set_egress_server_auth(
            current
                .tls_mitm_relay
                .egress_server_auth_ref()
                .cloned()
                .expect("demo always configures upstream policy"),
        );
        next.tls_mitm_relay = relay;
        next.ca_crt_pem = Bytes::copy_from_slice(cert_pem);
        Arc::new(next)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{state::LiveSettings, tls::server_auth::DemoServerAuth};
    use rama::{
        crypto::cert::boring::generate_certificate_authority_x509,
        tls::keylog::{NoopKeyLogSink, ToggleableKeyLogSink},
    };

    fn issuer() -> (crate::tls::DemoTlsMitmRelay, Vec<u8>) {
        let (cert, key) = generate_certificate_authority_x509(&Default::default()).unwrap();
        let pem = cert.to_pem().unwrap();
        (TlsMitmRelay::new_cached_in_memory(cert, key), pem)
    }

    #[test]
    fn live_updates_and_ca_rotation_keep_upstream_policy_and_other_settings() {
        let (mut relay, pem) = issuer();
        let auth = DemoServerAuth::new(&Default::default()).unwrap();
        relay.set_egress_server_auth(auth.tcp().unwrap());
        let state = Arc::new(arc_swap::ArcSwap::from_pointee(LiveSettings {
            server_auth: auth,
            html_badge_enabled: true,
            html_badge_label: "before".into(),
            exclude_domains: vec!["excluded.example".into()],
            ca_crt_pem: pem.into(),
            tls_mitm_relay: relay,
            tls_keylog_toggle: ToggleableKeyLogSink::new(NoopKeyLogSink).toggle(),
        }));
        let original = state.load_full();
        for verify in [true, false, true] {
            let request =
                serde_json::from_value(serde_json::json!({"verify_upstream_certificates": verify}))
                    .unwrap();
            assert_eq!(
                apply_settings(&state, &request)
                    .unwrap()
                    .verify_upstream_certificates,
                verify
            );
            let before = state.load_full();
            let (relay, pem) = issuer();
            swap_issuer(&state, &relay, &pem);
            let after = state.load_full();
            assert_eq!(after.server_auth.verify, verify);
            assert_eq!(
                format!("{:?}", before.tls_mitm_relay.egress_server_auth_ref()),
                format!("{:?}", after.tls_mitm_relay.egress_server_auth_ref())
            );
            assert_ne!(before.ca_crt_pem, after.ca_crt_pem);
            assert_eq!(after.exclude_domains, original.exclude_domains);
            assert_eq!(after.html_badge_label, "before");
            let request =
                serde_json::from_value(serde_json::json!({"html_badge_enabled": false})).unwrap();
            assert_eq!(
                apply_settings(&state, &request)
                    .unwrap()
                    .verify_upstream_certificates,
                verify
            );
        }
        assert!(
            !original.server_auth.verify,
            "an existing flow retains its snapshot"
        );
        let request = serde_json::from_str("{}").unwrap();
        assert!(
            apply_settings(&state, &request)
                .unwrap()
                .verify_upstream_certificates
        );
        assert!(!state.load().html_badge_enabled);
    }
}
