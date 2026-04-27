use std::sync::Arc;

use rama::{
    error::{BoxError, ErrorContext},
    net::apple::xpc::{XpcListener, XpcListenerConfig, XpcMessageRouter, XpcServer},
    rt::Executor,
    service::service_fn,
    telemetry::tracing,
};
use serde::{Deserialize, Serialize};

use crate::state::{LiveSettings, SharedState};

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Payload for the `updateSettings:withReply:` selector.
///
/// All fields are optional on the wire; missing values keep the current setting.
#[derive(Debug, Deserialize)]
struct UpdateSettingsRequest {
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
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn spawn_xpc_server(
    service_name: String,
    state: SharedState,
    executor: Executor,
) -> Result<(), BoxError> {
    tracing::info!(%service_name, "xpc demo server: start config+spawn");

    let config = XpcListenerConfig::new(service_name.clone());
    // .with_peer_requirement(PeerSecurityRequirement::TeamIdentity(Some(arcstr!("ADPG6C355H"))))

    let router = XpcMessageRouter::new()
        .with_typed_route::<UpdateSettingsRequest, UpdateSettingsReply, _>(
            "updateSettings:withReply:",
            service_fn({
                let state = state;
                move |req: UpdateSettingsRequest| {
                    let state = state.clone();
                    async move { Ok::<_, BoxError>(apply_settings(&state, req)) }
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

fn apply_settings(state: &SharedState, req: UpdateSettingsRequest) -> UpdateSettingsReply {
    let current = state.load_full();

    let html_badge_enabled = req.html_badge_enabled.unwrap_or(current.html_badge_enabled);

    let html_badge_label = req
        .html_badge_label
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| current.html_badge_label.clone());

    let exclude_domains = req
        .exclude_domains
        .unwrap_or_else(|| current.exclude_domains.clone());

    let new_settings = LiveSettings {
        html_badge_enabled,
        html_badge_label,
        exclude_domains,
        ca_crt_pem: current.ca_crt_pem.clone(),
        tls_mitm_relay: current.tls_mitm_relay.clone(),
    };

    tracing::debug!(
        html_badge_enabled = new_settings.html_badge_enabled,
        html_badge_label = %new_settings.html_badge_label,
        exclude_domains_count = new_settings.exclude_domains.len(),
        "xpc demo server: applying settings update"
    );

    state.store(Arc::new(new_settings));
    UpdateSettingsReply { ok: true }
}
