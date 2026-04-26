use std::sync::Arc;

use rama::{
    error::{BoxError, ErrorContext},
    net::apple::xpc::{XpcListener, XpcListenerConfig, XpcMessage, XpcServer},
    rt::Executor,
    service::service_fn,
    telemetry::tracing,
};

use crate::state::{LiveSettings, SharedState};

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn spawn_xpc_server(
    service_name: String,
    state: SharedState,
    executor: Executor,
) -> Result<(), BoxError> {
    tracing::info!(%service_name, "xpc demo server: start config+spawn");

    let config = XpcListenerConfig::new(service_name.clone());
    // .with_peer_requirement(PeerSecurityRequirement::TeamIdentity(Some(arcstr!("ADPG6C355H"))))

    let server = XpcServer::new(service_fn({
        let state = state;
        move |msg: XpcMessage| {
            let state = state.clone();
            async move { Ok::<_, BoxError>(handle_xpc_message(&state, msg)) }
        }
    }));

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

fn handle_xpc_message(state: &SharedState, msg: XpcMessage) -> Option<XpcMessage> {
    let XpcMessage::Dictionary(dict) = msg else {
        tracing::debug!("xpc demo server: ignoring non-dictionary message");
        return None;
    };

    let op = if let Some(XpcMessage::String(s)) = dict.get("op") {
        s.as_str()
    } else {
        tracing::debug!("xpc demo server: missing or non-string 'op' field");
        return None;
    };

    if op == "update_settings" {
        let current = state.load_full();

        let html_badge_enabled = match dict.get("html_badge_enabled") {
            Some(XpcMessage::Bool(v)) => *v,
            _ => current.html_badge_enabled,
        };

        let html_badge_label = match dict.get("html_badge_label") {
            Some(XpcMessage::String(s)) if !s.is_empty() => s.clone(),
            _ => current.html_badge_label.clone(),
        };

        let exclude_domains = match dict.get("exclude_domains") {
            Some(XpcMessage::Array(arr)) => arr
                .iter()
                .filter_map(|v| {
                    if let XpcMessage::String(s) = v {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>(),
            _ => current.exclude_domains.clone(),
        };

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
        None
    } else {
        tracing::debug!(op, "xpc demo server: unknown op");
        None
    }
}
