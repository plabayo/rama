use std::convert::Infallible;

use rama::{
    Service,
    extensions::ExtensionsRef as _,
    net::{
        apple::networkextension::{TcpFlow, TransparentProxyMeta},
        proxy::{ProxyRequest, StreamForwardService},
    },
    rt::Executor,
    service::service_fn,
    tcp::client::default_tcp_connect,
    telemetry::tracing,
};

use crate::utils::resolve_target_from_extensions;

pub(super) fn new_service() -> impl Service<TcpFlow, Output = (), Error = Infallible> {
    service_fn(service)
}

/// TCP flow handler used by the transparent proxy engine.
///
/// This resolves the remote target, establishes a TCP connection, then forwards bytes between
/// the client flow and the upstream stream.
async fn service(stream: TcpFlow) -> Result<(), Infallible> {
    let meta = stream
        .extensions()
        .get::<TransparentProxyMeta>()
        .cloned()
        .unwrap_or_else(|| TransparentProxyMeta::new(rama::net::Protocol::from_static("tcp")));
    let target = resolve_target_from_extensions(stream.extensions());

    tracing::info!(
        protocol = meta.protocol().as_str(),
        remote = ?meta.remote_endpoint(),
        local = ?meta.local_endpoint(),
        "tproxy tcp start"
    );

    let Some(target_addr) = target else {
        tracing::error!("tproxy tcp missing target endpoint, closing flow");
        return Ok(());
    };

    let exec = Executor::default();

    let Ok((target, _sock_addr)) =
        default_tcp_connect(stream.extensions(), target_addr, exec).await
    else {
        tracing::error!("tproxy tcp connect failed");
        return Ok(());
    };

    let req = ProxyRequest {
        source: stream,
        target,
    };

    match StreamForwardService::new().serve(req).await {
        Ok(()) => tracing::info!("tproxy tcp forward completed"),
        Err(err) => tracing::error!(error = %err, "tproxy tcp forward error"),
    }

    Ok(())
}
