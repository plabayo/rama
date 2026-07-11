use std::{fmt, path::PathBuf, sync::Arc, time::Duration};

use moka::sync::Cache;
use rama::{
    Layer, Service,
    extensions::ExtensionsRef,
    http::{
        Request, Response,
        ws::handshake::mitm::{
            WebSocketRelayDirection, WebSocketRelayInput, WebSocketRelayMessage,
        },
    },
    net::apple::networkextension::{
        process::{pid_arguments, pid_path},
        tproxy::TransparentProxyFlowMeta,
    },
    telemetry::tracing,
};

/// Per-pid cache for the process-path lookup done by the trace layer.
#[derive(Debug, Clone, Default)]
struct PidInfo {
    path: Option<Arc<PathBuf>>,
    args: Arc<Vec<String>>,
}

fn pid_info_cache() -> &'static Cache<i32, PidInfo> {
    static CACHE: std::sync::OnceLock<Cache<i32, PidInfo>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| {
        Cache::builder()
            .max_capacity(1024)
            .time_to_live(Duration::from_secs(30))
            .build()
    })
}

#[derive(Debug, Clone, Default)]
pub struct DemoTraceTrafficLayer;

impl<S> Layer<S> for DemoTraceTrafficLayer {
    type Service = DemoTraceTrafficService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DemoTraceTrafficService(inner)
    }
}

#[derive(Debug, Clone)]
pub struct DemoTraceTrafficService<S>(S);

impl<S> Service<WebSocketRelayInput> for DemoTraceTrafficService<S>
where
    S: Service<WebSocketRelayInput>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: WebSocketRelayInput) -> Result<Self::Output, Self::Error> {
        let direction = input.direction;
        let (message_kind, message_bytes) = match &input.message {
            WebSocketRelayMessage::Text(message) => ("text", message.len()),
            WebSocketRelayMessage::Binary(message) => ("binary", message.len()),
        };
        tracing::trace!(
            direction = match direction {
                WebSocketRelayDirection::Ingress => "[client->server]",
                WebSocketRelayDirection::Egress => "[server->client]",
            },
            message_kind,
            message_bytes,
            "demo traffic logger: websocket message",
        );

        let result = self.0.serve(input).await;

        tracing::trace!(
            direction = match direction {
                WebSocketRelayDirection::Ingress => "[client->server]",
                WebSocketRelayDirection::Egress => "[server->client]",
            },
            outcome = if result.is_ok() { "ok" } else { "err" },
            "demo traffic logger: websocket relay finished",
        );

        result
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for DemoTraceTrafficService<S>
where
    S: Service<Request<ReqBody>, Error: fmt::Display, Output = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let method = req.method().clone();
        let uri = req.uri().clone();

        let (app_bundle_id, pid, info, egress_interface, remote_hostname) = req
            .extensions()
            .get_ref::<TransparentProxyFlowMeta>()
            .map(|meta| {
                let app_bundle_id = meta.source_app_bundle_identifier.as_deref();
                let maybe_pid = meta.source_app_pid;
                let info = maybe_pid
                    .map(|pid| {
                        pid_info_cache().get_with(pid, || PidInfo {
                            path: lookup_process_path(pid).map(Arc::new),
                            args: Arc::new(lookup_process_arguments(pid)),
                        })
                    })
                    .unwrap_or_default();
                (
                    app_bundle_id,
                    maybe_pid,
                    info,
                    meta.local_interface_name.as_deref(),
                    meta.remote_hostname.as_deref(),
                )
            })
            .unwrap_or_default();
        let process_path_display = info.path.as_deref().map(|p| p.display());
        let process_args = &*info.args;

        // Demo-only: process arguments may contain secrets in real applications.
        tracing::debug!(
            app_bundle_id,
            pid,
            ?process_path_display,
            ?process_args,
            egress_interface,
            remote_hostname,
            %method,
            request_path = ?uri.path(),
            "demo traffic logger: http ingress request",
        );

        let result = self.0.serve(req).await;

        match result.as_ref() {
            Ok(res) => tracing::debug!(
                %method,
                request_path = ?uri.path(),
                status = %res.status(),
                "demo traffic logger: http egress response",
            ),
            Err(err) => tracing::debug!(
                %method,
                request_path = ?uri.path(),
                error = %err,
                "demo traffic logger: http egress error",
            ),
        }

        result
    }
}

fn lookup_process_path(pid: i32) -> Option<std::path::PathBuf> {
    match unsafe { pid_path(pid) } {
        Ok(path) => path,
        Err(err) => {
            tracing::warn!(pid, error = %err, "demo traffic logger: failed to resolve pid path");
            None
        }
    }
}

fn lookup_process_arguments(pid: i32) -> Vec<String> {
    match unsafe { pid_arguments(pid) } {
        Ok(args) => args,
        Err(err) => {
            tracing::warn!(pid, error = %err, "demo traffic logger: failed to resolve pid arguments");
            Vec::new()
        }
    }
}
