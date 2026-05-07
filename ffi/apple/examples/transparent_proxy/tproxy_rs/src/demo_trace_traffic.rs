use std::{fmt, path::PathBuf, sync::Arc, time::Duration};

use moka::sync::Cache;
use rama::{
    Layer, Service,
    extensions::ExtensionsRef,
    http::{
        Request, Response,
        ws::handshake::mitm::{WebSocketRelayDirection, WebSocketRelayInput},
    },
    net::apple::networkextension::{
        process::{pid_arguments, pid_path},
        tproxy::TransparentProxyFlowMeta,
    },
    telemetry::tracing,
};

/// Per-pid cache for the path/arguments lookups done by the trace
/// layer on every request. `pid_arguments` allocates ~1 MiB per call
/// (sized to `KERN_ARGMAX`); calling it on the per-request hot path
/// dominates allocator load on a busy h2 connection. The PID space is
/// stable for the lifetime of the originating process, so a short-TTL
/// cache is sound — when a PID is reused the entry will already have
/// expired.
type PidInfo = (Option<PathBuf>, Arc<Vec<String>>);
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
        tracing::debug!(
            "demo traffic logger: relay {} WS msg: {:?}",
            match direction {
                WebSocketRelayDirection::Ingress => "[client->server]",
                WebSocketRelayDirection::Egress => "[server->client]",
            },
            input.message,
        );

        let result = self.0.serve(input).await;

        tracing::debug!(
            "demo traffic logger: relay {} WS msg: reply = {}",
            match direction {
                WebSocketRelayDirection::Ingress => "[client->server]",
                WebSocketRelayDirection::Egress => "[server->client]",
            },
            match result {
                Ok(_) => "ok",
                Err(_) => "err",
            },
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

        let (app_bundle_id, pid, process_path, process_args) = req
            .extensions()
            .get_ref::<TransparentProxyFlowMeta>()
            .map(|meta| {
                let app_bundle_id = meta.source_app_bundle_identifier.as_deref();
                let maybe_pid = meta.source_app_pid;
                let (process_path, process_args) = maybe_pid
                    .map(|pid| {
                        pid_info_cache()
                            .get_with(pid, || {
                                (
                                    lookup_process_path(pid),
                                    Arc::new(lookup_process_arguments(pid)),
                                )
                            })
                    })
                    .unwrap_or_default();
                (app_bundle_id, maybe_pid, process_path, process_args)
            })
            .unwrap_or_default();
        let process_path_display = process_path.as_ref().map(|p| p.display());

        tracing::debug!(
            app_bundle_id,
            pid,
            ?process_path_display,
            ?process_args,
            "demo traffic logger: http ingress: {method} {uri}: request",
        );

        let result = self.0.serve(req).await;

        match result.as_ref() {
            Ok(res) => tracing::debug!(
                "demo traffic logger: http egress: {method} {uri}: response status = {}",
                res.status(),
            ),
            Err(err) => {
                tracing::debug!("demo traffic logger: http egress: {method} {uri}: error: {err}")
            }
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
