use std::{convert::Infallible, sync::Arc};

use rama::{
    Service,
    bytes::Bytes,
    net::{
        address::ip::{IpScopes, private::is_private_ip},
        apple::networkextension::{
            self as apple_ne,
            tproxy::{
                FlowAction, TransparentProxyConfig, TransparentProxyEngineBuilder,
                TransparentProxyFlowAction, TransparentProxyFlowMeta, TransparentProxyHandler,
                TransparentProxyHandlerFactory, TransparentProxyNetworkRule,
                TransparentProxyRuleProtocol, TransparentProxyServiceContext,
            },
        },
    },
    rt::Executor,
    telemetry::tracing,
};
use serde::{Deserialize, Serialize};

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod concurrency;
mod config;
mod demo_trace_traffic;
mod demo_xpc_server;
mod dial9;
mod http;
mod policy;
mod state;
mod tcp;
mod tls;
mod udp;
mod utils;

fn init(config: Option<&apple_ne::ffi::tproxy::TransparentProxyInitConfig>) -> bool {
    let mut log_subsystem = None;
    if let Some(config) = config {
        // SAFETY: pointer + length validity is guaranteed by FFI contract.
        if let Some(path) = unsafe { config.storage_dir() } {
            tracing::debug!(path = %path.display(), "received storage directory: pass to set_storage_dir");
            self::utils::set_storage_dir(Some(path));
        }
        // SAFETY: pointer + length validity is guaranteed by FFI contract.
        log_subsystem = unsafe { config.bundle_identifier() };
    }

    let init_status = self::utils::init_tracing(log_subsystem);
    tracing::info!(init_status, "rama proxy initialized");
    init_status
}

/// Domains passed through *up-front* (declined in `handleNewFlow` — the
/// documented transparent-provider hand-off to the direct route), keyed on the
/// OS-provided destination hostname (`remote_hostname`, available before any
/// TLS peek). Distinct from `exclude_domains`, which promote *after* the peek.
/// A few common, easy-to-drive names here let a soak run exercise the up-front
/// decline path on demand — just `curl https://example.com/` in a loop.
const UPFRONT_PASSTHROUGH_DOMAINS: &[&str] =
    &["example.com", "example.org", "example.net", "neverssl.com"];

/// `true` if `host` equals or is a subdomain of any suffix in `suffixes`.
fn host_matches_suffix(host: &str, suffixes: &[&str]) -> bool {
    suffixes
        .iter()
        .any(|s| host == *s || host.strip_suffix(s).is_some_and(|p| p.ends_with('.')))
}

#[inline(always)]
fn flow_action_for_flow(meta: &TransparentProxyFlowMeta) -> TransparentProxyFlowAction {
    // Up-front passthrough by destination hostname (OS-provided, no TLS peek).
    // `Passthrough` declines the flow (`handleNewFlow` returns false), which
    // for `NETransparentProxyProvider` hands it to the direct route — same
    // contract for TCP and UDP.
    if let Some(host) = meta.remote_hostname.as_deref()
        && host_matches_suffix(host, UPFRONT_PASSTHROUGH_DOMAINS)
    {
        return TransparentProxyFlowAction::Passthrough;
    }

    let Some(target) = meta.remote_endpoint.as_ref() else {
        return TransparentProxyFlowAction::Passthrough;
    };

    // IP-first: intercept domain/uninterpreted hosts; for IPs, passthrough
    // non-loopback private addresses (keeps e2e tests local).
    match target.host.try_as_ip() {
        Ok(addr) if is_private_ip(addr) && !addr.is_loopback() => {
            TransparentProxyFlowAction::Passthrough
        }
        _ => TransparentProxyFlowAction::Intercept,
    }
}

/// One line per new flow surfacing the Apple NE interface metadata: egress
/// interface (name/type/index/bound) and remote hostname, when the OS exposes them.
fn log_new_flow(protocol: &str, meta: &TransparentProxyFlowMeta) {
    tracing::info!(
        protocol,
        remote = ?meta.remote_endpoint,
        remote_hostname = meta.remote_hostname.as_deref(),
        egress_interface = meta.local_interface_name.as_deref(),
        egress_interface_type = ?meta.local_interface_type,
        egress_interface_index = ?meta.local_interface_index,
        is_bound = ?meta.is_bound,
        bundle_identifier = meta.source_app_bundle_identifier.as_deref(),
        "transparent proxy: new flow",
    );
}

#[derive(Clone, Copy, Default)]
struct DemoEngineFactory;

impl TransparentProxyHandlerFactory for DemoEngineFactory {
    type Handler = DemoTransparentProxyHandler;
    type Error = rama::error::BoxError;

    fn create_transparent_proxy_handler(
        &self,
        ctx: TransparentProxyServiceContext,
    ) -> impl Future<Output = Result<Self::Handler, Self::Error>> + Send {
        DemoTransparentProxyHandler::try_new(ctx)
    }
}

#[derive(Clone)]
struct DemoTransparentProxyHandler {
    config: TransparentProxyConfig,
    concurrency_limiter: Arc<concurrency::ConcurrencyLimiter>,
    tcp_mitm_service: tcp::DemoTcpMitmService,
    udp_service: rama::service::BoxService<apple_ne::UdpFlow, (), Infallible>,
    egress_connect_timeout: Option<std::time::Duration>,
    egress_tcp_no_delay: bool,
}

#[derive(Debug, Deserialize)]
struct AppMessageRequest {
    op: Option<String>,
    sent_at: Option<String>,
    source: Option<String>,
}

#[derive(Debug, Serialize)]
struct AppMessageReply {
    op: &'static str,
    source: &'static str,
    received_bytes: usize,
    acknowledged_source: Option<String>,
    acknowledged_sent_at: Option<String>,
}

impl DemoTransparentProxyHandler {
    async fn try_new(ctx: TransparentProxyServiceContext) -> Result<Self, rama::error::BoxError> {
        let (tcp_mitm_service, shared_state) =
            self::tcp::DemoTcpMitmService::try_new(ctx.clone()).await?;
        let udp_service = self::udp::try_new_service(ctx.clone()).await?.boxed();

        let demo_config = self::config::DemoProxyConfig::from_opaque_config(ctx.opaque_config())?;
        // Treat 0 / absent as "platform default".
        let egress_connect_timeout = demo_config
            .tcp_connect_timeout_ms
            .filter(|&ms| ms > 0)
            .map(std::time::Duration::from_millis);
        let egress_tcp_no_delay = demo_config.tcp_no_delay;
        if let Some(xpc_service_name) = demo_config.xpc_service_name {
            self::demo_xpc_server::spawn_xpc_server(
                xpc_service_name,
                demo_config.container_signing_identifier,
                shared_state,
                ctx.executor.clone(),
            )
            .unwrap_or_else(|err| {
                tracing::error!(%err, "failed to spawn xpc server");
            });
        }

        let proxy_config = TransparentProxyConfig::new()
            .with_rules(vec![
                TransparentProxyNetworkRule::any().with_protocol(TransparentProxyRuleProtocol::Tcp),
                TransparentProxyNetworkRule::any().with_protocol(TransparentProxyRuleProtocol::Udp),
            ])
            // Exclude non-loopback private/local ranges (RFC1918, link-local,
            // CGNAT) at the kernel level: they take the default route untouched
            // and are never diverted to the provider. Prefer this zero-cost
            // tier for whole destination ranges; per-flow decisions decline in
            // the handler and use the transparent-provider passthrough contract.
            // Loopback is intentionally left handled.
            .with_exclude_ip_scopes(IpScopes::LOCAL.difference(IpScopes::LOOPBACK));

        let concurrency_limiter =
            Arc::new(concurrency::ConcurrencyLimiter::new(Default::default()));

        Ok(Self {
            config: proxy_config,
            concurrency_limiter,
            tcp_mitm_service,
            udp_service,
            egress_connect_timeout,
            egress_tcp_no_delay,
        })
    }
}

impl TransparentProxyHandler for DemoTransparentProxyHandler {
    fn transparent_proxy_config(&self) -> TransparentProxyConfig {
        self.config.clone()
    }

    fn egress_tcp_connect_options(
        &self,
        _meta: &TransparentProxyFlowMeta,
    ) -> Option<apple_ne::tproxy::NwTcpConnectOptions> {
        Some(apple_ne::tproxy::NwTcpConnectOptions {
            // Unset ⇒ keep the engine/Swift default.
            connect_timeout: self.egress_connect_timeout,
            // Engine default is already no-delay ON; the config knob only
            // exists to opt back into Nagle. Suppressing ACK stretching is
            // a genuine choice (latency for ACK volume), so the example
            // opts in explicitly.
            tcp_no_delay: self.egress_tcp_no_delay,
            tcp_disable_ack_stretching: Some(true),
            ..Default::default()
        })
    }

    async fn handle_app_message(&self, _exec: Executor, message: Bytes) -> Option<Bytes> {
        let message_len = message.len();
        let request = match serde_json::from_slice::<AppMessageRequest>(&message) {
            Ok(request) => request,
            Err(err) => {
                tracing::debug!(
                    ?err,
                    message_len,
                    "transparent proxy demo failed to decode app message as JSON"
                );
                return None;
            }
        };

        let Some(op) = request.op.as_deref() else {
            tracing::debug!(message_len, "transparent proxy demo app message missing op");
            return None;
        };

        // The provider-message channel is reserved for the simple ping demo.
        // Richer commands (settings updates, CA install/uninstall) are
        // exposed as typed XPC routes — see `demo_xpc_server.rs`.
        if op == "ping" {
            let reply = AppMessageReply {
                op: "pong",
                source: "transparent-proxy-provider",
                received_bytes: message_len,
                acknowledged_source: request.source,
                acknowledged_sent_at: request.sent_at,
            };

            match serde_json::to_vec(&reply) {
                Ok(reply_bytes) => {
                    tracing::debug!(
                        request_op = op,
                        message_len,
                        reply_len = reply_bytes.len(),
                        "transparent proxy demo replying to app message"
                    );
                    Some(Bytes::from(reply_bytes))
                }
                Err(err) => {
                    tracing::debug!(
                        ?err,
                        request_op = op,
                        "transparent proxy demo failed to encode app message reply"
                    );
                    None
                }
            }
        } else {
            tracing::debug!(
                request_op = op,
                message_len,
                "transparent proxy demo ignoring app message op (use XPC for non-ping commands)"
            );
            None
        }
    }

    fn match_tcp_flow(
        &self,
        _exec: rama::rt::Executor,
        meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<
            impl rama::Service<
                rama::io::BridgeIo<apple_ne::TcpFlow, apple_ne::NwTcpStream>,
                Output = (),
                Error = Infallible,
            >,
        >,
    > + Send
    + '_ {
        log_new_flow("tcp", &meta);
        let action = flow_action_for_flow(&meta);
        let concurrency_limiter = self.concurrency_limiter.clone();
        let tcp_mitm_service = self.tcp_mitm_service.clone();
        std::future::ready(match action {
            TransparentProxyFlowAction::Intercept => {
                let bundle_identifier = meta.source_app_bundle_identifier.as_deref();
                let (scoped_host, port) = meta
                    .remote_endpoint
                    .as_ref()
                    .map(|endpoint| (Some(&endpoint.host), endpoint.port))
                    .unwrap_or((None, 0));

                match concurrency_limiter.try_reserve(port, bundle_identifier, scoped_host) {
                    Ok(reservation) => FlowAction::Intercept {
                        service: tcp_mitm_service.new_intercept_service(reservation),
                        meta,
                    },
                    Err(reason) => {
                        tracing::debug!(
                            ?reason,
                            port,
                            remote = ?meta.remote_endpoint,
                            bundle_identifier,
                            "transparent proxy tcp concurrency admission rejected flow; passing through"
                        );
                        FlowAction::Passthrough
                    }
                }
            }
            TransparentProxyFlowAction::Passthrough => FlowAction::Passthrough,
            TransparentProxyFlowAction::Blocked => FlowAction::Blocked,
        })
    }

    fn match_udp_flow(
        &self,
        _exec: rama::rt::Executor,
        meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<impl rama::Service<apple_ne::UdpFlow, Output = (), Error = Infallible>>,
    > + Send
    + '_ {
        log_new_flow("udp", &meta);
        // Pass through DNS (port 53) — letting the system resolver
        // hit the wire directly avoids a circular dependency between
        // the proxy service and the resolver it might itself use.
        if meta.remote_endpoint.as_ref().map(|e| e.port) == Some(53) {
            return std::future::ready(FlowAction::Passthrough);
        }
        let action = flow_action_for_flow(&meta);
        let udp_service = self.udp_service.clone();
        std::future::ready(match action {
            TransparentProxyFlowAction::Intercept => FlowAction::Intercept {
                service: udp_service,
                meta,
            },
            TransparentProxyFlowAction::Passthrough => FlowAction::Passthrough,
            TransparentProxyFlowAction::Blocked => FlowAction::Blocked,
        })
    }
}

apple_ne::transparent_proxy_ffi! {
    init = init,
    // Engine defaults (15 min TCP idle backstop, 15 min UDP max-lifetime,
    // 3s decision deadline) are applied automatically. Opt out via
    // `.without_tcp_idle_timeout()` / `.without_udp_max_flow_lifetime()`.
    engine_builder = TransparentProxyEngineBuilder::new(DemoEngineFactory)
        // dial9 runtime telemetry. Enabled when the FFI init handed
        // us a storage directory (the production code path); falls
        // back to a plain tokio runtime when no storage dir is
        // wired through. See `src/dial9.rs` and the example README.
        .with_runtime_factory(crate::dial9::make_runtime_factory()),
}
