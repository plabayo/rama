use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

use rama::{
    Service,
    bytes::Bytes,
    net::{
        address::{
            HostWithPort,
            ip::{IpScopes, private::is_private_ip},
        },
        apple::networkextension::{
            self as apple_ne,
            tproxy::{
                DefaultTransparentProxyAsyncRuntimeFactory, FlowAction, TransparentProxyConfig,
                TransparentProxyEngine, TransparentProxyEngineBuilder, TransparentProxyFlowAction,
                TransparentProxyFlowMeta, TransparentProxyHandler, TransparentProxyHandlerFactory,
                TransparentProxyNetworkRule, TransparentProxyRuleProtocol,
                TransparentProxyServiceContext,
            },
        },
    },
    rt::Executor,
    telemetry::tracing,
};
use serde::{Deserialize, Serialize};

// Sanitizer builds disable this feature so the linked test driver and FFI
// library share the system allocator intercepted by AddressSanitizer.
#[cfg(feature = "jemallocator")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod allocator;
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

const UDP_E2E_SAFETY_LIFETIME: Duration = Duration::from_mins(10);
const UDP_E2E_PROBE_BUNDLE_IDENTIFIERS: &[&str] = &["com.apple.python3", "com.apple.nscurl"];

/// Scope of the example's configured UDP overrides. Normal user-provided
/// configuration remains active for the handler's lifetime. The signed E2E's
/// launch-only overrides expire even if its shell cleanup is interrupted.
#[derive(Clone, Copy, Debug, Default)]
enum UdpPolicyScope {
    #[default]
    Normal,
    E2E {
        expires_at: Instant,
    },
}

impl UdpPolicyScope {
    fn new(e2e_mode: bool, now: Instant) -> Self {
        if e2e_mode {
            Self::E2E {
                expires_at: now + UDP_E2E_SAFETY_LIFETIME,
            }
        } else {
            Self::Normal
        }
    }

    fn is_e2e_active_at(self, now: Instant) -> bool {
        matches!(self, Self::E2E { expires_at } if now < expires_at)
    }

    fn configured_overrides_at<'a>(
        self,
        now: Instant,
        passthrough_ports: &'a [u16],
        blocked_endpoints: &'a [HostWithPort],
    ) -> (&'a [u16], &'a [HostWithPort]) {
        match self {
            Self::E2E { expires_at } if now >= expires_at => (&[], &[]),
            Self::Normal | Self::E2E { .. } => (passthrough_ports, blocked_endpoints),
        }
    }
}

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

fn udp_flow_action_for_flow(
    meta: &TransparentProxyFlowMeta,
    passthrough_ports: &[u16],
    blocked_endpoints: &[HostWithPort],
) -> TransparentProxyFlowAction {
    // Exact test overrides intentionally win over the normal port-53 decline,
    // allowing one public resolver to exercise the blocked path while another
    // still proves pass-through in the same signed run.
    if meta
        .remote_endpoint
        .as_ref()
        .is_some_and(|endpoint| blocked_endpoints.contains(endpoint))
    {
        return TransparentProxyFlowAction::Blocked;
    }

    let remote_port = meta.remote_endpoint.as_ref().map(|e| e.port);
    if remote_port == Some(53) || remote_port.is_some_and(|port| passthrough_ports.contains(&port))
    {
        return TransparentProxyFlowAction::Passthrough;
    }

    flow_action_for_flow(meta)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum UdpE2eDiagnosticRejection {
    // These are the eight bits of the shared mask. Adding another reason
    // requires widening both this representation and the atomic mask.
    MissingRemoteEndpoint = 1 << 0,
    EndpointNotAllowlisted = 1 << 1,
    MissingRunUuid = 1 << 2,
    MissingSourceApp = 1 << 3,
    SourceAppNotAllowlisted = 1 << 4,
    MissingLocalEndpoint = 1 << 5,
    ZeroLocalPort = 1 << 6,
    MissingSourcePid = 1 << 7,
}

impl UdpE2eDiagnosticRejection {
    fn label(self) -> &'static str {
        match self {
            Self::MissingRemoteEndpoint => "missing_remote_endpoint",
            Self::EndpointNotAllowlisted => "endpoint_not_allowlisted",
            Self::MissingRunUuid => "missing_run_uuid",
            Self::MissingSourceApp => "missing_source_app",
            Self::SourceAppNotAllowlisted => "source_app_not_allowlisted",
            Self::MissingLocalEndpoint => "missing_local_endpoint",
            Self::ZeroLocalPort => "zero_local_port",
            Self::MissingSourcePid => "missing_source_pid",
        }
    }
}

/// Shared by handler clones: each rejection reason is public at most once per
/// engine generation. Only active E2E new-flow decisions touch this mask.
#[derive(Clone, Default)]
struct UdpE2eDiagnosticRejections(Arc<AtomicU8>);

impl UdpE2eDiagnosticRejections {
    fn receipt(
        &self,
        run_uuid: Option<&str>,
        provider_pid: u32,
        provider_generation: u64,
        reason: UdpE2eDiagnosticRejection,
    ) -> Option<String> {
        // The validated launch configuration supplies the canonical UUID.
        // Never publish a rejection without that qualification identity.
        let run_uuid = run_uuid?;
        let bit = reason as u8;
        if self.0.fetch_or(bit, Ordering::Relaxed) & bit != 0 {
            return None;
        }
        Some(format!(
            "udp_e2e_diagnostic_rejected run_uuid={run_uuid} provider_pid={provider_pid} provider_generation={provider_generation} reason={}",
            reason.label(),
        ))
    }
}

/// Build the one privacy-relaxed message used by the signed E2E. Keeping the
/// allowlist and formatting here makes the behavior example-owned and directly
/// testable; the reusable Swift provider only forwards normalized metadata.
/// Failed prerequisites identify only a fixed reason, never rejected metadata.
fn udp_e2e_diagnostic(
    enabled: bool,
    run_uuid: Option<&str>,
    diagnostic_endpoints: &[HostWithPort],
    provider_pid: u32,
    provider_generation: u64,
    meta: &TransparentProxyFlowMeta,
    action: TransparentProxyFlowAction,
) -> Result<Option<String>, UdpE2eDiagnosticRejection> {
    if !enabled {
        return Ok(None);
    }

    let remote_endpoint = meta
        .remote_endpoint
        .as_ref()
        .ok_or(UdpE2eDiagnosticRejection::MissingRemoteEndpoint)?;
    if !diagnostic_endpoints.contains(remote_endpoint) {
        return Err(UdpE2eDiagnosticRejection::EndpointNotAllowlisted);
    }
    let run_uuid = run_uuid.ok_or(UdpE2eDiagnosticRejection::MissingRunUuid)?;
    let source_app = meta
        .source_app_bundle_identifier
        .as_deref()
        .ok_or(UdpE2eDiagnosticRejection::MissingSourceApp)?;
    if !UDP_E2E_PROBE_BUNDLE_IDENTIFIERS.contains(&source_app) {
        return Err(UdpE2eDiagnosticRejection::SourceAppNotAllowlisted);
    }
    let local_endpoint = match meta.local_endpoint.as_ref() {
        Some(endpoint) => {
            let endpoint = endpoint.clone().canonicalize();
            if endpoint.port == 0 {
                return Err(UdpE2eDiagnosticRejection::ZeroLocalPort);
            }
            endpoint.to_string()
        }
        // nscurl's unbound passthrough canary has one owned process per flow.
        // Its normalized metadata can omit the local endpoint before open.
        // Python fanout still requires concrete endpoint-to-flow correspondence.
        None if source_app == "com.apple.nscurl"
            && remote_endpoint.port == 443
            && matches!(action, TransparentProxyFlowAction::Passthrough) =>
        {
            "unavailable".to_owned()
        }
        None => return Err(UdpE2eDiagnosticRejection::MissingLocalEndpoint),
    };
    let source_pid = meta
        .source_app_pid
        .ok_or(UdpE2eDiagnosticRejection::MissingSourcePid)?;

    Ok(Some(format!(
        "udp_e2e_decision run_uuid={run_uuid} provider_pid={provider_pid} provider_generation={provider_generation} rama_decision={action} flow_id={} remote_endpoint={remote_endpoint} local_endpoint={local_endpoint} source_app={source_app} source_pid={}",
        meta.flow_id, source_pid,
    )))
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

/// Example-local adapter that lets the public opaque JSON configure engine
/// construction policy before the core builder consumes that same payload for
/// handler creation. The generic FFI macro intentionally treats opaque bytes
/// as opaque; parsing belongs to this example's schema.
struct DemoConfiguredEngineBuilder {
    inner: TransparentProxyEngineBuilder<
        DemoEngineFactory,
        DefaultTransparentProxyAsyncRuntimeFactory,
    >,
}

impl DemoConfiguredEngineBuilder {
    fn new() -> Self {
        Self {
            inner: TransparentProxyEngineBuilder::new(DemoEngineFactory)
                .with_runtime_factory(crate::dial9::make_runtime_factory()),
        }
    }

    fn maybe_with_opaque_config(mut self, opaque_config: Option<Arc<[u8]>>) -> Self {
        // Preserve the existing invalid-JSON behavior: handler construction in
        // `build` remains authoritative and returns its normal decode error.
        // This best-effort parse only extracts fields needed before that point.
        if let Ok(config) =
            self::config::DemoProxyConfig::from_opaque_config(opaque_config.as_deref())
            && let Some(milliseconds) = config.udp_ingress_probe_lease_ms
        {
            self.inner = self
                .inner
                .with_udp_ingress_probe_lease(Duration::from_millis(milliseconds));
        }
        self.inner = self.inner.maybe_with_opaque_config(opaque_config);
        self
    }

    fn build(
        self,
    ) -> Result<TransparentProxyEngine<DemoTransparentProxyHandler>, rama::error::BoxError> {
        self.inner.build()
    }
}

#[derive(Clone)]
struct DemoTransparentProxyHandler {
    config: TransparentProxyConfig,
    concurrency_limiter: Arc<concurrency::ConcurrencyLimiter>,
    tcp_mitm_service: tcp::DemoTcpMitmService,
    udp_service: rama::service::BoxService<apple_ne::UdpFlow, (), Infallible>,
    udp_passthrough_ports: Arc<[u16]>,
    udp_blocked_endpoints: Arc<[HostWithPort]>,
    udp_policy_scope: UdpPolicyScope,
    evidence_run_uuid: Option<Arc<str>>,
    udp_e2e_diagnostic_endpoints: Arc<[HostWithPort]>,
    udp_e2e_diagnostic_rejections: UdpE2eDiagnosticRejections,
    provider_pid: u32,
    provider_generation: u64,
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
        let demo_config = self::config::DemoProxyConfig::from_opaque_config(ctx.opaque_config())?;
        let (tcp_mitm_service, shared_state) =
            self::tcp::DemoTcpMitmService::try_new(ctx.clone()).await?;
        let udp_policy_scope = UdpPolicyScope::new(demo_config.udp_e2e_mode, Instant::now());
        let udp_service = self::udp::try_new_service(ctx.clone(), udp_policy_scope)
            .await?
            .boxed();

        let udp_passthrough_ports: Arc<[u16]> = demo_config.udp_passthrough_ports.clone().into();
        let udp_blocked_endpoints = demo_config.udp_blocked_endpoints.clone().into();
        let evidence_run_uuid = demo_config.evidence_run_uuid.map(Arc::<str>::from);
        let udp_e2e_diagnostic_endpoints: Arc<[HostWithPort]> =
            demo_config.udp_e2e_diagnostic_endpoints.into();
        let provider_pid = ctx.provider_pid();
        let provider_generation = ctx.provider_generation();
        if udp_policy_scope.is_e2e_active_at(Instant::now())
            && let Some(run_uuid) = evidence_run_uuid.as_deref()
        {
            tracing::debug!(
                "udp_e2e_diagnostic_active run_uuid={run_uuid} provider_pid={provider_pid} provider_generation={provider_generation} endpoint_count={} probe_app_count={}",
                udp_e2e_diagnostic_endpoints.len(),
                UDP_E2E_PROBE_BUNDLE_IDENTIFIERS.len(),
            );
        }
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

        let mut proxy_config = TransparentProxyConfig::new()
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
        if let Some(max_pending_bytes) = demo_config.tcp_write_pump_max_pending_bytes {
            proxy_config = proxy_config.with_tcp_write_pump_max_pending_bytes(max_pending_bytes);
        }

        let concurrency_limiter =
            Arc::new(concurrency::ConcurrencyLimiter::new(Default::default()));

        Ok(Self {
            config: proxy_config,
            concurrency_limiter,
            tcp_mitm_service,
            udp_service,
            udp_passthrough_ports,
            udp_blocked_endpoints,
            udp_policy_scope,
            evidence_run_uuid,
            udp_e2e_diagnostic_endpoints,
            udp_e2e_diagnostic_rejections: UdpE2eDiagnosticRejections::default(),
            provider_pid,
            provider_generation,
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
        let now = Instant::now();
        let (udp_passthrough_ports, udp_blocked_endpoints) =
            self.udp_policy_scope.configured_overrides_at(
                now,
                &self.udp_passthrough_ports,
                &self.udp_blocked_endpoints,
            );
        let action = udp_flow_action_for_flow(&meta, udp_passthrough_ports, udp_blocked_endpoints);
        let diagnostic = udp_e2e_diagnostic(
            self.udp_policy_scope.is_e2e_active_at(now),
            self.evidence_run_uuid.as_deref(),
            &self.udp_e2e_diagnostic_endpoints,
            self.provider_pid,
            self.provider_generation,
            &meta,
            action,
        );
        let message = match diagnostic {
            Ok(message) => message,
            Err(reason) => self.udp_e2e_diagnostic_rejections.receipt(
                self.evidence_run_uuid.as_deref(),
                self.provider_pid,
                self.provider_generation,
                reason,
            ),
        };
        if let Some(message) = message {
            tracing::debug!("{message}");
        }
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

#[cfg(test)]
mod udp_policy_tests {
    use super::*;
    use rama::net::apple::networkextension::tproxy::TransparentProxyFlowProtocol;

    fn udp_meta(endpoint: &str) -> TransparentProxyFlowMeta {
        let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
        meta.remote_endpoint = Some(endpoint.parse().expect("valid endpoint"));
        meta
    }

    fn udp_meta_for_app(endpoint: &str, bundle_identifier: &str) -> TransparentProxyFlowMeta {
        let mut meta = udp_meta(endpoint);
        meta.local_endpoint = Some("127.0.0.1:50001".parse().expect("valid local endpoint"));
        meta.source_app_bundle_identifier = Some(
            bundle_identifier
                .parse()
                .expect("non-empty bundle identifier"),
        );
        meta.source_app_pid = Some(4242);
        meta
    }

    #[test]
    fn exact_block_wins_over_dns_passthrough() {
        let blocked = ["8.8.8.8:53".parse().expect("valid endpoint")];

        assert_eq!(
            udp_flow_action_for_flow(&udp_meta("8.8.8.8:53"), &[443], &blocked),
            TransparentProxyFlowAction::Blocked
        );
        assert_eq!(
            udp_flow_action_for_flow(&udp_meta("1.1.1.1:53"), &[443], &blocked),
            TransparentProxyFlowAction::Passthrough
        );
        assert_eq!(
            udp_flow_action_for_flow(&udp_meta("104.16.132.229:443"), &[443], &blocked),
            TransparentProxyFlowAction::Passthrough
        );
        assert_eq!(
            udp_flow_action_for_flow(&udp_meta("162.159.200.1:123"), &[443], &blocked),
            TransparentProxyFlowAction::Intercept
        );
    }

    #[test]
    fn e2e_scope_expires_only_temporary_overrides() {
        let start = Instant::now();
        let ports = [443];
        let blocked = ["8.8.8.8:53".parse().expect("valid endpoint")];
        let before_expiry = start + UDP_E2E_SAFETY_LIFETIME - Duration::from_nanos(1);
        let at_expiry = start + UDP_E2E_SAFETY_LIFETIME;

        let e2e = UdpPolicyScope::new(true, start);
        assert!(e2e.is_e2e_active_at(before_expiry));
        assert_eq!(
            e2e.configured_overrides_at(before_expiry, &ports, &blocked),
            (&ports[..], &blocked[..])
        );
        assert!(!e2e.is_e2e_active_at(at_expiry));
        assert_eq!(
            e2e.configured_overrides_at(at_expiry, &ports, &blocked),
            (&[][..], &[][..])
        );

        let normal = UdpPolicyScope::new(false, start);
        assert!(!normal.is_e2e_active_at(at_expiry));
        assert_eq!(
            normal.configured_overrides_at(at_expiry, &ports, &blocked),
            (&ports[..], &blocked[..])
        );
    }

    const RUN_UUID: &str = "12345678-1234-4234-8234-123456789abc";
    const REJECTION_REASONS: [UdpE2eDiagnosticRejection; 8] = [
        UdpE2eDiagnosticRejection::MissingRemoteEndpoint,
        UdpE2eDiagnosticRejection::EndpointNotAllowlisted,
        UdpE2eDiagnosticRejection::MissingRunUuid,
        UdpE2eDiagnosticRejection::MissingSourceApp,
        UdpE2eDiagnosticRejection::SourceAppNotAllowlisted,
        UdpE2eDiagnosticRejection::MissingLocalEndpoint,
        UdpE2eDiagnosticRejection::ZeroLocalPort,
        UdpE2eDiagnosticRejection::MissingSourcePid,
    ];

    #[test]
    fn e2e_diagnostics_preserve_the_exact_success_message() {
        let python = udp_meta_for_app("1.1.1.1:53", "com.apple.python3");
        let endpoints = ["1.1.1.1:53".parse().expect("valid endpoint")];
        let expected = format!(
            "udp_e2e_decision run_uuid={RUN_UUID} provider_pid=99 provider_generation=7 rama_decision=passthrough flow_id={} remote_endpoint=1.1.1.1:53 local_endpoint=127.0.0.1:50001 source_app=com.apple.python3 source_pid=4242",
            python.flow_id,
        );
        assert_eq!(
            udp_e2e_diagnostic(
                true,
                Some(RUN_UUID),
                &endpoints,
                99,
                7,
                &python,
                TransparentProxyFlowAction::Passthrough,
            )
            .unwrap()
            .as_deref(),
            Some(expected.as_str())
        );
    }

    #[test]
    fn e2e_unavailable_local_is_only_for_nscurl_udp443_passthrough() {
        for endpoint in ["1.1.1.1:443", "[2606:4700:4700::1111]:443"] {
            let mut meta = udp_meta_for_app(endpoint, "com.apple.nscurl");
            meta.local_endpoint = None;
            let endpoints = [endpoint.parse().unwrap()];
            let diagnostic = |meta: &TransparentProxyFlowMeta, action| {
                udp_e2e_diagnostic(true, Some(RUN_UUID), &endpoints, 99, 7, meta, action)
            };
            let expected = format!(
                "udp_e2e_decision run_uuid={RUN_UUID} provider_pid=99 provider_generation=7 rama_decision=passthrough flow_id={} remote_endpoint={endpoint} local_endpoint=unavailable source_app=com.apple.nscurl source_pid=4242",
                meta.flow_id,
            );
            assert_eq!(
                diagnostic(&meta, TransparentProxyFlowAction::Passthrough),
                Ok(Some(expected)),
            );
            for action in [
                TransparentProxyFlowAction::Intercept,
                TransparentProxyFlowAction::Blocked,
            ] {
                assert_eq!(
                    diagnostic(&meta, action),
                    Err(UdpE2eDiagnosticRejection::MissingLocalEndpoint)
                );
            }
            meta.source_app_pid = None;
            assert_eq!(
                diagnostic(&meta, TransparentProxyFlowAction::Passthrough),
                Err(UdpE2eDiagnosticRejection::MissingSourcePid),
            );
            meta.source_app_pid = Some(4242);
            meta.local_endpoint = Some("127.0.0.1:0".parse().unwrap());
            assert_eq!(
                diagnostic(&meta, TransparentProxyFlowAction::Passthrough),
                Err(UdpE2eDiagnosticRejection::ZeroLocalPort),
            );
        }
        for (endpoint, app) in [
            ("1.1.1.1:443", "com.apple.python3"),
            ("1.1.1.1:53", "com.apple.nscurl"),
        ] {
            let mut meta = udp_meta_for_app(endpoint, app);
            meta.local_endpoint = None;
            assert_eq!(
                udp_e2e_diagnostic(
                    true,
                    Some(RUN_UUID),
                    &[endpoint.parse().unwrap()],
                    99,
                    7,
                    &meta,
                    TransparentProxyFlowAction::Passthrough
                ),
                Err(UdpE2eDiagnosticRejection::MissingLocalEndpoint),
            );
        }
    }

    #[test]
    fn e2e_diagnostics_distinguish_all_rejected_prerequisites() {
        let endpoints = ["1.1.1.1:53".parse().expect("valid endpoint")];
        for reason in REJECTION_REASONS {
            let mut meta = udp_meta_for_app("1.1.1.1:53", "com.apple.python3");
            let mut run_uuid = Some(RUN_UUID);
            match reason {
                UdpE2eDiagnosticRejection::MissingRemoteEndpoint => meta.remote_endpoint = None,
                UdpE2eDiagnosticRejection::EndpointNotAllowlisted => {
                    meta.remote_endpoint = Some("8.8.8.8:53".parse().unwrap());
                }
                UdpE2eDiagnosticRejection::MissingRunUuid => run_uuid = None,
                UdpE2eDiagnosticRejection::MissingSourceApp => {
                    meta.source_app_bundle_identifier = None;
                }
                UdpE2eDiagnosticRejection::SourceAppNotAllowlisted => {
                    meta.source_app_bundle_identifier =
                        Some("com.example.background".parse().unwrap());
                }
                UdpE2eDiagnosticRejection::MissingLocalEndpoint => meta.local_endpoint = None,
                UdpE2eDiagnosticRejection::ZeroLocalPort => {
                    meta.local_endpoint = Some("127.0.0.1:0".parse().unwrap());
                }
                UdpE2eDiagnosticRejection::MissingSourcePid => meta.source_app_pid = None,
            }
            assert_eq!(
                udp_e2e_diagnostic(
                    true,
                    run_uuid,
                    &endpoints,
                    99,
                    7,
                    &meta,
                    TransparentProxyFlowAction::Passthrough,
                ),
                Err(reason),
            );
            // Normal and expired E2E mode must return before any rejection is
            // offered to the shared mask, even with missing metadata.
            let start = Instant::now();
            for (scope, now) in [
                (UdpPolicyScope::Normal, start),
                (
                    UdpPolicyScope::new(true, start),
                    start + UDP_E2E_SAFETY_LIFETIME,
                ),
            ] {
                assert_eq!(
                    udp_e2e_diagnostic(
                        scope.is_e2e_active_at(now),
                        run_uuid,
                        &endpoints,
                        99,
                        7,
                        &meta,
                        TransparentProxyFlowAction::Passthrough,
                    ),
                    Ok(None),
                );
            }
        }
    }

    #[test]
    fn e2e_rejection_receipts_are_bounded_across_clones_and_threads() {
        let rejections = UdpE2eDiagnosticRejections::default();
        let start = std::sync::Barrier::new(16);
        let receipts = std::thread::scope(|scope| {
            let workers = (0..16)
                .map(|_| {
                    let cloned = rejections.clone();
                    let start = &start;
                    scope.spawn(move || {
                        start.wait();
                        REJECTION_REASONS
                            .into_iter()
                            .cycle()
                            .take(REJECTION_REASONS.len() * 4)
                            .filter_map(|reason| cloned.receipt(Some(RUN_UUID), 99, 7, reason))
                            .collect::<Vec<_>>()
                    })
                })
                .collect::<Vec<_>>();
            workers
                .into_iter()
                .flat_map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(receipts.len(), REJECTION_REASONS.len());
        for reason in REJECTION_REASONS {
            // Exact output guards against accidentally publishing rejected
            // endpoints, application identifiers, or source process metadata.
            let expected = format!(
                "udp_e2e_diagnostic_rejected run_uuid={RUN_UUID} provider_pid=99 provider_generation=7 reason={}",
                reason.label(),
            );
            assert_eq!(receipts.iter().filter(|line| **line == expected).count(), 1);
            assert!(rejections.receipt(Some(RUN_UUID), 99, 7, reason).is_none());
        }
        let next_generation = UdpE2eDiagnosticRejections::default();
        assert!(
            next_generation
                .receipt(
                    Some(RUN_UUID),
                    99,
                    8,
                    UdpE2eDiagnosticRejection::MissingLocalEndpoint,
                )
                .is_some()
        );
    }

    #[test]
    fn e2e_rejections_without_run_identity_are_silent_and_do_not_consume_budget() {
        let rejections = UdpE2eDiagnosticRejections::default();
        for reason in REJECTION_REASONS {
            assert!(rejections.receipt(None, 99, 7, reason).is_none());
            assert!(rejections.receipt(Some(RUN_UUID), 99, 7, reason).is_some());
        }
    }
}

apple_ne::transparent_proxy_ffi! {
    init = init,
    // Engine defaults include the 15 min TCP idle backstop and 3s decision
    // deadline. UDP has no absolute max lifetime by default so active QUIC/H3
    // flows remain viable; deployments can opt into a cap explicitly with
    // `.with_udp_max_flow_lifetime(...)`.
    // The adapter preserves the same dial9 runtime factory while allowing
    // example-owned opaque JSON fields to tune construction-time policy.
    engine_builder = DemoConfiguredEngineBuilder::new(),
}
