use std::{convert::Infallible, sync::Arc};

use rama::{
    Service,
    bytes::Bytes,
    net::{
        address::{Host, HostWithPort, ip::private::is_private_ip},
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
mod http;
mod policy;
mod state;
mod tcp;
mod tls;
mod udp;
mod utils;

fn init(config: Option<&apple_ne::ffi::tproxy::TransparentProxyInitConfig>) -> bool {
    if let Some(config) = config {
        // SAFETY: pointer + length validity is guaranteed by FFI contract.
        if let Some(path) = unsafe { config.storage_dir() } {
            tracing::debug!(path = %path.display(), "received storage directory: pass to set_storage_dir");
            self::utils::set_storage_dir(Some(path));
        }
    }

    let init_status = self::utils::init_tracing();
    tracing::info!("rama proxy initialized: {init_status}");
    init_status
}

#[inline(always)]
fn flow_action_for_remote_endpoint(
    remote_endpoint: Option<&HostWithPort>,
) -> TransparentProxyFlowAction {
    let Some(target) = remote_endpoint else {
        return TransparentProxyFlowAction::Passthrough;
    };

    match &target.host {
        Host::Name(_) => TransparentProxyFlowAction::Intercept,
        Host::Address(addr) => {
            if is_private_ip(*addr) && !addr.is_loopback() {
                // non-loopback private ip addreses,
                // as to ensure e2e ffi tests do still run :)
                TransparentProxyFlowAction::Passthrough
            } else {
                TransparentProxyFlowAction::Intercept
            }
        }
    }
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
    udp_service: rama::service::BoxService<
        rama::io::BridgeIo<apple_ne::UdpFlow, apple_ne::NwUdpSocket>,
        (),
        Infallible,
    >,
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

/// Generic reply for fire-and-acknowledge commands such as `install_root_ca`
/// and `uninstall_root_ca`. The container app inspects `ok` and surfaces
/// `error` to the user when the command failed.
///
/// `cert_der_b64` carries the DER-encoded MITM CA certificate (base64) for
/// the CA-related ops so the container can act on it — specifically, set or
/// remove the **admin** trust setting locally, since trust changes go
/// through Authorization Services and need an interactive admin auth dialog
/// that a sysext daemon cannot present.
#[derive(Debug, Serialize)]
struct CommandReply {
    op: &'static str,
    source: &'static str,
    ok: bool,
    error: Option<String>,
    cert_der_b64: Option<String>,
}

impl CommandReply {
    fn ok(op: &'static str) -> Self {
        Self {
            op,
            source: "transparent-proxy-provider",
            ok: true,
            error: None,
            cert_der_b64: None,
        }
    }

    fn ok_with_cert(op: &'static str, cert_der: &[u8]) -> Self {
        use base64::Engine;
        Self {
            op,
            source: "transparent-proxy-provider",
            ok: true,
            error: None,
            cert_der_b64: Some(base64::engine::general_purpose::STANDARD.encode(cert_der)),
        }
    }

    fn err(op: &'static str, err: &rama::error::BoxError) -> Self {
        Self {
            op,
            source: "transparent-proxy-provider",
            ok: false,
            error: Some(format!("{err:#}")),
            cert_der_b64: None,
        }
    }
}

fn encode_command_reply(reply: &CommandReply) -> Option<Bytes> {
    match serde_json::to_vec(reply) {
        Ok(bytes) => Some(Bytes::from(bytes)),
        Err(err) => {
            tracing::warn!(?err, op = reply.op, "failed to encode command reply");
            None
        }
    }
}

impl DemoTransparentProxyHandler {
    async fn try_new(ctx: TransparentProxyServiceContext) -> Result<Self, rama::error::BoxError> {
        let (tcp_mitm_service, shared_state) =
            self::tcp::DemoTcpMitmService::try_new(ctx.clone()).await?;
        let udp_service = self::udp::try_new_service(ctx.clone()).await?.boxed();

        if let Some(xpc_service_name) =
            self::config::DemoProxyConfig::from_opaque_config(ctx.opaque_config())?.xpc_service_name
        {
            self::demo_xpc_server::spawn_xpc_server(
                xpc_service_name,
                shared_state,
                ctx.executor.clone(),
            )
            .unwrap_or_else(|err| {
                tracing::error!(%err, "failed to spawn xpc server");
            });
        }

        let proxy_config = TransparentProxyConfig::new().with_rules(vec![
            TransparentProxyNetworkRule::any().with_protocol(TransparentProxyRuleProtocol::Tcp),
            TransparentProxyNetworkRule::any().with_protocol(TransparentProxyRuleProtocol::Udp),
        ]);

        let concurrency_limiter =
            Arc::new(concurrency::ConcurrencyLimiter::new(Default::default()));

        Ok(Self {
            config: proxy_config,
            concurrency_limiter,
            tcp_mitm_service,
            udp_service,
        })
    }
}

impl TransparentProxyHandler for DemoTransparentProxyHandler {
    fn transparent_proxy_config(&self) -> TransparentProxyConfig {
        self.config.clone()
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

        match op {
            "ping" => {
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
            }
            "install_root_ca" => {
                tracing::info!(message_len, "transparent proxy demo handling install_root_ca");
                let reply = match self::tls::install_root_ca() {
                    Ok(der) => CommandReply::ok_with_cert("install_root_ca", &der),
                    Err(err) => {
                        tracing::error!(error = %err, "install_root_ca failed");
                        CommandReply::err("install_root_ca", &err)
                    }
                };
                encode_command_reply(&reply)
            }
            "uninstall_root_ca" => {
                tracing::info!(message_len, "transparent proxy demo handling uninstall_root_ca");
                let reply = match self::tls::uninstall_root_ca() {
                    Ok(Some(der)) => CommandReply::ok_with_cert("uninstall_root_ca", &der),
                    Ok(None) => CommandReply::ok("uninstall_root_ca"),
                    Err(err) => {
                        tracing::error!(error = %err, "uninstall_root_ca failed");
                        CommandReply::err("uninstall_root_ca", &err)
                    }
                };
                encode_command_reply(&reply)
            }
            _ => {
                tracing::debug!(
                    request_op = op,
                    message_len,
                    "transparent proxy demo ignoring unknown app message op"
                );
                None
            }
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
        let action = flow_action_for_remote_endpoint(meta.remote_endpoint.as_ref());
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
        Output = FlowAction<
            impl rama::Service<
                rama::io::BridgeIo<apple_ne::UdpFlow, apple_ne::NwUdpSocket>,
                Output = (),
                Error = Infallible,
            >,
        >,
    > + Send
    + '_ {
        // Pass through DNS (port 53), the NE sandbox cannot bind raw UDP sockets,
        // so DNS forwarding fails with EPERM. Let DNS go directly.
        if meta.remote_endpoint.as_ref().map(|e| e.port) == Some(53) {
            return std::future::ready(FlowAction::Passthrough);
        }
        let action = flow_action_for_remote_endpoint(meta.remote_endpoint.as_ref());
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
    engine_builder = TransparentProxyEngineBuilder::new(DemoEngineFactory),
}
