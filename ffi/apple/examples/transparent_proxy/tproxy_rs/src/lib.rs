use std::{convert::Infallible, future::Future, sync::Arc};

use rama::{
    Service,
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
    telemetry::tracing,
};

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod concurrency;
mod config;
mod demo_trace_traffic;
mod host_ca_xpc;
mod http;
mod policy;
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
        // SAFETY: pointer + length validity is guaranteed by FFI contract.
        if let Some(app_group_dir) = unsafe { config.app_group_dir() } {
            tracing::debug!(path = %app_group_dir.display(), "received app-group directory");
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
    udp_service: rama::service::BoxService<apple_ne::UdpFlow, (), Infallible>,
}

impl DemoTransparentProxyHandler {
    async fn try_new(ctx: TransparentProxyServiceContext) -> Result<Self, rama::error::BoxError> {
        let tcp_mitm_service = self::tcp::DemoTcpMitmService::try_new(ctx.clone()).await?;
        let udp_service = self::udp::try_new_service(ctx).await?.boxed();

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

    fn match_tcp_flow(
        &self,
        _exec: rama::rt::Executor,
        meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<impl rama::Service<apple_ne::TcpFlow, Output = (), Error = Infallible>>,
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
        Output = FlowAction<impl rama::Service<apple_ne::UdpFlow, Output = (), Error = Infallible>>,
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
