use std::{convert::Infallible, future::Future};

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

mod config;
mod demo_trace_traffic;
mod http;
mod policy;
mod tcp;
mod tls;
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

fn proxy_config() -> TransparentProxyConfig {
    TransparentProxyConfig::new().with_rules(vec![
        TransparentProxyNetworkRule::any().with_protocol(TransparentProxyRuleProtocol::Tcp),
    ])
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
            if is_private_ip(*addr) {
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
    tcp_service: rama::service::BoxService<apple_ne::TcpFlow, (), Infallible>,
}

impl DemoTransparentProxyHandler {
    async fn try_new(ctx: TransparentProxyServiceContext) -> Result<Self, rama::error::BoxError> {
        let tcp_service = self::tcp::try_new_service(ctx).await?.boxed();
        Ok(Self {
            config: proxy_config(),
            tcp_service,
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
        let tcp_service = self.tcp_service.clone();
        std::future::ready(match action {
            TransparentProxyFlowAction::Intercept => FlowAction::Intercept {
                service: tcp_service,
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
