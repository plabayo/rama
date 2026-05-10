#![cfg(target_vendor = "apple")]

use rama_net_apple_networkextension::{
    tproxy::{
        TransparentProxyConfig, TransparentProxyEngineBuilder, TransparentProxyHandler,
        TransparentProxyHandlerFactory, TransparentProxyNetworkRule, TransparentProxyRuleProtocol,
        TransparentProxyServiceContext,
    },
    transparent_proxy_ffi,
};
use std::future::Future;

fn init(
    _config: Option<&rama_net_apple_networkextension::ffi::tproxy::TransparentProxyInitConfig>,
) -> bool {
    true
}

fn proxy_config() -> TransparentProxyConfig {
    TransparentProxyConfig::new().with_rules(vec![
        TransparentProxyNetworkRule::any().with_protocol(TransparentProxyRuleProtocol::Tcp),
    ])
}

#[derive(Clone, Copy, Default)]
struct TestFactory;

#[derive(Clone)]
struct TestHandler;

impl TransparentProxyHandlerFactory for TestFactory {
    type Handler = TestHandler;
    type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

    fn create_transparent_proxy_handler(
        &self,
        _ctx: TransparentProxyServiceContext,
    ) -> impl Future<Output = Result<Self::Handler, Self::Error>> + Send {
        std::future::ready(Ok(TestHandler))
    }
}

impl TransparentProxyHandler for TestHandler {
    fn transparent_proxy_config(&self) -> TransparentProxyConfig {
        proxy_config()
    }
}

transparent_proxy_ffi! {
    init = init,
    engine_builder = TransparentProxyEngineBuilder::new(TestFactory),
}

#[test]
fn macro_generates_direct_dependency_ffi_symbols() {
    _ = rama_transparent_proxy_initialize
        as unsafe extern "C" fn(
            *const rama_net_apple_networkextension::ffi::tproxy::TransparentProxyInitConfig,
        ) -> bool;
    _ = rama_transparent_proxy_engine_new
        as unsafe extern "C" fn() -> *mut RamaTransparentProxyEngine;
    _ = rama_transparent_proxy_engine_handle_app_message
        as unsafe extern "C" fn(
            *mut RamaTransparentProxyEngine,
            rama_net_apple_networkextension::ffi::BytesView,
        ) -> rama_net_apple_networkextension::ffi::BytesOwned;
}
