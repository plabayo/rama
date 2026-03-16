#![cfg(target_vendor = "apple")]

use rama_net_apple_networkextension::{
    tproxy::{
        TransparentProxyConfig, TransparentProxyFlowMeta, TransparentProxyNetworkRule,
        TransparentProxyRuleProtocol,
    },
    transparent_proxy_ffi,
};

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

fn should_intercept_flow(_meta: &TransparentProxyFlowMeta) -> bool {
    true
}

transparent_proxy_ffi! {
    init = init,
    config = proxy_config,
    should_intercept_flow = should_intercept_flow,
}

#[test]
fn macro_generates_direct_dependency_ffi_symbols() {
    let _ = rama_transparent_proxy_initialize
        as unsafe extern "C" fn(
            *const rama_net_apple_networkextension::ffi::tproxy::TransparentProxyInitConfig,
        ) -> bool;
    let _ = rama_transparent_proxy_engine_new
        as unsafe extern "C" fn() -> *mut RamaTransparentProxyEngine;
}
