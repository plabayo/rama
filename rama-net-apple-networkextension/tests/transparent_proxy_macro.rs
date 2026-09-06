#![cfg(all(test, target_vendor = "apple"))]

use rama_net_apple_networkextension::{
    tproxy::{
        TransparentProxyConfig, TransparentProxyEngineBuilder, TransparentProxyHandler,
        TransparentProxyHandlerFactory, TransparentProxyNetworkRule, TransparentProxyRuleProtocol,
        TransparentProxyServiceContext,
    },
    transparent_proxy_ffi,
};
use std::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
};

static INIT_SHOULD_PANIC: AtomicBool = AtomicBool::new(false);
static CONFIG_SHOULD_PANIC: AtomicBool = AtomicBool::new(false);

fn init(
    _config: Option<&rama_net_apple_networkextension::ffi::tproxy::TransparentProxyInitConfig>,
) -> bool {
    assert!(
        !INIT_SHOULD_PANIC.swap(false, Ordering::SeqCst),
        "synthetic initialization panic"
    );
    true
}

fn proxy_config() -> TransparentProxyConfig {
    assert!(
        !CONFIG_SHOULD_PANIC.swap(false, Ordering::SeqCst),
        "synthetic configuration panic"
    );
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
    _ = rama_transparent_proxy_engine_udp_idle_timeout_ms
        as unsafe extern "C" fn(*mut RamaTransparentProxyEngine) -> u64;
    _ = rama_transparent_proxy_engine_new_udp_session
        as unsafe extern "C" fn(
            *mut RamaTransparentProxyEngine,
            *const RamaTransparentProxyFlowMeta,
            RamaTransparentProxyUdpSessionCallbacks,
        ) -> RamaTransparentProxyUdpSessionResult;
    let _demand: Option<unsafe extern "C" fn(*mut std::ffi::c_void, u64)> =
        RamaTransparentProxyUdpSessionCallbacks {
            context: std::ptr::null_mut(),
            on_server_datagram: None,
            on_client_read_demand: None,
            on_server_closed: None,
        }
        .on_client_read_demand;
}

#[test]
fn macro_generates_promote_ffi_symbols() {
    _ = rama_transparent_proxy_tcp_session_register_promote_callbacks
        as unsafe extern "C" fn(
            *mut RamaTransparentProxyTcpSession,
            RamaTransparentProxyTcpPromoteCallbacks,
        );
    _ = rama_transparent_proxy_tcp_session_confirm_promoted
        as unsafe extern "C" fn(
            *mut RamaTransparentProxyTcpSession,
            u8,
            *const ::std::ffi::c_char,
            usize,
        );
}

#[test]
fn initialization_panic_is_contained_at_c_boundary() {
    INIT_SHOULD_PANIC.store(true, Ordering::SeqCst);
    assert!(!unsafe { rama_transparent_proxy_initialize(std::ptr::null()) });
}

#[test]
fn engine_build_panic_is_contained_at_c_boundary() {
    CONFIG_SHOULD_PANIC.store(true, Ordering::SeqCst);
    let engine = unsafe { rama_transparent_proxy_engine_new() };
    assert!(engine.is_null());

    let engine = unsafe { rama_transparent_proxy_engine_new() };
    assert!(!engine.is_null());
    assert_eq!(
        unsafe { rama_transparent_proxy_engine_udp_idle_timeout_ms(engine) },
        60_000
    );
    unsafe { rama_transparent_proxy_engine_free(engine) };
}
