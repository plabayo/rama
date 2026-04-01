use std::net::IpAddr;

use rama::{
    net::{
        address::{Host, HostWithPort},
        apple::networkextension::{
            self as apple_ne,
            tproxy::{
                TransparentProxyConfig, TransparentProxyFlowAction, TransparentProxyFlowMeta,
                TransparentProxyFlowProtocol,
                TransparentProxyNetworkRule, TransparentProxyRuleProtocol,
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

fn proxy_config() -> TransparentProxyConfig {
    TransparentProxyConfig::new().with_rules(vec![
        TransparentProxyNetworkRule::any().with_protocol(TransparentProxyRuleProtocol::Tcp),
    ])
}

fn flow_action(meta: &TransparentProxyFlowMeta) -> TransparentProxyFlowAction {
    tracing::trace!(
        protocol = ?meta.protocol,
        remote = ?meta.remote_endpoint,
        local = ?meta.local_endpoint,
        "flow policy action: evaluating (rust callback entered)"
    );

    if meta.protocol != TransparentProxyFlowProtocol::Tcp {
        return TransparentProxyFlowAction::Passthrough;
    }

    flow_action_for_remote_endpoint(meta.remote_endpoint.as_ref())
}

#[inline(always)]
fn flow_action_for_remote_endpoint(
    remote_endpoint: Option<&HostWithPort>
) -> TransparentProxyFlowAction {
    let Some(target) = remote_endpoint else {
        return TransparentProxyFlowAction::Passthrough;
    };

    match &target.host {
        Host::Name(_) => TransparentProxyFlowAction::Intercept,
        Host::Address(IpAddr::V4(addr)) => {
            if !addr.is_loopback() && !addr.is_private() {
                TransparentProxyFlowAction::Intercept
            } else {
                TransparentProxyFlowAction::Passthrough
            }
        }
        Host::Address(IpAddr::V6(addr)) => {
            if !addr.is_loopback() && !addr.is_unique_local() {
                TransparentProxyFlowAction::Intercept
            } else {
                TransparentProxyFlowAction::Passthrough
            }
        }
    }
}

apple_ne::transparent_proxy_ffi! {
    init = init,
    config = proxy_config,
    flow_action = flow_action,
    tcp_service = self::tcp::try_new_service,
    udp_service = self::udp::new_service,
}
