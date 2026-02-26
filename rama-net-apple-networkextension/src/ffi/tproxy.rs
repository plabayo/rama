use std::ffi::{c_char, c_void};

use rama_net::address::HostWithPort;

use crate::ffi::cstr::{opt_cstr_to_host, opt_cstr_to_non_empty_str};
use crate::ffi::{BytesOwned, BytesView};
use crate::tproxy::{self, TransparentProxyFlowProtocol};

#[repr(C)]
pub struct TransparentFlowEndpoint {
    pub host_utf8: *const c_char,
    pub host_utf8_len: usize,
    pub port: u16,
}

impl TransparentFlowEndpoint {
    unsafe fn as_optional_host_with_port(&self) -> Option<HostWithPort> {
        let host = unsafe { opt_cstr_to_host(self.host_utf8) }?;
        Some(HostWithPort::new(host, self.port))
    }
}

#[repr(C)]
pub struct TransparentProxyFlowMeta {
    pub protocol: u32,
    pub remote_endpoint: TransparentFlowEndpoint,
    pub local_endpoint: TransparentFlowEndpoint,
    pub source_app_signing_identifier_utf8: *const c_char,
    pub source_app_bundle_identifier_utf8: *const c_char,
}

impl TransparentProxyFlowMeta {
    pub unsafe fn as_owned_rust_type(&self) -> tproxy::TransparentProxyFlowMeta {
        tproxy::TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::from(self.protocol))
            .maybe_with_remote_endpoint(
                // SAFETY: pointer validity is part of FFI contract.
                unsafe { self.remote_endpoint.as_optional_host_with_port() },
            )
            .maybe_with_local_endpoint(
                // SAFETY: pointer validity is part of FFI contract.
                unsafe { self.local_endpoint.as_optional_host_with_port() },
            )
            .maybe_with_source_app_signing_identifier(
                // SAFETY: pointer validity is part of FFI contract.
                unsafe { opt_cstr_to_non_empty_str(self.source_app_signing_identifier_utf8) },
            )
            .maybe_with_source_app_bundle_identifier(
                // SAFETY: pointer validity is part of FFI contract.
                unsafe { opt_cstr_to_non_empty_str(self.source_app_bundle_identifier_utf8) },
            )
    }
}

#[repr(C)]
pub struct TransparentProxyNetworkRule {
    pub remote_network_utf8: *const c_char,
    pub remote_network_utf8_len: usize,
    pub remote_prefix: u8,
    pub local_network_utf8: *const c_char,
    pub local_network_utf8_len: usize,
    pub local_prefix: u8,
    pub protocol: u32,
    pub direction: u32,
}

#[repr(C)]
pub struct TransparentProxyConfig {
    pub rules: *const TransparentProxyNetworkRule,
    pub rules_len: usize,
}

impl TransparentProxyConfig {
    pub unsafe fn borrow_from_rust_type(t: &tproxy::TransparentProxyConfig) -> Self {
        // TODO
        Self {
            rules: todo!(),
            rules_len: todo!(),
        }
    }
}

#[repr(C)]
pub struct TransparentProxyTcpSessionCallbacks {
    pub context: *mut c_void,
    pub on_server_bytes: Option<extern "C" fn(*mut c_void, BytesView)>,
    pub on_server_closed: Option<extern "C" fn(*mut c_void)>,
}

#[repr(C)]
pub struct TransparentProxyUdpSessionCallbacks {
    pub context: *mut c_void,
    pub on_server_datagram: Option<extern "C" fn(*mut c_void, BytesView)>,
    pub on_server_closed: Option<extern "C" fn(*mut c_void)>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rama_owned_bytes_free(bytes: BytesOwned) {
    // SAFETY: caller guarantees `bytes` came from this FFI layer and is not freed yet.
    unsafe { bytes.free() }
}
