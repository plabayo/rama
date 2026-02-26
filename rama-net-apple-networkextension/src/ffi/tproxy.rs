use std::{
    ffi::{c_char, c_void},
    ptr,
};

use rama_net::address::{Host, HostWithPort};
use rama_utils::str::NonEmptyStr;

use crate::ffi::BytesView;
use crate::tproxy::{self, TransparentProxyFlowProtocol};

#[repr(C)]
pub struct TransparentFlowEndpoint {
    pub host_utf8: *const c_char,
    pub host_utf8_len: usize,
    pub port: u16,
}

impl TransparentFlowEndpoint {
    /// # Safety
    ///
    /// `self.host_utf8` must either be null, or point to at least
    /// `self.host_utf8_len` bytes of valid UTF-8 for the duration of this call.
    pub unsafe fn as_optional_host_with_port(&self) -> Option<HostWithPort> {
        if self.port == 0 {
            return None;
        }

        // SAFETY: pointer + length validity is guaranteed by caller contract.
        let host = unsafe { opt_utf8_to_host(self.host_utf8, self.host_utf8_len) }?;
        Some(HostWithPort::new(host, self.port))
    }
}

#[repr(C)]
pub struct TransparentProxyFlowMeta {
    pub protocol: u32,
    pub remote_endpoint: TransparentFlowEndpoint,
    pub local_endpoint: TransparentFlowEndpoint,
    pub source_app_signing_identifier_utf8: *const c_char,
    pub source_app_signing_identifier_utf8_len: usize,
    pub source_app_bundle_identifier_utf8: *const c_char,
    pub source_app_bundle_identifier_utf8_len: usize,
}

impl TransparentProxyFlowMeta {
    /// # Safety
    ///
    /// All pointer + length fields in `self` must be valid for reads during
    /// this call.
    pub unsafe fn as_owned_rust_type(&self) -> tproxy::TransparentProxyFlowMeta {
        tproxy::TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::from(self.protocol))
            .maybe_with_remote_endpoint(
                // SAFETY: pointer + length validity is guaranteed by caller contract.
                unsafe { self.remote_endpoint.as_optional_host_with_port() },
            )
            .maybe_with_local_endpoint(
                // SAFETY: pointer + length validity is guaranteed by caller contract.
                unsafe { self.local_endpoint.as_optional_host_with_port() },
            )
            .maybe_with_source_app_signing_identifier(
                // SAFETY: pointer + length validity is guaranteed by caller contract.
                unsafe {
                    opt_utf8_to_non_empty_str(
                        self.source_app_signing_identifier_utf8,
                        self.source_app_signing_identifier_utf8_len,
                    )
                },
            )
            .maybe_with_source_app_bundle_identifier(
                // SAFETY: pointer + length validity is guaranteed by caller contract.
                unsafe {
                    opt_utf8_to_non_empty_str(
                        self.source_app_bundle_identifier_utf8,
                        self.source_app_bundle_identifier_utf8_len,
                    )
                },
            )
    }
}

#[repr(C)]
pub struct TransparentProxyNetworkRule {
    pub remote_network_utf8: *const c_char,
    pub remote_network_utf8_len: usize,
    pub remote_prefix: u8,
    pub remote_prefix_is_set: bool,
    pub local_network_utf8: *const c_char,
    pub local_network_utf8_len: usize,
    pub local_prefix: u8,
    pub local_prefix_is_set: bool,
    pub protocol: u32,
    pub direction: u32,
}

#[repr(C)]
pub struct TransparentProxyConfig {
    pub tunnel_remote_address_utf8: *const c_char,
    pub tunnel_remote_address_utf8_len: usize,
    pub rules: *const TransparentProxyNetworkRule,
    pub rules_len: usize,
}

impl TransparentProxyConfig {
    /// Build an owned FFI representation from typed Rust config.
    #[must_use]
    pub fn from_rust_type(config: &tproxy::TransparentProxyConfig) -> Self {
        let (tunnel_remote_address_utf8, tunnel_remote_address_utf8_len) =
            alloc_utf8(config.tunnel_remote_address());

        let mut rules = Vec::with_capacity(config.rules().len());
        for rule in config.rules() {
            let (remote_network_utf8, remote_network_utf8_len) =
                alloc_opt_utf8(rule.remote_network());
            let (local_network_utf8, local_network_utf8_len) = alloc_opt_utf8(rule.local_network());

            rules.push(TransparentProxyNetworkRule {
                remote_network_utf8,
                remote_network_utf8_len,
                remote_prefix: rule.remote_prefix().unwrap_or(0),
                remote_prefix_is_set: rule.remote_prefix().is_some(),
                local_network_utf8,
                local_network_utf8_len,
                local_prefix: rule.local_prefix().unwrap_or(0),
                local_prefix_is_set: rule.local_prefix().is_some(),
                protocol: rule.protocol().as_u32(),
                direction: rule.direction() as u32,
            });
        }

        let boxed_rules = rules.into_boxed_slice();
        let rules_len = boxed_rules.len();
        let rules = if rules_len == 0 {
            ptr::null()
        } else {
            Box::into_raw(boxed_rules) as *const TransparentProxyNetworkRule
        };

        Self {
            tunnel_remote_address_utf8,
            tunnel_remote_address_utf8_len,
            rules,
            rules_len,
        }
    }

    /// # Safety
    ///
    /// `self` must have been created by [`TransparentProxyConfig::from_rust_type`]
    /// exactly once. Calling this twice on the same allocations is undefined behavior.
    pub unsafe fn free(self) {
        // SAFETY: this pointer/len pair came from `alloc_utf8` in `from_rust_type`.
        unsafe {
            free_utf8(
                self.tunnel_remote_address_utf8,
                self.tunnel_remote_address_utf8_len,
            )
        };

        if self.rules.is_null() || self.rules_len == 0 {
            return;
        }

        let rules_ptr = self.rules as *mut TransparentProxyNetworkRule;
        let boxed_rules = {
            let raw_slice = ptr::slice_from_raw_parts_mut(rules_ptr, self.rules_len);
            // SAFETY: `raw_slice` was produced via `Box::into_raw` in `from_rust_type`.
            unsafe { Box::from_raw(raw_slice) }
        };

        for rule in boxed_rules.iter() {
            // SAFETY: these pointer/len pairs came from `alloc_opt_utf8` in `from_rust_type`.
            unsafe { free_utf8(rule.remote_network_utf8, rule.remote_network_utf8_len) };
            // SAFETY: these pointer/len pairs came from `alloc_opt_utf8` in `from_rust_type`.
            unsafe { free_utf8(rule.local_network_utf8, rule.local_network_utf8_len) };
        }
    }
}

#[repr(C)]
pub struct TransparentProxyTcpSessionCallbacks {
    pub context: *mut c_void,
    pub on_server_bytes: Option<unsafe extern "C" fn(*mut c_void, BytesView)>,
    pub on_server_closed: Option<unsafe extern "C" fn(*mut c_void)>,
}

#[repr(C)]
pub struct TransparentProxyUdpSessionCallbacks {
    pub context: *mut c_void,
    pub on_server_datagram: Option<unsafe extern "C" fn(*mut c_void, BytesView)>,
    pub on_server_closed: Option<unsafe extern "C" fn(*mut c_void)>,
}

fn alloc_opt_utf8(value: Option<&str>) -> (*const c_char, usize) {
    value.map_or((ptr::null(), 0), alloc_utf8)
}

fn alloc_utf8(value: &str) -> (*const c_char, usize) {
    let boxed: Box<[u8]> = value.as_bytes().to_vec().into_boxed_slice();
    let len = boxed.len();
    if len == 0 {
        return (ptr::null(), 0);
    }
    (Box::into_raw(boxed) as *const u8 as *const c_char, len)
}

/// # Safety
///
/// `ptr/len` must come from `alloc_utf8` and must not be freed more than once.
unsafe fn free_utf8(ptr: *const c_char, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }

    let raw_slice = ptr::slice_from_raw_parts_mut(ptr as *mut u8, len);
    // SAFETY: caller guarantees this points to memory allocated via `alloc_utf8`.
    let _ = unsafe { Box::from_raw(raw_slice) };
}

/// # Safety
///
/// `ptr` must be null or readable for `len` bytes and contain UTF-8.
unsafe fn opt_utf8_to_non_empty_str(ptr: *const c_char, len: usize) -> Option<NonEmptyStr> {
    // SAFETY: pointer + length validity is guaranteed by caller contract.
    let raw = unsafe { opt_utf8(ptr, len) }?;
    raw.try_into().ok()
}

/// # Safety
///
/// `ptr` must be null or readable for `len` bytes and contain UTF-8.
unsafe fn opt_utf8_to_host(ptr: *const c_char, len: usize) -> Option<Host> {
    // SAFETY: pointer + length validity is guaranteed by caller contract.
    let raw = unsafe { opt_utf8(ptr, len) }?;
    Host::try_from(raw).ok()
}

/// # Safety
///
/// `ptr` must be null or readable for `len` bytes and contain UTF-8.
unsafe fn opt_utf8<'a>(ptr: *const c_char, len: usize) -> Option<&'a str> {
    if ptr.is_null() || len == 0 {
        return None;
    }

    // SAFETY: pointer + length validity is guaranteed by caller contract.
    let raw = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };
    let text = std::str::from_utf8(raw).ok()?.trim();
    (!text.is_empty()).then_some(text)
}
