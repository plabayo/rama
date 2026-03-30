use std::{
    ffi::{c_char, c_void},
    path::PathBuf,
    ptr,
};

use rama_net::address::{Host, HostWithPort};
use rama_utils::str::NonEmptyStr;

use crate::ffi::BytesView;
use crate::process::AuditToken;
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
    pub source_app_audit_token_bytes: *const u8,
    pub source_app_audit_token_bytes_len: usize,
    pub source_app_pid: i32,
    pub source_app_pid_is_set: bool,
}

impl TransparentProxyFlowMeta {
    /// # Safety
    ///
    /// All pointer + length fields in `self` must be valid for reads during
    /// this call.
    pub unsafe fn as_owned_rust_type(&self) -> tproxy::TransparentProxyFlowMeta {
        let source_app_audit_token = unsafe {
            opt_audit_token(
                self.source_app_audit_token_bytes,
                self.source_app_audit_token_bytes_len,
            )
        };
        let source_app_pid = if self.source_app_pid_is_set {
            Some(self.source_app_pid)
        } else {
            source_app_audit_token.as_ref().map(AuditToken::pid)
        };

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
            .maybe_with_source_app_audit_token(source_app_audit_token)
            .maybe_with_source_app_pid(source_app_pid)
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
}

#[repr(C)]
pub struct TransparentProxyConfig {
    pub tunnel_remote_address_utf8: *const c_char,
    pub tunnel_remote_address_utf8_len: usize,
    pub rules: *const TransparentProxyNetworkRule,
    pub rules_len: usize,
}

#[repr(C)]
pub struct TransparentProxyInitConfig {
    pub storage_dir_utf8: *const c_char,
    pub storage_dir_utf8_len: usize,
    pub app_group_dir_utf8: *const c_char,
    pub app_group_dir_utf8_len: usize,
}

impl TransparentProxyInitConfig {
    /// # Safety
    ///
    /// Pointer + length pairs in `self` must be valid for reads during this call.
    pub unsafe fn storage_dir(&self) -> Option<PathBuf> {
        // SAFETY: pointer + length validity is guaranteed by caller contract.
        unsafe { opt_utf8(self.storage_dir_utf8, self.storage_dir_utf8_len) }.map(PathBuf::from)
    }

    /// # Safety
    ///
    /// Pointer + length pairs in `self` must be valid for reads during this call.
    pub unsafe fn app_group_dir(&self) -> Option<PathBuf> {
        // SAFETY: pointer + length validity is guaranteed by caller contract.
        unsafe { opt_utf8(self.app_group_dir_utf8, self.app_group_dir_utf8_len) }.map(PathBuf::from)
    }
}

impl TransparentProxyConfig {
    /// Build an owned FFI representation from typed Rust config.
    #[must_use]
    pub fn from_rust_type(config: &tproxy::TransparentProxyConfig) -> Self {
        let (tunnel_remote_address_utf8, tunnel_remote_address_utf8_len) =
            alloc_str_utf8(config.tunnel_remote_address());

        let mut rules = Vec::with_capacity(config.rules().len());
        for rule in config.rules() {
            let (remote_network_utf8, remote_network_utf8_len) =
                opt_string_as_utf8_array(rule.remote_network().map(ToString::to_string));
            let (local_network_utf8, local_network_utf8_len) =
                opt_string_as_utf8_array(rule.local_network().map(ToString::to_string));

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

fn opt_string_as_utf8_array(value: Option<String>) -> (*const c_char, usize) {
    if let Some(s) = value {
        alloc_vec_utf8(s.into_bytes())
    } else {
        (ptr::null(), 0)
    }
}

#[inline(always)]
fn alloc_str_utf8(value: &str) -> (*const c_char, usize) {
    alloc_vec_utf8(value.as_bytes().to_vec())
}

fn alloc_vec_utf8(value: Vec<u8>) -> (*const c_char, usize) {
    let boxed: Box<[u8]> = value.into_boxed_slice();
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

/// # Safety
///
/// `ptr` must be null or readable for `len` bytes.
unsafe fn opt_audit_token(ptr: *const u8, len: usize) -> Option<AuditToken> {
    if ptr.is_null() || len == 0 {
        return None;
    }

    // SAFETY: pointer + length validity is guaranteed by caller contract.
    let raw = unsafe { std::slice::from_raw_parts(ptr, len) };
    AuditToken::from_bytes(raw)
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use crate::tproxy::TransparentProxyFlowProtocol;

    use super::{TransparentFlowEndpoint, TransparentProxyFlowMeta};

    #[test]
    fn flow_meta_uses_explicit_pid_when_present() {
        let meta = TransparentProxyFlowMeta {
            protocol: TransparentProxyFlowProtocol::Tcp.as_u32(),
            remote_endpoint: TransparentFlowEndpoint {
                host_utf8: ptr::null(),
                host_utf8_len: 0,
                port: 0,
            },
            local_endpoint: TransparentFlowEndpoint {
                host_utf8: ptr::null(),
                host_utf8_len: 0,
                port: 0,
            },
            source_app_signing_identifier_utf8: ptr::null(),
            source_app_signing_identifier_utf8_len: 0,
            source_app_bundle_identifier_utf8: ptr::null(),
            source_app_bundle_identifier_utf8_len: 0,
            source_app_audit_token_bytes: ptr::null(),
            source_app_audit_token_bytes_len: 0,
            source_app_pid: 4242,
            source_app_pid_is_set: true,
        };

        let owned = unsafe { meta.as_owned_rust_type() };
        assert_eq!(owned.source_app_pid, Some(4242));
        assert!(owned.source_app_audit_token.is_none());
    }
}
