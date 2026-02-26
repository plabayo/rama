use std::ffi::{CStr, c_char};

use rama_net::address::Host;
use rama_utils::str::NonEmptyStr;

pub(super) unsafe fn opt_cstr_to_non_empty_str(ptr: *const c_char) -> Option<NonEmptyStr> {
    if ptr.is_null() {
        return None;
    }
    assert!(ptr.is_aligned());

    // SAFETY: pointer validity is part of FFI contract.
    let c_str = unsafe { CStr::from_ptr(ptr) };

    c_str.to_string_lossy().trim().try_into().ok()
}

pub(super) unsafe fn opt_cstr_to_host(ptr: *const c_char) -> Option<Host> {
    if ptr.is_null() {
        return None;
    }
    assert!(ptr.is_aligned());

    // SAFETY: pointer validity is part of FFI contract.
    let c_str = unsafe { CStr::from_ptr(ptr) };

    Host::try_from(c_str.to_string_lossy().trim()).ok()
}
