//! Private CoreFoundation helpers used by Apple-specific raw bindings.
//!
//! For now only used to support MacOS legacy keychain,
//! but already reserved for future other use cases.

use crate::ffi::sys;

pub(crate) fn cf_release(value: *const std::ffi::c_void) {
    if !value.is_null() {
        // SAFETY: `value` is a CoreFoundation object pointer obtained from APIs
        // following the create/copy rule or retained elsewhere in this crate.
        unsafe { sys::CFRelease(value) };
    }
}
