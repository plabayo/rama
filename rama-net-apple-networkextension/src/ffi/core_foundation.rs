//! Private CoreFoundation helpers used by Apple-specific raw bindings.
//!
//! For now only used to support MacOS legacy keychain,
//! but already reserved for future other use cases.

use crate::ffi::sys;

/// Release one reference to a CoreFoundation object; null is ignored.
///
/// # Safety
///
/// The caller must ensure `value` is null or a live CoreFoundation object on
/// which it owns one reference (Create/Copy rule or an explicit retain),
/// that this call gives back that reference exactly once, and that the caller
/// does not use `value` afterwards unless it owns another reference.
pub(crate) unsafe fn cf_release(value: *const std::ffi::c_void) {
    if !value.is_null() {
        // SAFETY: `CFRelease` requires a non-null CF object (Apple: passing
        // NULL crashes) whose reference the caller owns. Non-null is checked;
        // ownership of exactly one reference is this fn's precondition.
        unsafe { sys::CFRelease(value) };
    }
}
