use std::ffi::{c_int, c_uint, c_void};
use std::io;
use std::mem;
use std::ptr;

use core_foundation::base::{CFType, CFTypeRef, TCFType, kCFAllocatorDefault};
use core_foundation::boolean::CFBoolean;
use core_foundation::string::{CFString, CFStringRef};

use crate::{JsError, JsErrorKind};

const CS_OPS_STATUS: c_uint = 0;
const CS_RUNTIME: u32 = 0x0001_0000;
const EXECUTABLE_MEMORY_ENTITLEMENT: &str =
    "com.apple.security.cs.allow-unsigned-executable-memory";

type SecTaskRef = *const c_void;

unsafe extern "C" {
    fn csops(pid: c_int, ops: c_uint, user_address: *mut c_void, user_size: usize) -> c_int;
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecTaskCreateFromSelf(allocator: core_foundation::base::CFAllocatorRef) -> SecTaskRef;
    fn SecTaskCopyValueForEntitlement(
        task: SecTaskRef,
        entitlement: CFStringRef,
        error: *mut core_foundation::error::CFErrorRef,
    ) -> CFTypeRef;
}

pub(super) fn require_executable_memory_entitlement() -> Result<(), JsError> {
    if !hardened_runtime_enabled()? || has_executable_memory_entitlement()? {
        return Ok(());
    }

    Err(JsError::new(
        JsErrorKind::Setup,
        format!(
            "the macOS hardened runtime requires the {EXECUTABLE_MEMORY_ENTITLEMENT} \
             code-signing entitlement for Rama's Wasmtime backend"
        ),
    ))
}

fn hardened_runtime_enabled() -> Result<bool, JsError> {
    let mut status = 0_u32;
    let pid = c_int::try_from(std::process::id()).map_err(|err| {
        JsError::new(
            JsErrorKind::Setup,
            format!("the current process ID is invalid on macOS: {err}"),
        )
    })?;
    // SAFETY: `status` is a writable `u32` matching CS_OPS_STATUS's output,
    // and its exact size is supplied to the kernel.
    let result = unsafe {
        csops(
            pid,
            CS_OPS_STATUS,
            ptr::from_mut(&mut status).cast(),
            mem::size_of_val(&status),
        )
    };
    if result != 0 {
        return Err(JsError::new(
            JsErrorKind::Setup,
            format!(
                "failed to inspect the macOS code-signing status: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    Ok(status & CS_RUNTIME != 0)
}

fn has_executable_memory_entitlement() -> Result<bool, JsError> {
    // SAFETY: the default allocator is valid for SecTaskCreateFromSelf.
    let task = unsafe { SecTaskCreateFromSelf(kCFAllocatorDefault) };
    if task.is_null() {
        return Err(JsError::new(
            JsErrorKind::Setup,
            "failed to inspect the current macOS code-signing entitlements",
        ));
    }

    let entitlement = CFString::new(EXECUTABLE_MEMORY_ENTITLEMENT);
    // SAFETY: `task` and `entitlement` are live Core Foundation objects. The
    // null error pointer opts out of a detailed CFError.
    let value = unsafe {
        SecTaskCopyValueForEntitlement(task, entitlement.as_concrete_TypeRef(), ptr::null_mut())
    };
    // SAFETY: SecTaskCreateFromSelf returned this owned Core Foundation object.
    unsafe { core_foundation::base::CFRelease(task.cast()) };

    if value.is_null() {
        return Ok(false);
    }
    // SAFETY: SecTaskCopyValueForEntitlement follows the Create Rule.
    let value = unsafe { CFType::wrap_under_create_rule(value) };
    Ok(value.downcast::<CFBoolean>().is_some_and(bool::from))
}
