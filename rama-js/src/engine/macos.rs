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
    /// XNU `<sys/codesign.h>`: for `CS_OPS_STATUS`, copies the `u32`
    /// code-signing flags to `user_address`, writing at most `user_size` bytes.
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
             code-signing entitlement for Rama's native Wasmtime backend; \
             enable rama-js/interpreter (or rama/js-interpreter) to use the \
             interpreter and select JsBackend::Interpreter without this entitlement"
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
    // SAFETY: `csops` writes at most `user_size` bytes to `user_address`:
    // `&mut status` is an exclusive, aligned `u32` and `user_size` is its size.
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
    // SAFETY: reading an extern static that CFBase.h declares `const`, so no
    // write can race this read.
    let allocator = unsafe { kCFAllocatorDefault };
    // SAFETY: SecTask.h `SecTaskCreateFromSelf` takes a nullable allocator and
    // returns null or a SecTask the caller must release (Create rule).
    let task = unsafe { SecTaskCreateFromSelf(allocator) };
    if task.is_null() {
        return Err(JsError::new(
            JsErrorKind::Setup,
            "failed to inspect the current macOS code-signing entitlements",
        ));
    }

    let entitlement = CFString::new(EXECUTABLE_MEMORY_ENTITLEMENT);
    // SAFETY: SecTask.h `SecTaskCopyValueForEntitlement`: `task` is the
    // non-null SecTask still owned here, `entitlement` a live CFString, and
    // `error` is nullable. The result is null or +1 (Copy rule).
    let value = unsafe {
        SecTaskCopyValueForEntitlement(task, entitlement.as_concrete_TypeRef(), ptr::null_mut())
    };
    // SAFETY: `CFRelease` needs a non-null CF object with a reference to
    // give up: `task` is the +1 SecTask from above, released once, unused after.
    unsafe { core_foundation::base::CFRelease(task.cast()) };

    if value.is_null() {
        return Ok(false);
    }
    // SAFETY: `wrap_under_create_rule` takes over one owned reference to a
    // valid CF object: `value` is non-null (checked) and +1 (Copy rule).
    let value = unsafe { CFType::wrap_under_create_rule(value) };
    Ok(value.downcast::<CFBoolean>().is_some_and(bool::from))
}
