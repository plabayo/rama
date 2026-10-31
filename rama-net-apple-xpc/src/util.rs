use std::{
    ffi::{CString, c_void},
    panic::{AssertUnwindSafe, catch_unwind},
    process, ptr,
};

use rama_utils::str::arcstr::ArcStr;

use crate::{
    error::XpcError,
    ffi::{dispatch_queue_create, dispatch_queue_t},
};

// Declared locally rather than expanding the bindgen surface. `dispatch_release` is a
// real libdispatch symbol; it is only macro'd away for Objective-C with
// `OS_OBJECT_USE_OBJC=1`, which does not apply to Rust callers.
unsafe extern "C" {
    /// `void dispatch_release(dispatch_object_t object)` from `<dispatch/object.h>`.
    fn dispatch_release(object: *mut c_void);
}

pub(crate) fn make_c_string(value: impl AsRef<str>) -> Result<CString, XpcError> {
    let value = value.as_ref();
    CString::new(value).map_err(|_e| XpcError::InvalidCString(ArcStr::from(value)))
}

/// Run `f`, aborting the process if it panics.
///
/// Every Rust closure handed to libxpc as a block runs under this guard: block2 invokes
/// blocks through `extern "C-unwind"`, and libxpc/libdispatch do not document support
/// for unwinding through their frames.
///
/// # Safety-usable invariant
///
/// No panic escapes this function: it either returns `f`'s value or never returns.
pub(crate) fn abort_on_unwind<R>(f: impl FnOnce() -> R) -> R {
    // The payload is not dropped: its `Drop` could panic again.
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_payload| process::abort())
}

#[derive(Debug)]
pub(crate) struct DispatchQueue {
    // Safety invariant: `raw` is null, or a dispatch queue on which this value owns
    // exactly one reference, released once by `Drop`.
    raw: dispatch_queue_t,
}

impl DispatchQueue {
    pub(crate) fn new(label: Option<&str>) -> Result<Self, XpcError> {
        let Some(label) = label else {
            return Ok(Self {
                raw: ptr::null_mut(),
            });
        };
        let label = make_c_string(label)?;
        // SAFETY: `label` is a NUL-terminated string live for the call, and
        // dispatch_queue_create(3) copies it. A null `attr` is `DISPATCH_QUEUE_SERIAL`.
        // The result is `DISPATCH_RETURNS_RETAINED`: `Self` takes that one reference.
        let raw = unsafe { dispatch_queue_create(label.as_ptr(), ptr::null_mut()) };
        if raw.is_null() {
            return Err(XpcError::QueueCreationFailed);
        }
        Ok(Self { raw })
    }

    /// Queue to pass as a `targetq` argument: null (libdispatch default target queue)
    /// or a queue that stays live while `self` is.
    pub(crate) fn as_raw(&self) -> dispatch_queue_t {
        self.raw
    }
}

impl Drop for DispatchQueue {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: `dispatch_release` requires a non-null dispatch object on which the
            // caller owns a reference; the field invariant gives exactly that, and `raw`
            // is not used again. Connections that target this queue hold their own
            // reference (libdispatch retains target queues, `dispatch_set_target_queue`).
            unsafe { dispatch_release(self.raw.cast::<c_void>()) };
        }
    }
}
