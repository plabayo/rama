use std::{
    ffi::{CString, c_void},
    ptr,
};

use rama_utils::str::arcstr::ArcStr;

use crate::{
    error::XpcError,
    ffi::{dispatch_queue_create, dispatch_queue_t},
};

// `dispatch_queue_create` returns a +1 retained dispatch_queue_t. When that queue is
// handed to `xpc_connection_create_mach_service`/`xpc_connection_create`, XPC retains
// it internally — but the +1 we received still belongs to us, so dropping the wrapper
// without releasing it leaks one queue per connection. Declare `dispatch_release`
// locally rather than expanding the bindgen surface.
//
// `dispatch_release` is a real libdispatch C symbol on every macOS version we support;
// it is only macro'd to a no-op in Objective-C compilation with `OS_OBJECT_USE_OBJC=1`,
// which does not affect Rust callers.
unsafe extern "C" {
    fn dispatch_release(object: *mut c_void);
}

pub(crate) fn make_c_string(value: impl AsRef<str>) -> Result<CString, XpcError> {
    let value = value.as_ref();
    CString::new(value).map_err(|_e| XpcError::InvalidCString(ArcStr::from(value)))
}

#[derive(Debug)]
pub(crate) struct DispatchQueue {
    pub(crate) raw: dispatch_queue_t,
}

impl DispatchQueue {
    pub(crate) fn new(label: Option<&str>) -> Result<Self, XpcError> {
        let raw = match label {
            Some(label) => {
                let label = make_c_string(label)?;
                // SAFETY: `label` is a valid NUL-terminated C string whose buffer
                // outlives this call (libdispatch copies the label internally).
                // Passing NULL for the second arg requests a serial queue with default
                // attributes. Returns a +1 retained queue (released in `Drop`) or NULL
                // on allocation failure.
                unsafe { dispatch_queue_create(label.as_ptr(), ptr::null_mut()) }
            }
            None => ptr::null_mut(),
        };
        if label.is_some() && raw.is_null() {
            return Err(XpcError::QueueCreationFailed);
        }
        Ok(Self { raw })
    }
}

impl Drop for DispatchQueue {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: `self.raw` was obtained from `dispatch_queue_create`, which
            // returns a +1 retained queue. We release exactly that retain here.
            // Consumers (e.g. xpc_connection_create_mach_service) retain the queue
            // internally before the Drop runs, so the queue object itself remains
            // alive for as long as XPC needs it.
            unsafe { dispatch_release(self.raw.cast::<c_void>()) };
        }
    }
}
