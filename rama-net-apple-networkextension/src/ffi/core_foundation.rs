//! Private CoreFoundation helpers used by Apple-specific raw bindings.
//!
//! This module intentionally stays crate-private. It wraps a small subset of
//! CoreFoundation ownership and collection APIs so higher-level modules like
//! `secure_enclave` can focus on Apple Security semantics instead of manual
//! retain/release and dictionary assembly.

use std::{ffi::CString, ptr};

use libc::c_char;

use crate::ffi::sys;

/// Low-level error from a CoreFoundation or Apple Security API call.
///
/// Higher-level modules convert this into their own error types via `From`.
#[derive(Debug, Clone)]
pub(crate) struct CfError {
    pub(crate) code: Option<i64>,
    pub(crate) message: String,
}

impl CfError {
    pub(crate) fn new(code: Option<i64>, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub(crate) fn cf_release(value: *const std::ffi::c_void) {
    if !value.is_null() {
        // SAFETY: `value` is a CoreFoundation object pointer obtained from APIs
        // following the create/copy rule or retained elsewhere in this crate.
        unsafe { sys::CFRelease(value) };
    }
}

pub(crate) fn cf_error(error: sys::CFErrorRef) -> CfError {
    // SAFETY: `error` is a valid CFErrorRef returned by a Security API.
    let description = unsafe { sys::CFErrorCopyDescription(error) };
    let message: String = if description.is_null() {
        "Security framework operation failed".to_owned()
    } else {
        // SAFETY: `CFErrorCopyDescription` follows the create rule.
        let description = unsafe { CfOwned::from_create_rule(description) };
        match cf_string_to_string(description.as_ptr()) {
            Ok(value) => value,
            Err(_) => "Security framework operation failed".to_owned(),
        }
    };
    // SAFETY: `error` is valid for the duration of this function.
    let code = Some(unsafe { sys::CFErrorGetCode(error) as i64 });
    cf_release(error.cast());
    CfError::new(code, message)
}

fn cf_string_to_string(value: sys::CFStringRef) -> Result<String, CfError> {
    // SAFETY: `value` is expected to be a valid CFStringRef.
    let max_len = unsafe {
        sys::CFStringGetMaximumSizeForEncoding(
            sys::CFStringGetLength(value),
            sys::kCFStringEncodingUTF8,
        )
    };
    if max_len < 0 {
        return Err(CfError::new(
            None,
            "CFStringGetMaximumSizeForEncoding returned a negative length",
        ));
    }
    let mut buffer = vec![0_u8; max_len as usize + 1];
    // SAFETY: `buffer` is writable and sized according to the CFString API
    // contract, and `value` remains valid during the call.
    let ok = unsafe {
        sys::CFStringGetCString(
            value,
            buffer.as_mut_ptr().cast::<c_char>(),
            buffer.len() as i64,
            sys::kCFStringEncodingUTF8,
        )
    };
    if ok == 0 {
        return Err(CfError::new(None, "CFStringGetCString failed"));
    }
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    String::from_utf8(buffer[..end].to_vec())
        .map_err(|_| CfError::new(None, "Security framework string was not valid UTF-8"))
}

pub(crate) struct QueryDictionary {
    raw: sys::CFMutableDictionaryRef,
    owned: Vec<Box<dyn CfOwnedValue>>,
}

impl QueryDictionary {
    pub(crate) fn new() -> Self {
        // SAFETY: the callback tables are immutable globals from CoreFoundation.
        let raw = unsafe {
            sys::CFDictionaryCreateMutable(
                sys::kCFAllocatorDefault,
                0,
                &sys::kCFTypeDictionaryKeyCallBacks,
                &sys::kCFTypeDictionaryValueCallBacks,
            )
        };
        Self {
            raw,
            owned: Vec::new(),
        }
    }

    pub(crate) fn set_ptr(&mut self, key: *const std::ffi::c_void, value: *const std::ffi::c_void) {
        // SAFETY: `self.raw` is a valid mutable dictionary and key/value point to
        // live CF objects or constant CF singleton values.
        unsafe { sys::CFDictionarySetValue(self.raw, key, value) };
    }

    pub(crate) fn set_owned<T>(&mut self, key: *const std::ffi::c_void, value: T)
    where
        T: CfOwnedValue + 'static,
    {
        let value_ptr = value.as_void_ptr();
        // SAFETY: same guarantees as `set_ptr`; ownership is retained on the Rust
        // side by pushing `value` into `self.owned`.
        unsafe { sys::CFDictionarySetValue(self.raw, key, value_ptr) };
        self.owned.push(Box::new(value));
    }

    pub(crate) fn as_ptr(&self) -> sys::CFDictionaryRef {
        self.raw
    }
}

impl Drop for QueryDictionary {
    fn drop(&mut self) {
        cf_release(self.raw.cast());
    }
}

pub(crate) trait CfOwnedValue {
    fn as_void_ptr(&self) -> *const std::ffi::c_void;
}

pub(crate) struct CfOwned<T> {
    raw: *mut T,
}

impl<T> CfOwned<T> {
    pub(crate) unsafe fn from_create_rule(raw: *const T) -> Self {
        Self {
            raw: raw.cast_mut(),
        }
    }

    pub(crate) fn as_ptr(&self) -> *mut T {
        self.raw
    }
}

impl CfOwned<sys::__CFData> {
    pub(crate) fn to_vec(&self) -> Vec<u8> {
        // SAFETY: `self.raw` is a valid CFDataRef owned by this wrapper.
        let len = unsafe { sys::CFDataGetLength(self.raw) as usize };
        // SAFETY: `self.raw` is a valid CFDataRef owned by this wrapper.
        let ptr = unsafe { sys::CFDataGetBytePtr(self.raw) };
        if ptr.is_null() || len == 0 {
            return Vec::new();
        }
        // SAFETY: CoreFoundation guarantees the data pointer is valid for `len`
        // bytes while the CFData object is alive.
        unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
    }
}

impl<T> Drop for CfOwned<T> {
    fn drop(&mut self) {
        cf_release(self.raw.cast());
    }
}

impl<T> CfOwnedValue for CfOwned<T> {
    fn as_void_ptr(&self) -> *const std::ffi::c_void {
        self.raw.cast()
    }
}

pub(crate) struct CfString {
    raw: sys::CFStringRef,
}

impl CfString {
    pub(crate) fn new(value: &str) -> Result<Self, CfError> {
        let value = CString::new(value)
            .map_err(|_| CfError::new(None, "string input contained an interior NUL byte"))?;
        // SAFETY: `value` is a valid NUL-terminated UTF-8 string for the duration
        // of this call.
        let raw = unsafe {
            sys::CFStringCreateWithCString(
                sys::kCFAllocatorDefault,
                value.as_ptr(),
                sys::kCFStringEncodingUTF8,
            )
        };
        if raw.is_null() {
            return Err(CfError::new(
                None,
                "CFStringCreateWithCString returned null",
            ));
        }
        Ok(Self { raw })
    }
}

impl Drop for CfString {
    fn drop(&mut self) {
        cf_release(self.raw.cast());
    }
}

impl CfOwnedValue for CfString {
    fn as_void_ptr(&self) -> *const std::ffi::c_void {
        self.raw.cast()
    }
}

pub(crate) struct CfData {
    raw: sys::CFDataRef,
}

impl CfData {
    pub(crate) fn new(value: &[u8]) -> Self {
        // SAFETY: `value.as_ptr()` is valid for `value.len()` bytes for the duration
        // of the call.
        let raw = unsafe {
            sys::CFDataCreate(sys::kCFAllocatorDefault, value.as_ptr(), value.len() as i64)
        };
        Self { raw }
    }

    pub(crate) fn as_ptr(&self) -> sys::CFDataRef {
        self.raw
    }
}

impl Drop for CfData {
    fn drop(&mut self) {
        cf_release(self.raw.cast());
    }
}

impl CfOwnedValue for CfData {
    fn as_void_ptr(&self) -> *const std::ffi::c_void {
        self.raw.cast()
    }
}

pub(crate) struct CfNumber {
    raw: sys::CFNumberRef,
}

impl CfNumber {
    pub(crate) fn sint32(value: i32) -> Self {
        // SAFETY: the pointer to `value` remains valid for the duration of the call.
        let raw = unsafe {
            sys::CFNumberCreate(
                sys::kCFAllocatorDefault,
                sys::kCFNumberSInt32Type as i64,
                ptr::from_ref(&value).cast(),
            )
        };
        Self { raw }
    }
}

impl Drop for CfNumber {
    fn drop(&mut self) {
        cf_release(self.raw.cast());
    }
}

impl CfOwnedValue for CfNumber {
    fn as_void_ptr(&self) -> *const std::ffi::c_void {
        self.raw.cast()
    }
}
