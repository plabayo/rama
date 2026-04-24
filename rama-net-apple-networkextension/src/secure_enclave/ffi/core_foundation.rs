use std::{ffi::CString, ptr};

use libc::c_char;
use rama_utils::str::arcstr::ArcStr;

use crate::security_ffi as ffi;

use super::super::SecureEnclaveKeyError;

pub(crate) fn cf_release(value: *const std::ffi::c_void) {
    if !value.is_null() {
        unsafe { ffi::CFRelease(value) };
    }
}

pub(crate) fn cf_error(error: ffi::CFErrorRef) -> SecureEnclaveKeyError {
    let description = unsafe { ffi::CFErrorCopyDescription(error) };
    let message: ArcStr = if description.is_null() {
        ArcStr::from("Security framework operation failed")
    } else {
        let description = unsafe { CfOwned::from_create_rule(description) };
        match cf_string_to_string(description.as_ptr()) {
            Ok(value) => ArcStr::from(value),
            Err(_) => ArcStr::from("Security framework operation failed"),
        }
    };
    let code = Some(unsafe { ffi::CFErrorGetCode(error) as i64 });
    cf_release(error.cast());
    SecureEnclaveKeyError::new(code, message)
}

fn cf_string_to_string(value: ffi::CFStringRef) -> Result<String, SecureEnclaveKeyError> {
    let max_len = unsafe {
        ffi::CFStringGetMaximumSizeForEncoding(
            ffi::CFStringGetLength(value),
            ffi::kCFStringEncodingUTF8,
        )
    };
    if max_len < 0 {
        return Err(SecureEnclaveKeyError::new(
            None,
            "CFStringGetMaximumSizeForEncoding returned a negative length",
        ));
    }
    let mut buffer = vec![0_u8; max_len as usize + 1];
    let ok = unsafe {
        ffi::CFStringGetCString(
            value,
            buffer.as_mut_ptr().cast::<c_char>(),
            buffer.len() as i64,
            ffi::kCFStringEncodingUTF8,
        )
    };
    if ok == 0 {
        return Err(SecureEnclaveKeyError::new(
            None,
            "CFStringGetCString failed",
        ));
    }
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    String::from_utf8(buffer[..end].to_vec()).map_err(|_| {
        SecureEnclaveKeyError::new(None, "Security framework string was not valid UTF-8")
    })
}

pub(crate) struct QueryDictionary {
    raw: ffi::CFMutableDictionaryRef,
    owned: Vec<Box<dyn CfOwnedValue>>,
}

impl QueryDictionary {
    pub(crate) fn new() -> Self {
        let raw = unsafe {
            ffi::CFDictionaryCreateMutable(
                ffi::kCFAllocatorDefault,
                0,
                &ffi::kCFTypeDictionaryKeyCallBacks,
                &ffi::kCFTypeDictionaryValueCallBacks,
            )
        };
        Self {
            raw,
            owned: Vec::new(),
        }
    }

    pub(crate) fn set_ptr(&mut self, key: *const std::ffi::c_void, value: *const std::ffi::c_void) {
        unsafe { ffi::CFDictionarySetValue(self.raw, key, value) };
    }

    pub(crate) fn set_owned<T>(&mut self, key: *const std::ffi::c_void, value: T)
    where
        T: CfOwnedValue + 'static,
    {
        let value_ptr = value.as_void_ptr();
        unsafe { ffi::CFDictionarySetValue(self.raw, key, value_ptr) };
        self.owned.push(Box::new(value));
    }

    pub(crate) fn as_ptr(&self) -> ffi::CFDictionaryRef {
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

impl CfOwned<ffi::__CFData> {
    pub(crate) fn to_vec(&self) -> Vec<u8> {
        let len = unsafe { ffi::CFDataGetLength(self.raw) as usize };
        let ptr = unsafe { ffi::CFDataGetBytePtr(self.raw) };
        if ptr.is_null() || len == 0 {
            return Vec::new();
        }
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
    raw: ffi::CFStringRef,
}

impl CfString {
    pub(crate) fn new(value: &str) -> Result<Self, SecureEnclaveKeyError> {
        let value = CString::new(value).map_err(|_| {
            SecureEnclaveKeyError::new(None, "string input contained an interior NUL byte")
        })?;
        let raw = unsafe {
            ffi::CFStringCreateWithCString(
                ffi::kCFAllocatorDefault,
                value.as_ptr(),
                ffi::kCFStringEncodingUTF8,
            )
        };
        if raw.is_null() {
            return Err(SecureEnclaveKeyError::new(
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
    raw: ffi::CFDataRef,
}

impl CfData {
    pub(crate) fn new(value: &[u8]) -> Self {
        let raw = unsafe {
            ffi::CFDataCreate(ffi::kCFAllocatorDefault, value.as_ptr(), value.len() as i64)
        };
        Self { raw }
    }

    pub(crate) fn as_ptr(&self) -> ffi::CFDataRef {
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
    raw: ffi::CFNumberRef,
}

impl CfNumber {
    pub(crate) fn sint32(value: i32) -> Self {
        let raw = unsafe {
            ffi::CFNumberCreate(
                ffi::kCFAllocatorDefault,
                ffi::kCFNumberSInt32Type as i64,
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
