use rama_core::error::{BoxError, ErrorContext as _};
use std::ffi::c_int;

#[repr(C)]
#[derive(Debug)]
pub struct RamaBytesOwned {
    pub ptr: *mut u8,
    pub len: c_int,
    pub cap: c_int,
}

impl RamaBytesOwned {
    pub unsafe fn free(self) {
        let Self { ptr, len, cap } = self;
        if ptr.is_null() || cap <= 0 {
            return;
        }

        let vec_len = len.min(cap) as usize;
        let vec_cap = cap as usize;
        let _ = unsafe { Vec::from_raw_parts(ptr, vec_len, vec_cap) };
    }
}

impl TryFrom<Vec<u8>> for RamaBytesOwned {
    type Error = BoxError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.is_empty() {
            return Ok(Self {
                ptr: std::ptr::null_mut(),
                len: 0,
                cap: 0,
            });
        }

        let (ptr, vec_len, vec_cap) = bytes.into_raw_parts();
        Ok(Self {
            ptr,
            len: c_int::try_from(vec_len).context("convert vec len to c_int")?,
            cap: c_int::try_from(vec_cap).context("convert vec len to c_int")?,
        })
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct RamaBytesView {
    pub ptr: *const u8,
    pub len: c_int,
}

impl RamaBytesView {
    pub unsafe fn into_slice<'a>(self) -> &'a [u8] {
        if self.ptr.is_null() || self.len <= 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.ptr, self.len as usize) }
    }
}
