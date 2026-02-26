use rama_core::error::BoxError;

#[repr(C)]
#[derive(Debug)]
pub struct BytesOwned {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl BytesOwned {
    /// # Safety
    ///
    /// `self` must come from this crate's FFI allocation path and must not have
    /// been freed before.
    pub unsafe fn free(self) {
        let Self { ptr, len, cap } = self;
        if ptr.is_null() || cap == 0 {
            return;
        }

        let vec_len = len.min(cap);
        let vec_cap = cap;
        // SAFETY: caller contract guarantees pointer/capacity originate from a `Vec<u8>`.
        let _ = unsafe { Vec::from_raw_parts(ptr, vec_len, vec_cap) };
    }
}

impl TryFrom<Vec<u8>> for BytesOwned {
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
            len: vec_len,
            cap: vec_cap,
        })
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct BytesView {
    pub ptr: *const u8,
    pub len: usize,
}

impl BytesView {
    /// # Safety
    ///
    /// `self.ptr` must be valid for reads of `self.len` bytes for the returned
    /// lifetime.
    pub unsafe fn into_slice<'a>(self) -> &'a [u8] {
        if self.ptr.is_null() || self.len == 0 {
            return &[];
        }
        // SAFETY: caller contract guarantees pointer validity.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}
