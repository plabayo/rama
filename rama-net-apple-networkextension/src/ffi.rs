#[repr(C)]
pub struct RamaBytesView {
    pub ptr: *const u8,
    pub len: i32,
}

#[repr(C)]
pub struct RamaBytesOwned {
    pub ptr: *mut u8,
    pub len: i32,
}

pub fn bytes_owned_from_vec(mut bytes: Vec<u8>) -> RamaBytesOwned {
    if bytes.is_empty() {
        return RamaBytesOwned {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
    }
    let len = bytes.len() as i32;
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    RamaBytesOwned { ptr, len }
}

pub unsafe fn bytes_view_as_slice<'a>(view: RamaBytesView) -> &'a [u8] {
    if view.ptr.is_null() || view.len <= 0 {
        return &[];
    }
    unsafe { std::slice::from_raw_parts(view.ptr, view.len as usize) }
}

pub extern "C" fn bytes_free(ptr: *mut u8, len: i32) {
    if ptr.is_null() || len <= 0 {
        return;
    }
    unsafe {
        let _ = Box::from_raw(std::slice::from_raw_parts_mut(ptr, len as usize));
    }
}
