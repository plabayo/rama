use std::ffi::{c_int, c_uchar};

use super::{CMsgHdr, MsgHdr};

#[derive(Copy, Clone)]
#[repr(align(8))] // Conservative bound for align_of<libc::cmsghdr>
pub(crate) struct Aligned<T>(pub(crate) T);

/// Helpers for [`libc::msghdr`]
impl MsgHdr for libc::msghdr {
    type ControlMessage = libc::cmsghdr;

    fn cmsg_first_hdr(&self) -> *mut Self::ControlMessage {
        // SAFETY: callers of the private `MsgHdr` abstraction establish that
        // `self` contains a valid control buffer before walking it.
        unsafe { libc::CMSG_FIRSTHDR(self) }
    }

    unsafe fn cmsg_nxt_hdr(&self, cmsg: *const Self::ControlMessage) -> *mut Self::ControlMessage {
        // `CMSG_NXTHDR` in pointer arithmetic: several platforms' own macros round-trip the
        // address through an integer, which loses the control buffer's provenance.
        // SAFETY: the caller supplies a complete header in this control buffer.
        let len = unsafe { &*cmsg }.len();
        let Some(offset) = cmsg_align(len) else {
            return std::ptr::null_mut();
        };
        let header = cmsg_align(size_of::<libc::cmsghdr>()).unwrap_or(usize::MAX);
        let end = self.msg_control.addr().saturating_add(self.control_len());
        let next_end = cmsg
            .addr()
            .checked_add(offset)
            .and_then(|next| next.checked_add(header));
        if next_end.is_none_or(|next_end| next_end > end) {
            std::ptr::null_mut()
        } else {
            cmsg.wrapping_byte_add(offset).cast_mut()
        }
    }

    fn set_control_len(&mut self, len: usize) {
        self.msg_controllen = len as _;
        if len == 0 {
            // netbsd is particular about this being a NULL pointer if there are no control
            // messages.
            self.msg_control = std::ptr::null_mut();
        }
    }

    fn control_len(&self) -> usize {
        self.msg_controllen as _
    }
}

/// `len` rounded up to the platform's control-message alignment, which is what one byte of
/// payload adds to an entry's space.
fn cmsg_align(len: usize) -> Option<usize> {
    let unit = libc::cmsghdr::cmsg_space(1) - libc::cmsghdr::cmsg_space(0);
    len.checked_next_multiple_of(unit)
}

/// Helpers for [`libc::cmsghdr`]
impl CMsgHdr for libc::cmsghdr {
    fn cmsg_len(length: usize) -> usize {
        // SAFETY: this libc macro only computes a size; it dereferences no
        // caller-provided pointer.
        unsafe { libc::CMSG_LEN(length as _) as usize }
    }

    fn cmsg_space(length: usize) -> usize {
        // SAFETY: this libc macro only computes a size; it dereferences no
        // caller-provided pointer.
        unsafe { libc::CMSG_SPACE(length as _) as usize }
    }

    unsafe fn cmsg_data(this: *const Self) -> *mut c_uchar {
        // SAFETY: the caller guarantees that `this` is a header inside a
        // control buffer, so the payload offset stays inside it as well.
        unsafe { libc::CMSG_DATA(this) }
    }

    fn set(&mut self, level: c_int, ty: c_int, len: usize) {
        self.cmsg_level = level as _;
        self.cmsg_type = ty as _;
        self.cmsg_len = len as _;
    }

    fn len(&self) -> usize {
        self.cmsg_len as _
    }
}
