use std::{ffi::c_int, ptr};

use windows_sys::Win32::Networking::WinSock;

use super::{CMsgHdr, MAX_PAYLOAD, MsgHdr};

#[derive(Copy, Clone)]
#[repr(align(8))] // Conservative bound for align_of<WinSock::CMSGHDR>
pub(crate) struct Aligned<T>(pub(crate) T);

const _: () = assert!(align_of::<WinSock::CMSGHDR>() <= align_of::<Aligned<[u8; 0]>>());

/// Helpers for [`WinSock::WSAMSG`]
// https://learn.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-wsamsg
// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Networking/WinSock/struct.WSAMSG.html
// SAFETY: `cmsg_first_hdr` returns `Control.buf` itself or null, `control_len` returns
// `Control.len`, and `cmsg_nxt_hdr` returns null or `cmsg.wrapping_byte_add(offset)` for a
// `usize` offset, which keeps the provenance of `cmsg`.
unsafe impl MsgHdr for WinSock::WSAMSG {
    type ControlMessage = WinSock::CMSGHDR;

    fn cmsg_first_hdr(&self) -> *mut Self::ControlMessage {
        if self.Control.len as usize >= size_of::<WinSock::CMSGHDR>() {
            self.Control.buf as *mut WinSock::CMSGHDR
        } else {
            ptr::null_mut::<WinSock::CMSGHDR>()
        }
    }

    unsafe fn cmsg_nxt_hdr(&self, cmsg: *const Self::ControlMessage) -> *mut Self::ControlMessage {
        // SAFETY: the place read `(*cmsg).cmsg_len` needs `cmsg` aligned and pointing to an
        // initialized header that is not written during the read; this function's contract
        // requires all three for the duration of the call.
        let len = unsafe { (*cmsg).cmsg_len };
        let Some(offset) = cmsghdr_align(len) else {
            return ptr::null_mut();
        };
        let Some(next_end) = cmsg
            .addr()
            .checked_add(offset)
            .and_then(|next| next.checked_add(size_of::<WinSock::CMSGHDR>()))
        else {
            return ptr::null_mut();
        };
        let max = self
            .Control
            .buf
            .addr()
            .saturating_add(self.Control.len as usize);
        if next_end > max {
            ptr::null_mut()
        } else {
            // Pointer arithmetic keeps the control buffer's provenance, where an integer
            // round-trip would leave the result with exposed provenance only.
            cmsg.wrapping_byte_add(offset).cast_mut()
        }
    }

    fn set_control_len(&mut self, len: usize) {
        self.Control.len = len as _;
        // Some Winsock implementations reject a non-null control pointer when
        // its length is zero, even though no control data will be read.
        if len == 0 {
            self.Control.buf = ptr::null_mut();
        }
    }

    fn control_len(&self) -> usize {
        self.Control.len as _
    }
}

/// Helpers for [`WinSock::CMSGHDR`]
// https://learn.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-wsacmsghdr
// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Networking/WinSock/struct.CMSGHDR.html
// SAFETY: `CMSGHDR`'s fields are integers (`usize`, `i32`, `i32`), so every initialized bit
// pattern is a valid value. For `n <= MAX_PAYLOAD`, `cmsg_len(n)` is the data-aligned header size (at least
// `size_of::<CMSGHDR>()`) plus `n`, and `cmsg_space(n)` is the data-aligned sum of the header
// size and `n` rounded up to the header alignment, which is at least `cmsg_len(n)` and far
// below `usize::MAX`; larger `n` return `usize::MAX`.
unsafe impl CMsgHdr for WinSock::CMSGHDR {
    fn cmsg_len(length: usize) -> usize {
        if length > MAX_PAYLOAD {
            return usize::MAX;
        }
        cmsgdata_align(size_of::<Self>()) + length
    }

    fn cmsg_space(length: usize) -> usize {
        if length > MAX_PAYLOAD {
            return usize::MAX;
        }
        cmsgdata_align(size_of::<Self>() + align_up(length, align_of::<Self>()))
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

// Helpers functions for `WinSock::WSAMSG` and `WinSock::CMSGHDR` are based on C macros from
// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/shared/ws2def.h#L741

/// `WSA_CMSGHDR_ALIGN`, or `None` when the rounded length overflows.
fn cmsghdr_align(length: usize) -> Option<usize> {
    length.checked_next_multiple_of(align_of::<WinSock::CMSGHDR>())
}

/// `WSA_CMSGDATA_ALIGN`, for the small sizes the length helpers pass.
fn cmsgdata_align(length: usize) -> usize {
    align_up(length, align_of::<usize>())
}

fn align_up(length: usize, align: usize) -> usize {
    (length + align - 1) & !(align - 1)
}
