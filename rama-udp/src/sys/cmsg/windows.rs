use std::{
    ffi::{c_int, c_uchar},
    ptr,
};

use windows_sys::Win32::Networking::WinSock;

use super::{CMsgHdr, MsgHdr};

#[derive(Copy, Clone)]
#[repr(align(8))] // Conservative bound for align_of<WinSock::CMSGHDR>
pub(crate) struct Aligned<T>(pub(crate) T);

/// Helpers for [`WinSock::WSAMSG`]
// https://learn.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-wsamsg
// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Networking/WinSock/struct.WSAMSG.html
impl MsgHdr for WinSock::WSAMSG {
    type ControlMessage = WinSock::CMSGHDR;

    fn cmsg_first_hdr(&self) -> *mut Self::ControlMessage {
        if self.Control.len as usize >= size_of::<WinSock::CMSGHDR>() {
            self.Control.buf as *mut WinSock::CMSGHDR
        } else {
            ptr::null_mut::<WinSock::CMSGHDR>()
        }
    }

    fn cmsg_nxt_hdr(&self, cmsg: &Self::ControlMessage) -> *mut Self::ControlMessage {
        let Some(next) = (cmsg as *const _ as usize).checked_add(cmsghdr_align(cmsg.cmsg_len))
        else {
            return ptr::null_mut();
        };
        let Some(next_end) = next.checked_add(size_of::<WinSock::CMSGHDR>()) else {
            return ptr::null_mut();
        };
        let max = self.Control.buf as usize + self.Control.len as usize;
        if next_end > max {
            ptr::null_mut()
        } else {
            next as *mut WinSock::CMSGHDR
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
impl CMsgHdr for WinSock::CMSGHDR {
    fn cmsg_len(length: usize) -> usize {
        cmsgdata_align(size_of::<Self>()) + length
    }

    fn cmsg_space(length: usize) -> usize {
        cmsgdata_align(size_of::<Self>() + cmsghdr_align(length))
    }

    fn cmsg_data(&self) -> *mut c_uchar {
        (self as *const _ as usize + cmsgdata_align(size_of::<Self>())) as *mut c_uchar
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
fn cmsghdr_align(length: usize) -> usize {
    (length + align_of::<WinSock::CMSGHDR>() - 1) & !(align_of::<WinSock::CMSGHDR>() - 1)
}

fn cmsgdata_align(length: usize) -> usize {
    (length + align_of::<usize>() - 1) & !(align_of::<usize>() - 1)
}
