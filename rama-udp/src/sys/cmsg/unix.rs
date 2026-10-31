use std::ffi::c_int;

use super::{CMsgHdr, MAX_PAYLOAD, MsgHdr, control_payload_struct};

/// A `T` at offset 0 (`repr(C)`), aligned for `libc::cmsghdr` (8 is a conservative bound,
/// checked by the assertion below).
#[derive(Copy, Clone)]
#[repr(C, align(8))]
pub(crate) struct Aligned<T>(pub(crate) T);

const _: () = assert!(align_of::<libc::cmsghdr>() <= align_of::<Aligned<[u8; 0]>>());

// SAFETY: `cmsg_first_hdr` returns `msg_control` itself or null, `control_len` returns
// `msg_controllen`, and `cmsg_nxt_hdr` returns null or `cmsg.wrapping_byte_add(offset)`
// for a `usize` offset, which keeps the provenance of `cmsg`.
unsafe impl MsgHdr for libc::msghdr {
    type ControlMessage = libc::cmsghdr;

    fn cmsg_first_hdr(&self) -> *mut Self::ControlMessage {
        // `CMSG_FIRSTHDR`, without the `unsafe` libc helper: this only reads two fields.
        if self.control_len() >= size_of::<libc::cmsghdr>() {
            self.msg_control.cast()
        } else {
            std::ptr::null_mut()
        }
    }

    unsafe fn cmsg_nxt_hdr(&self, cmsg: *const Self::ControlMessage) -> *mut Self::ControlMessage {
        // `CMSG_NXTHDR` in pointer arithmetic: several platforms' own macros round-trip the
        // address through an integer, which leaves the result with exposed rather than the
        // control buffer's own provenance.
        // SAFETY: `&*cmsg` needs `cmsg` aligned and pointing to an initialized header that is
        // not written while the reference lives; this function's contract requires all three
        // for the duration of the call.
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

// SAFETY: libc declares `cmsghdr` with integer fields only (some libcs add integer or
// `Padding` filler), so every initialized bit pattern is a valid value. libc defines
// `CMSG_LEN(n)` as the aligned `cmsghdr` size plus `n`, and `CMSG_SPACE(n)` as that size plus
// `n` rounded up to the same alignment, so the relations hold for `n <= MAX_PAYLOAD`, where
// neither `u32` sum can overflow; larger `n` return `usize::MAX`. The
// `native_lengths_stay_consistent_with_the_header_they_describe` test checks them, and that
// `CMSG_DATA` agrees with `cmsg_data`, on each tested target.
unsafe impl CMsgHdr for libc::cmsghdr {
    fn cmsg_len(length: usize) -> usize {
        if length > MAX_PAYLOAD {
            return usize::MAX;
        }
        // SAFETY: `CMSG_LEN` only computes a size; `length <= u16::MAX` converts losslessly.
        unsafe { libc::CMSG_LEN(length as _) as usize }
    }

    fn cmsg_space(length: usize) -> usize {
        if length > MAX_PAYLOAD {
            return usize::MAX;
        }
        // SAFETY: `CMSG_SPACE` only computes a size; `length <= u16::MAX` converts losslessly.
        unsafe { libc::CMSG_SPACE(length as _) as usize }
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

control_payload_struct! {
    libc::in_addr => libc::in_addr_t;
    libc::in6_addr => [u8; 16];
}

#[cfg(any(target_os = "linux", target_os = "android"))]
control_payload_struct! {
    libc::in_pktinfo => libc::c_int, libc::in_addr, libc::in_addr;
}

#[cfg(target_os = "android")]
control_payload_struct! {
    libc::in6_pktinfo => libc::in6_addr, libc::c_int;
}

#[cfg(not(any(target_os = "android", target_os = "redox", target_os = "hurd")))]
control_payload_struct! {
    libc::in6_pktinfo => libc::in6_addr, libc::c_uint;
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
control_payload_struct! {
    libc::sockaddr_in => libc::sa_family_t, libc::in_port_t, libc::in_addr, [u8; 8];
    libc::sockaddr_in6 => libc::sa_family_t, libc::in_port_t, u32, libc::in6_addr, u32;
    libc::timespec => TimeT, libc::c_long;
}

/// The type of `timespec::tv_sec`.
#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
#[cfg_attr(
    target_env = "musl",
    expect(
        deprecated,
        reason = "musl deprecates `time_t` ahead of its 64-bit change"
    )
)]
type TimeT = libc::time_t;
