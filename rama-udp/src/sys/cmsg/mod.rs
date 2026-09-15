use std::{
    ffi::{c_int, c_uchar},
    io, ptr,
};

#[cfg(unix)]
#[path = "unix.rs"]
mod imp;

#[cfg(windows)]
#[path = "windows.rs"]
mod imp;

pub(crate) use imp::Aligned;

/// Encodes native control messages into a buffer used by calls such as `sendmsg`.
///
/// The operation must be "finished" for the native msghdr to be usable, either by calling `finish`
/// explicitly or by dropping the `Encoder`.
pub(crate) struct Encoder<'a, M: MsgHdr> {
    hdr: &'a mut M,
    cmsg: Option<&'a mut M::ControlMessage>,
    len: usize,
}

impl<'a, M: MsgHdr> Encoder<'a, M> {
    /// # Safety
    /// - `hdr` must contain a suitably aligned pointer to a big enough buffer to hold control messages
    ///   bytes. All bytes of this buffer can be safely written.
    /// - The `Encoder` must be dropped before `hdr` is passed to a system call, and must not be leaked.
    pub(crate) unsafe fn new(hdr: &'a mut M) -> Self {
        // SAFETY: the caller guarantees that the header's control buffer is
        // valid, aligned, writable and lives for `'a`.
        let cmsg = unsafe { hdr.cmsg_first_hdr().as_mut() };
        Self { cmsg, hdr, len: 0 }
    }

    /// Append a control message to the buffer.
    ///
    /// Layout or capacity failures are programming errors guarded at socket
    /// construction, but are still returned so requested metadata is never
    /// silently omitted in a release build.
    pub(crate) fn push<T: Copy>(&mut self, level: c_int, ty: c_int, value: T) -> io::Result<()> {
        let space = M::ControlMessage::cmsg_space(size_of_val(&value));
        let valid_layout = align_of::<T>() <= align_of::<M::ControlMessage>()
            && self.hdr.control_len() >= self.len + space;
        if !valid_layout {
            return Err(io::Error::other("invalid control-message buffer layout"));
        }
        let Some(cmsg) = self.cmsg.take() else {
            return Err(io::Error::other(
                "no control-message buffer space remaining",
            ));
        };
        cmsg.set(level, ty, M::ControlMessage::cmsg_len(size_of_val(&value)));
        // SAFETY: `new` established the backing buffer, and the alignment and
        // remaining capacity for `T` were checked above.
        unsafe {
            ptr::write(cmsg.cmsg_data() as *const T as *mut T, value);
        }
        self.len += space;
        // SAFETY: `cmsg` is the current entry in the valid buffer established
        // by `new`; the native helper returns either its next entry or null.
        self.cmsg = unsafe { self.hdr.cmsg_nxt_hdr(cmsg).as_mut() };
        Ok(())
    }
}

// Ensures the encoded length is set before the control buffer is passed to the
// operating system.
impl<M: MsgHdr> Drop for Encoder<'_, M> {
    fn drop(&mut self) {
        self.hdr.set_control_len(self.len as _);
    }
}

/// Decode a control-message payload after checking its native length.
///
/// # Safety
///
/// `cmsg` must come from a live native control-message buffer. When its native
/// length matches `T`, the payload must contain `size_of::<T>()` initialized,
/// readable bytes.
pub(crate) unsafe fn decode<T: Copy, C: CMsgHdr>(cmsg: &C) -> io::Result<T> {
    if cmsg.len() != C::cmsg_len(size_of::<T>()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid UDP control-message length",
        ));
    }
    // The payload is only aligned for `C`, which on musl is less strict than payloads such as
    // `libc::timespec`, so it cannot be read through an aligned `ptr::read`.
    // SAFETY: the caller supplied a valid native control message and the length
    // check above proves that its payload contains all bytes of `T`.
    Ok(unsafe { ptr::read_unaligned(cmsg.cmsg_data() as *const T) })
}

pub(crate) struct Iter<'a, M: MsgHdr> {
    hdr: &'a M,
    cmsg: Option<&'a M::ControlMessage>,
}

impl<'a, M: MsgHdr> Iter<'a, M> {
    /// # Safety
    ///
    /// `hdr` must hold a pointer to memory outliving `'a` which can be soundly read for the
    /// lifetime of the constructed `Iter` and contains a buffer of native cmsgs, i.e. is aligned
    /// for native `cmsghdr`, is fully initialized, and has correct internal links.
    pub(crate) unsafe fn new(hdr: &'a M) -> Self {
        // SAFETY: the caller guarantees a readable, aligned control buffer
        // that lives for `'a`.
        let cmsg = unsafe { hdr.cmsg_first_hdr().as_ref() };
        Self { hdr, cmsg }
    }
}

impl<'a, M: MsgHdr> Iterator for Iter<'a, M> {
    type Item = &'a M::ControlMessage;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.cmsg.take()?;
        // SAFETY: `current` belongs to the valid native control-message chain
        // established by `Iter::new`.
        self.cmsg = unsafe { self.hdr.cmsg_nxt_hdr(current).as_ref() };

        // A native length that cannot cover its own header is malformed, and
        // both platforms keep walking such an entry forever: on MacOS < 14
        // CMSG_NXTHDR might continuously return a zeroed cmsg, and the Winsock
        // rule advances by the aligned length, so a zero never leaves the
        // current entry. End the cmsghdr chain instead.
        #[cfg(any(target_vendor = "apple", windows))]
        if current.len() < size_of::<M::ControlMessage>() {
            self.cmsg = None;
            return None;
        }

        Some(current)
    }
}

// Helper traits for native types for control messages
pub(crate) trait MsgHdr {
    type ControlMessage: CMsgHdr;

    fn cmsg_first_hdr(&self) -> *mut Self::ControlMessage;

    fn cmsg_nxt_hdr(&self, cmsg: &Self::ControlMessage) -> *mut Self::ControlMessage;

    /// Sets the number of control messages added to this `struct msghdr`.
    ///
    /// Note that this is a destructive operation and should only be done as a finalisation
    /// step.
    fn set_control_len(&mut self, len: usize);

    fn control_len(&self) -> usize;
}

pub(crate) trait CMsgHdr {
    fn cmsg_len(length: usize) -> usize;

    fn cmsg_space(length: usize) -> usize;

    fn cmsg_data(&self) -> *mut c_uchar;

    fn set(&mut self, level: c_int, ty: c_int, len: usize);

    fn len(&self) -> usize;
}

#[cfg(unix)]
pub(crate) const LEN: usize = 256;

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;

    const TEST_LEN: usize = 256;

    #[cfg(unix)]
    use libc::{cmsghdr as NativeCMsgHdr, msghdr as NativeMsgHdr};
    #[cfg(windows)]
    use windows_sys::Win32::Networking::WinSock::{
        CMSGHDR as NativeCMsgHdr, WSABUF, WSAMSG as NativeMsgHdr,
    };

    #[cfg(unix)]
    const TEST_LEVEL: c_int = libc::IPPROTO_IP;
    #[cfg(unix)]
    const TEST_TYPE: c_int = libc::IP_TTL;
    #[cfg(windows)]
    const TEST_LEVEL: c_int = windows_sys::Win32::Networking::WinSock::IPPROTO_IP as c_int;
    #[cfg(windows)]
    const TEST_TYPE: c_int = windows_sys::Win32::Networking::WinSock::IP_TTL as c_int;

    #[cfg(unix)]
    fn message_header(control: &mut Aligned<[u8; TEST_LEN]>, len: usize) -> NativeMsgHdr {
        // SAFETY: all-zero is a valid empty `msghdr`; the test initializes the
        // control pointer and length before passing it to the cmsg helpers.
        let mut header: NativeMsgHdr = unsafe { std::mem::zeroed() };
        header.msg_control = control.0.as_mut_ptr().cast();
        header.msg_controllen = len as _;
        header
    }

    #[cfg(windows)]
    fn message_header(control: &mut Aligned<[u8; TEST_LEN]>, len: usize) -> NativeMsgHdr {
        // SAFETY: all-zero is a valid empty `WSAMSG`; the test initializes the
        // control buffer and its length before passing it to the cmsg helpers.
        let mut header: NativeMsgHdr = unsafe { std::mem::zeroed() };
        header.Control = WSABUF {
            buf: control.0.as_mut_ptr(),
            len: len as _,
        };
        header
    }

    /// A zeroed native control-message header, for tests that write its fields
    /// themselves instead of walking a buffer the operating system filled in.
    fn zeroed_control_message() -> NativeCMsgHdr {
        // SAFETY: the native header contains only integer fields, for which
        // zero is a valid initialized value.
        unsafe { std::mem::zeroed() }
    }

    #[test]
    fn encoder_writes_data_and_finalizes_the_encoded_length() {
        let mut control = Aligned([0; TEST_LEN]);
        let mut header = message_header(&mut control, TEST_LEN);
        let value = 0x1234_5678_u32;
        let expected = <NativeCMsgHdr as CMsgHdr>::cmsg_space(size_of_val(&value));

        // SAFETY: `message_header` points at the aligned, writable `control`
        // buffer, whose full capacity is recorded in the header.
        let mut encoder = unsafe { Encoder::new(&mut header) };
        encoder.push(TEST_LEVEL, TEST_TYPE, value).unwrap();
        drop(encoder);
        assert_eq!(header.control_len(), expected);

        // SAFETY: the encoder initialized the control-message chain and
        // finalized its reported length without outliving the backing buffer.
        let mut messages = unsafe { Iter::new(&header) };
        let message = messages.next().unwrap();
        assert_eq!(message.cmsg_level as c_int, TEST_LEVEL);
        assert_eq!(message.cmsg_type as c_int, TEST_TYPE);
        // SAFETY: `messages` walks the live control buffer initialized above.
        let decoded = unsafe { decode::<u32, _>(message) };
        assert_eq!(decoded.unwrap(), value);
        assert!(messages.next().is_none());
    }

    #[test]
    fn encoder_rejects_capacity_that_only_fits_the_header() {
        let mut control = Aligned([0; TEST_LEN]);
        let mut header = message_header(&mut control, size_of::<NativeCMsgHdr>());

        // SAFETY: the backing allocation is larger than the deliberately
        // restricted reported capacity and stays live for the encoder.
        let mut encoder = unsafe { Encoder::new(&mut header) };
        assert!(encoder.push(TEST_LEVEL, TEST_TYPE, 1_u32).is_err());
    }

    #[test]
    fn decode_rejects_a_payload_with_the_wrong_native_length() {
        let mut cmsg = zeroed_control_message();
        cmsg.set(0, 0, <NativeCMsgHdr as CMsgHdr>::cmsg_len(size_of::<u8>()));

        // SAFETY: the header is initialized and its mismatched length makes
        // `decode` reject it before reading a payload.
        let error = unsafe { decode::<u32, _>(&cmsg) }.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    /// A payload length always leaves room for the header it follows, and the
    /// space it occupies never shrinks below that length.
    #[test]
    fn native_lengths_stay_consistent_with_the_header_they_describe() {
        let header = size_of::<NativeCMsgHdr>();
        for payload in [0, 1, 4, 8, 20] {
            let len = <NativeCMsgHdr as CMsgHdr>::cmsg_len(payload);
            let space = <NativeCMsgHdr as CMsgHdr>::cmsg_space(payload);
            assert!(len >= header + payload, "cmsg_len({payload}) = {len}");
            assert!(space >= len, "cmsg_space({payload}) = {space} < {len}");
        }
    }

    /// Both platforms can be asked to walk an entry whose native length does
    /// not even cover its own header: MacOS < 14 by returning a zeroed cmsg,
    /// and Winsock because the chain advances by that length alone. Neither
    /// may loop on it, and a length exactly at the boundary still decodes.
    #[cfg(any(target_vendor = "apple", windows))]
    #[test]
    fn iterator_ends_on_a_header_too_short_to_advance_the_chain() {
        let mut control = Aligned([0; TEST_LEN]);
        let header_len = size_of::<NativeCMsgHdr>();
        let header = message_header(&mut control, header_len);
        // SAFETY: the header points at aligned storage for a complete native
        // control message, and the test writes only that header.
        unsafe { header.cmsg_first_hdr().as_mut().unwrap() }.set(0, 0, 0);
        // SAFETY: the native header and its backing buffer remain initialized
        // and live for the iterator.
        let mut messages = unsafe { Iter::new(&header) };
        assert!(messages.next().is_none());
        // A fused end: re-polling must not resume walking the same entry.
        assert!(messages.next().is_none());

        // SAFETY: the same initialized control buffer is still live.
        unsafe { header.cmsg_first_hdr().as_mut().unwrap() }.set(0, 0, header_len);
        // SAFETY: as above; this time `cmsg_len` is exactly the valid lower
        // boundary for a native header.
        assert!(unsafe { Iter::new(&header) }.next().is_some());
    }

    /// Unix walks the chain with the platform's own `CMSG_NXTHDR`, but the
    /// Winsock rule is a hand-written port of `WSA_CMSG_NXTHDR`. A following
    /// entry belongs to the chain once the buffer covers its complete header,
    /// and one byte short of that it does not: a receive that read metadata
    /// into the last entry would otherwise drop or invent it.
    #[cfg(windows)]
    #[test]
    fn the_chain_reaches_the_last_header_the_buffer_completely_covers() {
        let payload = 0x1234_5678_u32;
        let header_len = size_of::<NativeCMsgHdr>();
        let second = <NativeCMsgHdr as CMsgHdr>::cmsg_space(size_of_val(&payload));
        let covered = second + header_len;

        for (control_len, reachable) in [(covered, true), (covered - 1, false)] {
            let mut control = Aligned([0; TEST_LEN]);
            // SAFETY: `control` is aligned for and far larger than one native
            // header, which is all this writes.
            let first = unsafe { &mut *control.0.as_mut_ptr().cast::<NativeCMsgHdr>() };
            first.set(
                TEST_LEVEL,
                TEST_TYPE,
                <NativeCMsgHdr as CMsgHdr>::cmsg_len(size_of_val(&payload)),
            );
            // SAFETY: `second` is an aligned offset within `control`, leaving
            // room there for a second complete native header.
            let next = unsafe { &mut *control.0[second..].as_mut_ptr().cast::<NativeCMsgHdr>() };
            next.set(TEST_LEVEL, TEST_TYPE, header_len);
            let header = message_header(&mut control, control_len);

            // SAFETY: the chain above is initialized and stays live for the
            // iterator, which never reads past the reported control length.
            let mut messages = unsafe { Iter::new(&header) };
            assert!(messages.next().is_some(), "control_len {control_len}");
            assert_eq!(
                messages.next().is_some(),
                reachable,
                "control_len {control_len}"
            );
        }
    }
}
