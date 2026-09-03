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

        #[cfg(target_vendor = "apple")]
        {
            // On MacOS < 14 CMSG_NXTHDR might continuously return a zeroed cmsg. In
            // such case, return `None` instead, thus indicating the end of
            // the cmsghdr chain.
            if current.len() < size_of::<M::ControlMessage>() {
                return None;
            }
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn message_header(control: &mut Aligned<[u8; LEN]>, len: usize) -> libc::msghdr {
        // SAFETY: all-zero is a valid empty `msghdr`; the test initializes the
        // control pointer and length before passing it to the cmsg helpers.
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        header.msg_control = control.0.as_mut_ptr().cast();
        header.msg_controllen = len as _;
        header
    }

    #[test]
    fn encoder_writes_data_and_finalizes_the_encoded_length() {
        let mut control = Aligned([0; LEN]);
        let mut header = message_header(&mut control, LEN);
        let value = 0x1234_5678_u32;
        let expected = <libc::cmsghdr as CMsgHdr>::cmsg_space(size_of_val(&value));

        // SAFETY: `message_header` points at the aligned, writable `control`
        // buffer, whose full capacity is recorded in the header.
        let mut encoder = unsafe { Encoder::new(&mut header) };
        encoder.push(libc::IPPROTO_IP, libc::IP_TTL, value).unwrap();
        drop(encoder);
        assert_eq!(header.control_len(), expected);

        // SAFETY: the encoder initialized the control-message chain and
        // finalized its reported length without outliving the backing buffer.
        let mut messages = unsafe { Iter::new(&header) };
        // SAFETY: `messages` walks the live control buffer initialized above.
        let decoded = unsafe { decode::<u32, _>(messages.next().unwrap()) };
        assert_eq!(decoded.unwrap(), value);
        assert!(messages.next().is_none());
    }

    #[test]
    fn encoder_rejects_capacity_that_only_fits_the_header() {
        let mut control = Aligned([0; LEN]);
        let mut header = message_header(&mut control, size_of::<libc::cmsghdr>());

        // SAFETY: the backing allocation is larger than the deliberately
        // restricted reported capacity and stays live for the encoder.
        let mut encoder = unsafe { Encoder::new(&mut header) };
        assert!(encoder.push(libc::IPPROTO_IP, libc::IP_TTL, 1_u32).is_err());
    }

    #[test]
    fn decode_rejects_a_payload_with_the_wrong_native_length() {
        // SAFETY: `cmsghdr` contains only integer fields, for which zero is a
        // valid initialized value; the test sets its length before use.
        let mut cmsg: libc::cmsghdr = unsafe { std::mem::zeroed() };
        cmsg.set(0, 0, <libc::cmsghdr as CMsgHdr>::cmsg_len(size_of::<u8>()));

        // SAFETY: the header is initialized and its mismatched length makes
        // `decode` reject it before reading a payload.
        let error = unsafe { decode::<u32, _>(&cmsg) }.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn apple_iterator_rejects_short_headers_but_accepts_the_boundary() {
        let mut control = Aligned([0; LEN]);
        let header_len = size_of::<libc::cmsghdr>();
        let header = message_header(&mut control, header_len);
        // SAFETY: the header points at aligned storage for a complete
        // `cmsghdr`, and the test writes only that header.
        unsafe { header.cmsg_first_hdr().as_mut().unwrap() }.set(0, 0, 0);
        // SAFETY: the native header and its backing buffer remain initialized
        // and live for the iterator.
        assert!(unsafe { Iter::new(&header) }.next().is_none());

        // SAFETY: the same initialized control buffer is still live.
        unsafe { header.cmsg_first_hdr().as_mut().unwrap() }.set(0, 0, header_len);
        // SAFETY: as above; this time `cmsg_len` is exactly the valid lower
        // boundary for a native header.
        assert!(unsafe { Iter::new(&header) }.next().is_some());
    }
}
