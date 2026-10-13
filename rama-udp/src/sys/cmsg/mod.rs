use std::{
    ffi::{c_int, c_uchar},
    io,
    marker::PhantomData,
    ops::Deref,
    ptr::{self, NonNull},
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
    // A pointer derived from the control buffer, not a reference to one header,
    // so that it also covers the payload trailing that header.
    cmsg: Option<NonNull<M::ControlMessage>>,
    len: usize,
}

impl<'a, M: MsgHdr> Encoder<'a, M> {
    /// # Safety
    /// - `hdr` must contain a suitably aligned pointer to a big enough buffer to hold control messages
    ///   bytes. All bytes of this buffer can be safely written.
    /// - The `Encoder` must be dropped before `hdr` is passed to a system call, and must not be leaked.
    pub(crate) unsafe fn new(hdr: &'a mut M) -> Self {
        let cmsg = NonNull::new(hdr.cmsg_first_hdr());
        Self { cmsg, hdr, len: 0 }
    }

    /// Append a control message to the buffer.
    ///
    /// Capacity failures are programming errors guarded at socket
    /// construction, but are still returned so requested metadata is never
    /// silently omitted in a release build.
    pub(crate) fn push<T: Copy>(&mut self, level: c_int, ty: c_int, value: T) -> io::Result<()> {
        let space = M::ControlMessage::cmsg_space(size_of_val(&value));
        if self.hdr.control_len() < self.len + space {
            return Err(io::Error::other("control-message buffer too small"));
        }
        let Some(cmsg) = self.cmsg.take() else {
            return Err(io::Error::other(
                "no control-message buffer space remaining",
            ));
        };
        let cmsg = cmsg.as_ptr();
        let cmsg_len = M::ControlMessage::cmsg_len(size_of_val(&value));
        // SAFETY: `new` established that `cmsg` points into the writable
        // control buffer, and the capacity check above covers its header.
        unsafe { (*cmsg).set(level, ty, cmsg_len) };
        // SAFETY: `cmsg` is a header inside the control buffer and carries the
        // provenance of the whole buffer.
        let data = unsafe { M::ControlMessage::cmsg_data(cmsg) };
        // The payload is only aligned for the native header, not necessarily for `T`.
        // SAFETY: the capacity check above covers the payload after the header.
        unsafe { ptr::write_unaligned(data.cast::<T>(), value) };
        // SAFETY: `cmsg` is the header just initialized inside this message's
        // control buffer.
        self.cmsg = NonNull::new(unsafe { self.hdr.cmsg_nxt_hdr(cmsg) });
        self.len += space;
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

pub(crate) struct Iter<'a, M: MsgHdr> {
    hdr: &'a M,
    cmsg: Option<NonNull<M::ControlMessage>>,
    /// Address just past the control bytes the receive reported.
    end: usize,
}

impl<'a, M: MsgHdr> Iter<'a, M> {
    /// # Safety
    ///
    /// `hdr` must hold a pointer to memory outliving `'a` which can be soundly read for the
    /// lifetime of the constructed `Iter` and contains a buffer of native cmsgs, i.e. is aligned
    /// for native `cmsghdr`, is initialized for its reported length, and has correct internal
    /// links.
    pub(crate) unsafe fn new(hdr: &'a M) -> Self {
        let first = hdr.cmsg_first_hdr();
        Self {
            hdr,
            cmsg: NonNull::new(first),
            end: first.addr().saturating_add(hdr.control_len()),
        }
    }
}

impl<'a, M: MsgHdr> Iterator for Iter<'a, M> {
    type Item = CMsg<'a, M::ControlMessage>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.cmsg.take()?;
        // SAFETY: `new` guarantees that every linked header lies inside the
        // initialized control buffer.
        let len = unsafe { current.as_ref() }.len();

        // A length short of its own header never advances the chain on several
        // platforms (MacOS < 14 may even yield zeroed cmsgs), and one past the
        // reported bytes reads what the receive never wrote: both end it.
        let within = len >= size_of::<M::ControlMessage>()
            && current
                .as_ptr()
                .addr()
                .checked_add(len)
                .is_some_and(|entry_end| entry_end <= self.end);
        if !within {
            return None;
        }

        // SAFETY: `current` is an initialized header inside this message's
        // control buffer, as established by `new`.
        self.cmsg = NonNull::new(unsafe { self.hdr.cmsg_nxt_hdr(current.as_ptr()) });
        Some(CMsg {
            ptr: current,
            _lifetime: PhantomData,
        })
    }
}

/// A native control message: its header and the payload that trails it.
///
/// Holds a pointer with provenance over the whole control buffer, since a
/// reference to the header would not cover the payload.
#[derive(Clone, Copy)]
pub(crate) struct CMsg<'a, C: CMsgHdr> {
    ptr: NonNull<C>,
    _lifetime: PhantomData<&'a C>,
}

impl<C: CMsgHdr> CMsg<'_, C> {
    /// Decode the payload after checking its native length.
    ///
    /// # Safety
    ///
    /// Every bit pattern of `size_of::<T>()` bytes must be a valid `T`.
    pub(crate) unsafe fn decode<T: Copy>(self) -> io::Result<T> {
        if self.len() != C::cmsg_len(size_of::<T>()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid UDP control-message length",
            ));
        }
        // SAFETY: `Iter` only yields headers inside the control buffer, with
        // the provenance of that buffer.
        let data = unsafe { C::cmsg_data(self.ptr.as_ptr()) };
        // The payload is only aligned for `C`, which on musl is less strict than payloads such as
        // `libc::timespec`, so it cannot be read through an aligned `ptr::read`.
        // SAFETY: `Iter` only yields entries within the initialized control
        // bytes, and the length check above proves the payload is a whole `T`.
        Ok(unsafe { ptr::read_unaligned(data.cast::<T>()) })
    }
}

impl<C: CMsgHdr> Deref for CMsg<'_, C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        // SAFETY: `Iter` only yields initialized headers of a buffer that
        // outlives `'a`.
        unsafe { self.ptr.as_ref() }
    }
}

// Helper traits for native types for control messages
pub(crate) trait MsgHdr {
    type ControlMessage: CMsgHdr;

    /// The first control-message header, or null when the buffer cannot hold one.
    ///
    /// This is the stored control buffer pointer itself, so it carries the
    /// provenance of the whole buffer rather than of `self`.
    fn cmsg_first_hdr(&self) -> *mut Self::ControlMessage;

    /// The header following `cmsg`, or null when there is none.
    ///
    /// # Safety
    ///
    /// `cmsg` must point to an initialized header inside this message's control
    /// buffer, with the provenance of that buffer.
    unsafe fn cmsg_nxt_hdr(&self, cmsg: *const Self::ControlMessage) -> *mut Self::ControlMessage;

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

    /// The payload trailing the header `this` points to.
    ///
    /// # Safety
    ///
    /// `this` must point to a header inside a control buffer. The result
    /// inherits its provenance, which must therefore cover the whole buffer.
    unsafe fn cmsg_data(this: *const Self) -> *mut c_uchar;

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

    fn level_and_type(message: CMsg<'_, NativeCMsgHdr>) -> (c_int, c_int) {
        (message.cmsg_level as c_int, message.cmsg_type as c_int)
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
        // SAFETY: every bit pattern is a valid `u32`.
        let decoded = unsafe { message.decode::<u32>() };
        assert_eq!(decoded.unwrap(), value);
        assert!(messages.next().is_none());
    }

    /// Payloads are written and read through a pointer covering the whole
    /// buffer, at whatever offset the padding of earlier entries leaves them.
    /// Mixed sizes move that offset, and a payload stricter than the native
    /// header's alignment must not be assumed aligned: Miri checks both.
    #[test]
    fn mixed_payloads_round_trip_through_one_control_buffer() {
        let mut control = Aligned([0; TEST_LEN]);
        let mut header = message_header(&mut control, TEST_LEN);
        {
            // SAFETY: `message_header` points at the aligned, writable
            // `control` buffer, whose full capacity is recorded in the header.
            let mut encoder = unsafe { Encoder::new(&mut header) };
            encoder.push(1, 2, 0x1234_5678_u32).unwrap();
            encoder.push(3, 4, [0xab_u8; 5]).unwrap();
            encoder.push(5, 6, 0x0102_u16).unwrap();
            encoder.push(7, 8, 0x0102_0304_0506_0708_u64).unwrap();
        }

        // SAFETY: the encoder initialized the control-message chain and
        // finalized its reported length without outliving the backing buffer.
        let mut messages = unsafe { Iter::new(&header) };

        let message = messages.next().unwrap();
        assert_eq!(level_and_type(message), (1, 2));
        // SAFETY: every bit pattern is a valid `u32`.
        let decoded = unsafe { message.decode::<u32>() };
        assert_eq!(decoded.unwrap(), 0x1234_5678);

        let message = messages.next().unwrap();
        assert_eq!(level_and_type(message), (3, 4));
        // SAFETY: every bit pattern is a valid byte array.
        let decoded = unsafe { message.decode::<[u8; 5]>() };
        assert_eq!(decoded.unwrap(), [0xab; 5]);

        let message = messages.next().unwrap();
        assert_eq!(level_and_type(message), (5, 6));
        // SAFETY: every bit pattern is a valid `u16`.
        let decoded = unsafe { message.decode::<u16>() };
        assert_eq!(decoded.unwrap(), 0x0102);

        let message = messages.next().unwrap();
        assert_eq!(level_and_type(message), (7, 8));
        // SAFETY: every bit pattern is a valid `u64`.
        let decoded = unsafe { message.decode::<u64>() };
        assert_eq!(decoded.unwrap(), 0x0102_0304_0506_0708);

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
        let mut control = Aligned([0; TEST_LEN]);
        let header = message_header(&mut control, TEST_LEN);
        // SAFETY: the header points at aligned storage for a complete native
        // control message, and the test writes only that header.
        unsafe { header.cmsg_first_hdr().as_mut().unwrap() }.set(
            TEST_LEVEL,
            TEST_TYPE,
            <NativeCMsgHdr as CMsgHdr>::cmsg_len(size_of::<u8>()),
        );
        // SAFETY: the native header and its backing buffer remain initialized
        // and live for the iterator.
        let message = unsafe { Iter::new(&header) }.next().unwrap();

        // SAFETY: every bit pattern is a valid `u32`, and the mismatched
        // length makes `decode` reject it before reading a payload.
        let error = unsafe { message.decode::<u32>() }.unwrap_err();
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

    /// Several platforms can be asked to walk an entry whose native length does
    /// not even cover its own header: MacOS < 14 by returning a zeroed cmsg,
    /// and the BSDs and Winsock because the chain advances by that length
    /// alone. None may loop on it, and a length exactly at the boundary still
    /// decodes.
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

    /// Some kernels copy a truncated control message with its original length,
    /// so an entry may claim payload bytes past what the receive reported.
    /// Decoding it would read bytes the kernel never wrote; an entry is only
    /// yielded once the reported control bytes cover all of it.
    #[test]
    fn iterator_ends_on_an_entry_running_past_the_reported_control_bytes() {
        let entry_len = <NativeCMsgHdr as CMsgHdr>::cmsg_len(size_of::<u32>());
        for (control_len, yielded) in [(entry_len, true), (entry_len - 1, false)] {
            let mut control = Aligned([0; TEST_LEN]);
            let header = message_header(&mut control, control_len);
            // SAFETY: the header points at aligned storage for a complete
            // native control message, and the test writes only that header.
            unsafe { header.cmsg_first_hdr().as_mut().unwrap() }
                .set(TEST_LEVEL, TEST_TYPE, entry_len);
            // SAFETY: the native header and its backing buffer remain
            // initialized and live for the iterator.
            let mut messages = unsafe { Iter::new(&header) };
            assert_eq!(
                messages.next().is_some(),
                yielded,
                "control_len {control_len}"
            );
            assert!(messages.next().is_none(), "control_len {control_len}");
        }
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
