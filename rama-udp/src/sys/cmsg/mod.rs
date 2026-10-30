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

/// Largest payload, in bytes, for which [`CMsgHdr::cmsg_len`] and [`CMsgHdr::cmsg_space`]
/// compute a length; larger payloads report `usize::MAX`, which no control buffer fits.
pub(crate) const MAX_PAYLOAD: usize = u16::MAX as usize;

/// Encodes native control messages into a buffer used by calls such as `sendmsg`.
///
/// Dropping the `Encoder` stores the encoded length in the native msghdr, which makes it
/// usable; the borrow of `hdr` keeps the msghdr from a system call until then.
pub(crate) struct Encoder<'a, M: MsgHdr> {
    hdr: &'a mut M,
    // A pointer derived from the control buffer, not a reference to one header,
    // so that it also covers the payload trailing that header.
    // Safety invariant: `None`, or a pointer at or after the start of `hdr`'s control
    // buffer, with the provenance of that buffer.
    cmsg: Option<NonNull<M::ControlMessage>>,
    // Safety invariant: the address one past the last control-buffer byte `new` was given.
    end: usize,
    len: usize,
}

impl<'a, M: MsgHdr> Encoder<'a, M> {
    /// # Safety
    ///
    /// The caller must ensure that `hdr`'s control buffer pointer is null or aligned for
    /// `M::ControlMessage`, that it is valid for reads and writes of `hdr.control_len()`
    /// bytes, all initialized, and that nothing but the returned `Encoder` accesses those
    /// bytes while it exists.
    pub(crate) unsafe fn new(hdr: &'a mut M) -> Self {
        let first = hdr.cmsg_first_hdr();
        let end = first.addr().saturating_add(hdr.control_len());
        // Safety invariant: `first` is null or the control buffer pointer itself (`MsgHdr`
        // contract), with that buffer's provenance.
        let cmsg = NonNull::new(first);
        Self {
            cmsg,
            hdr,
            end,
            len: 0,
        }
    }

    /// Append a control message to the buffer.
    ///
    /// Capacity failures are programming errors guarded at socket
    /// construction, but are still returned so requested metadata is never
    /// silently omitted in a release build.
    pub(crate) fn push<T: ControlPayload>(
        &mut self,
        level: c_int,
        ty: c_int,
        value: T,
    ) -> io::Result<()> {
        let size = size_of::<T>();
        let space = M::ControlMessage::cmsg_space(size);
        let Some(cmsg) = self.cmsg.take() else {
            return Err(io::Error::other(
                "no control-message buffer space remaining",
            ));
        };
        let cmsg = cmsg.as_ptr();
        let fits = cmsg.is_aligned()
            && cmsg
                .addr()
                .checked_add(space)
                .is_some_and(|entry_end| entry_end <= self.end);
        if !fits {
            return Err(io::Error::other("control-message buffer too small"));
        }
        // In the bounds checked above: `size_of::<C>() <= cmsg_len(0)` and
        // `cmsg_len(0) + size == cmsg_len(size) <= space` (`CMsgHdr` contract; `space` is not
        // `usize::MAX` since it fit), so header and payload both end within `self.end`.

        // SAFETY: `set` takes `&mut` to the header at `cmsg`, which needs it aligned (checked
        // above), dereferenceable and initialized for one header, and unaliased. By the
        // field invariant `cmsg` is at or after the buffer start, and the bound above ends
        // the header within `self.end`; `new`'s contract makes those bytes initialized and
        // reachable only through this `Encoder`. The header holds only integers.
        unsafe { (*cmsg).set(level, ty, M::ControlMessage::cmsg_len(size)) };
        let data = cmsg_data(cmsg);
        // The payload is only aligned for the native header, not necessarily for `T`.
        // SAFETY: `write_unaligned` needs `data` valid for writes of `size` bytes: they are
        // `cmsg + cmsg_len(0) .. cmsg + cmsg_len(size)` (`cmsg_data`), inside the bound above,
        // with the buffer's provenance. `T: ControlPayload` writes no uninitialized byte, so
        // the buffer stays initialized for the headers written after it.
        unsafe { ptr::write_unaligned(data.cast::<T>(), value) };
        // SAFETY: `cmsg_nxt_hdr` needs an aligned, initialized header inside this message's
        // control buffer with its provenance: `cmsg` is the header just written above.
        let next = unsafe { self.hdr.cmsg_nxt_hdr(cmsg) };
        // Safety invariant: `next` is null or `cmsg` advanced with its provenance
        // (`MsgHdr` contract), so still at or after the buffer start.
        self.cmsg = NonNull::new(next);
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
    // Safety invariant: `None`, or a pointer at or after the start of `hdr`'s control
    // buffer, with the provenance of that buffer.
    cmsg: Option<NonNull<M::ControlMessage>>,
    /// Address just past the control bytes the receive reported.
    // Safety invariant: the control buffer start plus `hdr.control_len()`.
    end: usize,
}

impl<'a, M: MsgHdr> Iter<'a, M> {
    /// # Safety
    ///
    /// The caller must ensure that `hdr`'s control buffer pointer is null or aligned for
    /// `M::ControlMessage`, and that its first `hdr.control_len()` bytes lie in one live
    /// allocation, are initialized, and are not written for `'a`.
    pub(crate) unsafe fn new(hdr: &'a M) -> Self {
        let first = hdr.cmsg_first_hdr();
        Self {
            hdr,
            // Safety invariant: `first` is null or the control buffer pointer itself
            // (`MsgHdr` contract), with that buffer's provenance.
            cmsg: NonNull::new(first),
            end: first.addr().saturating_add(hdr.control_len()),
        }
    }
}

impl<'a, M: MsgHdr> Iterator for Iter<'a, M> {
    type Item = CMsg<'a, M::ControlMessage>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.cmsg.take()?;
        let header_in_bounds = current.as_ptr().is_aligned()
            && current
                .as_ptr()
                .addr()
                .checked_add(size_of::<M::ControlMessage>())
                .is_some_and(|header_end| header_end <= self.end);
        if !header_in_bounds {
            return None;
        }
        // SAFETY: `as_ref` needs `current` aligned (checked above) and pointing to a valid,
        // initialized header that is not written while the reference lives. The field
        // invariant puts it at or after the buffer start and the check above ends it within
        // the reported bytes, which `new`'s contract makes initialized and unwritten for `'a`;
        // the `CMsgHdr` contract makes any initialized bytes a valid header.
        // `len()` is read once: every later bound uses this value, not another call.
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

        // SAFETY: `cmsg_nxt_hdr` needs an aligned, initialized header inside this message's
        // control buffer with its provenance, which is what the proof above shows `current` is.
        let next = unsafe { self.hdr.cmsg_nxt_hdr(current.as_ptr()) };
        // Safety invariant: `next` is null or `current` advanced with its provenance
        // (`MsgHdr` contract), so still at or after the buffer start.
        self.cmsg = NonNull::new(next);
        // Safety invariant of `CMsg`: `current` is aligned, and its `len` bytes lie in the
        // initialized, unwritten reported bytes (`within` and `new`'s contract).
        Some(CMsg {
            ptr: current,
            len,
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
    // Safety invariant: `ptr` is aligned for `C`, has the provenance of its control
    // buffer, and the `len` (at least `size_of::<C>()`) bytes from it are initialized and
    // not written for `'a`.
    ptr: NonNull<C>,
    // Safety invariant: the entry length `Iter` checked against the buffer, as above.
    len: usize,
    _lifetime: PhantomData<&'a C>,
}

impl<C: CMsgHdr> CMsg<'_, C> {
    /// The native length of this entry, header included, as checked against the buffer.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Decode the payload after checking its native length.
    ///
    /// # Safety
    ///
    /// The caller must ensure that every initialized bit pattern of `size_of::<T>()` bytes is
    /// a valid `T`.
    pub(crate) unsafe fn decode<T: Copy>(self) -> io::Result<T> {
        if self.len() != C::cmsg_len(size_of::<T>()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid UDP control-message length",
            ));
        }
        let data = cmsg_data(self.ptr.as_ptr());
        // The payload is only aligned for `C`, which on musl is less strict than payloads such as
        // `libc::timespec`, so it cannot be read through an aligned `ptr::read`.
        // SAFETY: `read_unaligned` needs `data` valid for reads of `size_of::<T>()` initialized
        // bytes forming a valid `T`. `self.len` fits in the buffer (field invariant), so the
        // length check makes `cmsg_len(size_of::<T>())` other than `usize::MAX` and, by the
        // `CMsgHdr` contract, `cmsg_len(0) + size_of::<T>() == self.len`. The read therefore
        // covers `ptr + cmsg_len(0) .. ptr + self.len` with the buffer's provenance
        // (`cmsg_data`), initialized by the field invariant; this function's contract makes
        // it a valid `T`.
        Ok(unsafe { ptr::read_unaligned(data.cast::<T>()) })
    }
}

impl<C: CMsgHdr> Deref for CMsg<'_, C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        // SAFETY: `as_ref` needs `ptr` aligned and pointing to a valid `C` that is not written
        // while the reference lives. The field invariant gives aligned, initialized and
        // unwritten for `'a`, which outlives the borrow of `self`; the `CMsgHdr` contract makes
        // those initialized bytes a valid `C`.
        unsafe { self.ptr.as_ref() }
    }
}

/// Native message header with a control buffer.
///
/// # Safety
///
/// Implementors must ensure that:
/// - `cmsg_first_hdr` returns null or the stored control buffer pointer itself, with its
///   address and provenance;
/// - `control_len` returns the stored control buffer length;
/// - `cmsg_nxt_hdr(cmsg)` returns null or `cmsg` advanced by a non-negative byte offset
///   through pointer arithmetic, keeping the provenance of `cmsg`.
pub(crate) unsafe trait MsgHdr {
    type ControlMessage: CMsgHdr;

    /// The first control-message header, or null when the buffer cannot hold one.
    fn cmsg_first_hdr(&self) -> *mut Self::ControlMessage;

    /// The header following `cmsg`, or null when there is none.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `cmsg` is aligned for `Self::ControlMessage`, points to an
    /// initialized header inside this message's control buffer that is not written during
    /// the call, and has the provenance of that buffer.
    unsafe fn cmsg_nxt_hdr(&self, cmsg: *const Self::ControlMessage) -> *mut Self::ControlMessage;

    /// Sets the number of control messages added to this `struct msghdr`.
    ///
    /// Note that this is a destructive operation and should only be done as a finalisation
    /// step.
    fn set_control_len(&mut self, len: usize);

    fn control_len(&self) -> usize;
}

/// Native control-message header.
///
/// # Safety
///
/// Implementors must ensure that every initialized bit pattern of `size_of::<Self>()` bytes
/// is a valid `Self`, and that, for every `n <= MAX_PAYLOAD`,
/// `size_of::<Self>() <= cmsg_len(0)`, `cmsg_len(n) == cmsg_len(0) + n` and
/// `cmsg_len(n) <= cmsg_space(n) < usize::MAX`, and that both return `usize::MAX` for larger
/// `n`. The payload of a header is the `cmsg_len(0)` offset [`cmsg_data`] computes.
/// `len` need not be consistent between calls: callers read it once per header.
pub(crate) unsafe trait CMsgHdr: Sized {
    fn cmsg_len(length: usize) -> usize;

    fn cmsg_space(length: usize) -> usize;

    fn set(&mut self, level: c_int, ty: c_int, len: usize);

    fn len(&self) -> usize;
}

/// The payload trailing the header `this` points to: `this` advanced by `cmsg_len(0)`
/// bytes, keeping the provenance of `this`.
///
/// Computing it needs no `unsafe`: the result is only dereferenceable where `this` is.
fn cmsg_data<C: CMsgHdr>(this: *const C) -> *mut c_uchar {
    this.cast::<c_uchar>()
        .wrapping_add(C::cmsg_len(0))
        .cast_mut()
}

/// A control-message payload whose every byte is initialized.
///
/// # Safety
///
/// Implementors must ensure that `Self` has no padding and no field that may hold
/// uninitialized bytes, so that every byte of every `Self` value is initialized.
pub(crate) unsafe trait ControlPayload: Copy {}

/// Implements [`ControlPayload`] for structs whose listed field types are all
/// `ControlPayload`, asserting at compile time that those fields fill the struct.
macro_rules! control_payload_struct {
    ($($ty:ty => $($field:ty),+;)+) => {$(
        const _: () = {
            const fn is_payload<T: $crate::sys::cmsg::ControlPayload>() {}
            $(is_payload::<$field>();)+
            assert!(size_of::<$ty>() == 0 $(+ size_of::<$field>())+);
        };
        // SAFETY: the assertion above shows the listed fields, each `ControlPayload`,
        // fill `$ty`, so it has no padding and every byte belongs to an initialized field.
        unsafe impl $crate::sys::cmsg::ControlPayload for $ty {}
    )+};
}
pub(crate) use control_payload_struct;

macro_rules! control_payload_integer {
    ($($ty:ty),+) => {$(
        // SAFETY: integers have no padding, and an integer value is initialized (the
        // Reference's validity rules for integers forbid uninitialized bytes).
        unsafe impl ControlPayload for $ty {}
    )+};
}
control_payload_integer!(u8, u16, u32, u64, i8, i16, i32, i64);

// SAFETY: an array of `u8` has no padding and each of its integer elements is initialized.
unsafe impl<const N: usize> ControlPayload for [u8; N] {}

#[cfg(unix)]
pub(crate) const LEN: usize = 256;

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        let data_offset = <NativeCMsgHdr as CMsgHdr>::cmsg_len(0);
        assert!(data_offset >= header, "cmsg_len(0) = {data_offset}");
        for payload in [0, 1, 4, 8, 20, MAX_PAYLOAD] {
            let len = <NativeCMsgHdr as CMsgHdr>::cmsg_len(payload);
            let space = <NativeCMsgHdr as CMsgHdr>::cmsg_space(payload);
            assert_eq!(len, data_offset + payload, "cmsg_len({payload})");
            assert!(space >= len, "cmsg_space({payload}) = {space} < {len}");
            assert_ne!(space, usize::MAX, "cmsg_space({payload})");
        }
        for payload in [MAX_PAYLOAD + 1, usize::MAX] {
            assert_eq!(<NativeCMsgHdr as CMsgHdr>::cmsg_len(payload), usize::MAX);
            assert_eq!(<NativeCMsgHdr as CMsgHdr>::cmsg_space(payload), usize::MAX);
        }

        // The payload offset `cmsg_data` uses is the platform's own.
        #[cfg(unix)]
        {
            let control = Aligned([0_u8; TEST_LEN]);
            let header = control.0.as_ptr().cast::<NativeCMsgHdr>();
            // SAFETY: `CMSG_DATA` offsets `header` within `control`, which is aligned for and
            // larger than one header; nothing is read or written through the result.
            let native = unsafe { libc::CMSG_DATA(header) };
            assert_eq!(cmsg_data(header).addr(), native.addr());
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

    /// A header whose `len()` reports 8 once and 72 on every later call: the
    /// `CMsgHdr` contract allows that, so decoding must bound itself by the length
    /// the iterator checked, not by a fresh call.
    #[test]
    fn decode_bounds_the_payload_by_the_length_the_iterator_checked() {
        static LEN_CALLS: AtomicUsize = AtomicUsize::new(0);

        #[repr(C)]
        struct ShiftingHeader(u64);

        // SAFETY: a lone `u64` makes any initialized 8 bytes a valid value, and the lengths
        // are the 8-byte header plus the payload, `usize::MAX` past `MAX_PAYLOAD`, with equal
        // space, which meets every relation the contract states.
        unsafe impl CMsgHdr for ShiftingHeader {
            fn cmsg_len(length: usize) -> usize {
                if length > MAX_PAYLOAD {
                    usize::MAX
                } else {
                    size_of::<Self>() + length
                }
            }

            fn cmsg_space(length: usize) -> usize {
                Self::cmsg_len(length)
            }

            fn set(&mut self, _level: c_int, _ty: c_int, len: usize) {
                self.0 = len as u64;
            }

            fn len(&self) -> usize {
                if LEN_CALLS.fetch_add(1, Ordering::Relaxed) == 0 {
                    size_of::<Self>()
                } else {
                    size_of::<Self>() + 64
                }
            }
        }

        struct OneHeader(*mut ShiftingHeader);

        // SAFETY: `cmsg_first_hdr` returns the stored pointer, `control_len` the stored
        // length (one header), and `cmsg_nxt_hdr` always null.
        unsafe impl MsgHdr for OneHeader {
            type ControlMessage = ShiftingHeader;

            fn cmsg_first_hdr(&self) -> *mut ShiftingHeader {
                self.0
            }

            unsafe fn cmsg_nxt_hdr(&self, _cmsg: *const ShiftingHeader) -> *mut ShiftingHeader {
                ptr::null_mut()
            }

            fn set_control_len(&mut self, _len: usize) {}

            fn control_len(&self) -> usize {
                size_of::<ShiftingHeader>()
            }
        }

        let mut control = ShiftingHeader(8);
        let header = OneHeader(&raw mut control);
        // SAFETY: the control pointer is `control`, an aligned, initialized header of
        // `control_len()` bytes that nothing writes while the iterator lives.
        let message = unsafe { Iter::new(&header) }.next().unwrap();
        // SAFETY: every initialized bit pattern is a valid byte array.
        let error = unsafe { message.decode::<[u8; 64]>() }.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
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
