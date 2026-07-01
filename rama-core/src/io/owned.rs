//! Owned-buffer async IO traits: rama's completion-style IO surface.
//!
//! These are inspired by the owned-buffer model used by io_uring runtimes
//! (`compio` / `monoio` / `tokio-uring`): instead of lending a borrowed buffer
//! to a readiness-based `poll_read`, the caller hands an **owned** buffer to the
//! operation and gets it back together with the result. That ownership is the
//! precondition for a completion backend: the buffer must stay valid and stable
//! until the kernel finishes the op, a borrowed-per-poll buffer is gone after
//! `Pending`, whereas the returned future keeps the owned one alive.
//!
//! # Buffers: [`IoBuf`] / [`IoBufMut`]
//! An owned buffer is an [`IoBuf`] (its initialized bytes via `as_init() -> &[u8]`);
//! a read *target* is an [`IoBufMut`] (writable backing via
//! `as_uninit() -> &mut [MaybeUninit<u8>]`, with [`SetLen`] split out to declare the
//! initialized length).
//!
//! **Reads overwrite from offset 0** (the compio/tokio-uring semantic), they fill
//! the buffer from the start, so reusing one without clearing it is safe. To
//! *accumulate* instead (read into the spare, keeping prior bytes), pass
//! [`buf.uninit()`](IoBufMut::uninit), a spare-view [`Uninit`] that appends.
//!
//! A tokio transport *is* an owned transport for free: no wrapper is needed in
//! the `tokio -> owned` direction. Owned-native backends (an io_uring leaf, a
//! sans-io TLS stream) implement the owned traits **directly** and must NOT also
//! implement tokio's `AsyncRead`/`AsyncWrite` (coherence: that would overlap the
//! blanket). The reverse `owned -> tokio` direction, for readiness-only consumers
//! that can't take owned buffers will need an extra memory copy.

use core::future::poll_fn;
use core::mem::MaybeUninit;
use core::ops::{Bound, RangeBounds};
use core::pin::Pin;
use core::task::{Context, Poll};
use std::io;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::bytes::{Bytes, BytesMut};

/// Result of an owned-buffer IO operation: the [`io::Result`] plus the buffer
/// handed back to the caller (ownership round-trips through the operation).
pub type BufResult<T, B> = (io::Result<T>, B);

/// An owned, stable byte buffer that can back an IO read or write.
///
/// # Safety
/// The backing storage must stay valid and at a **fixed address for as long as a
/// backend owns the buffer during an in-flight op**: from when the backend reads
/// [`buf_ptr`](IoBuf::buf_ptr) / [`buf_mut_ptr`](IoBufMut::buf_mut_ptr) until the
/// op completes (the kernel may read/write it after the call returns). A heap
/// buffer (`Vec`/`BytesMut`/`Bytes`) satisfies this trivially, moving the handle
/// moves a header, not the allocation. An **inline** (stack) buffer ([`ArrayBuf`])
/// satisfies it too if: a completion backend moves the buffer into its op-slab
/// *before* taking the pointer and does not move it again until the CQE, so the
/// address the kernel sees stays fixed for the op.
pub unsafe trait IoBuf: Send + 'static {
    /// The initialized (readable / already-written) bytes.
    ///
    /// The core accessor: pointer and length both derive from it, so an impl is a
    /// one-liner and use-sites get a safe, bounded slice instead of raw ptr+len.
    fn as_init(&self) -> &[u8];

    /// Number of initialized bytes (`as_init().len()`).
    #[inline]
    fn buf_len(&self) -> usize {
        self.as_init().len()
    }

    /// Raw const pointer to the start of the initialized region: for handing an
    /// address to a kernel/FFI sink (io_uring `SEND_ZC`, a TLS BIO). Most code
    /// should prefer [`as_init`](IoBuf::as_init).
    ///
    /// Warning: make sure to read SAFETY rules of [`IoBuf`]
    #[inline]
    fn buf_ptr(&self) -> *const u8 {
        self.as_init().as_ptr()
    }

    /// Restrict this buffer to the sub-range `[begin, end)`, consuming it.
    ///
    /// Used by writers to express "the not-yet-written tail" without copying.
    /// Recover the original buffer with [`Slice::into_inner`].
    ///
    /// The range must lie within the **initialized** region `[0, buf_len)`, the
    /// resulting [`Slice`] reports its whole length as initialized, so slicing into
    /// the uninitialized spare would expose uninitialized bytes as readable.
    /// Panics if the range is out of bounds for [`buf_len`](IoBuf::buf_len).
    fn slice(self, range: impl RangeBounds<usize>) -> Slice<Self>
    where
        Self: Sized,
    {
        #[expect(
            clippy::expect_used,
            reason = "a valid buffer range bound + 1 cannot overflow usize"
        )]
        let begin = match range.start_bound() {
            Bound::Included(&n) => n,
            Bound::Excluded(&n) => n.checked_add(1).expect("slice range out of bounds"),
            Bound::Unbounded => 0,
        };
        #[expect(
            clippy::expect_used,
            reason = "a valid buffer range bound + 1 cannot overflow usize"
        )]
        let end = match range.end_bound() {
            Bound::Included(&n) => n.checked_add(1).expect("slice range out of bounds"),
            Bound::Excluded(&n) => n,
            Bound::Unbounded => self.buf_len(),
        };
        assert!(
            begin <= end && end <= self.buf_len(),
            "slice range out of bounds (must be within the initialized region)"
        );
        Slice {
            buf: self,
            begin,
            end,
        }
    }
}

/// Declare how many leading bytes of a buffer are initialized.
///
/// Split out of [`IoBufMut`] (mirroring compio's `SetLen`) so views like
/// [`Slice`] and [`Uninit`] can forward length-setting without re-implementing the
/// whole mutable-buffer surface.
pub trait SetLen {
    /// Set the initialized length to `len`.
    ///
    /// # Safety
    /// The first `len` bytes must actually be initialized and `len` must be `<=`
    /// the buffer's total capacity.
    unsafe fn set_len(&mut self, len: usize);
}

/// An [`IoBuf`] that can also be written into (i.e. used as a read destination).
///
/// # Safety
/// [`as_uninit`](IoBufMut::as_uninit) must expose the buffer's full backing storage
/// — the initialized prefix `[0, buf_len)` followed by writable spare
/// `[buf_len, capacity)` — and the spare must be safe to write. Same address
/// stability contract as [`IoBuf`].
pub unsafe trait IoBufMut: IoBuf + SetLen {
    /// The full backing storage as possibly-uninitialized bytes: the initialized
    /// prefix `[0, buf_len)` plus the writable spare `[buf_len, capacity)`.
    ///
    /// The core accessor: capacity, the raw pointer, and the read-target spare
    /// all derive from it, and a reader fills [`spare_mut`](IoBufMut::spare_mut)
    /// (a safe `&mut [MaybeUninit<u8>]`) instead of doing raw pointer arithmetic.
    fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>];

    /// Total capacity (`as_uninit().len()`).
    #[inline]
    fn buf_capacity(&mut self) -> usize {
        self.as_uninit().len()
    }

    /// Raw mutable pointer to the start of the backing storage: for a kernel/FFI
    /// read target (io_uring recv). Most code should prefer
    /// [`spare_mut`](IoBufMut::spare_mut).
    ///
    /// Warning: make sure to read SAFETY rules of [`IoBufMut`]
    #[inline]
    fn buf_mut_ptr(&mut self) -> *mut u8 {
        self.as_uninit().as_mut_ptr().cast()
    }

    /// The writable spare tail `[buf_len, capacity)` — the read destination.
    #[inline]
    fn spare_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        let len = self.buf_len();
        &mut self.as_uninit()[len..]
    }

    /// The **initialized** region `[0, buf_len)` as a mutable slice, for an
    /// in-place transform (e.g. decrypting a TLS record inside the very buffer it
    /// arrived in, no copy).
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        let len = self.buf_len();
        // SAFETY: `[0, buf_len)` is initialized.
        unsafe { self.as_uninit()[..len].assume_init_mut() }
    }

    /// A read-target view of just the writable spare `[buf_len, capacity)`.
    ///
    /// Reading into it **appends** to `self` (the view's offset 0 is `self`'s
    /// `buf_len`), so it's how you accumulate on top of the overwrite-from-0 read
    /// primitive,  e.g. `read_exact` loops `read_owned(buf.uninit())`. The owned
    /// analogue of compio's `Uninit`.
    fn uninit(self) -> Uninit<Self>
    where
        Self: Sized,
    {
        let begin = self.buf_len();
        Uninit { buf: self, begin }
    }
}

/// A sub-range view `[begin, end)` of an owned [`IoBuf`], itself an [`IoBuf`].
///
/// Created by [`IoBuf::slice`]; the underlying buffer is recovered with
/// [`into_inner`](Slice::into_inner).
#[derive(Debug)]
pub struct Slice<B> {
    buf: B,
    begin: usize,
    end: usize,
}

impl<B> Slice<B> {
    /// Recover the underlying buffer.
    #[inline]
    pub fn into_inner(self) -> B {
        self.buf
    }
}

// SAFETY: the view points into `buf`'s stable storage and `[begin, end)` was
// checked to be within `buf`'s initialized region in `IoBuf::slice`, so it's a
// valid write source. (A read *target* is a [`Uninit`], not a [`Slice`].)
unsafe impl<B: IoBuf> IoBuf for Slice<B> {
    #[inline]
    fn as_init(&self) -> &[u8] {
        &self.buf.as_init()[self.begin..self.end]
    }
}

/// A read-target view of a buffer's writable spare `[buf_len, capacity)`: reading
/// into it **appends** to the underlying (the view's offset 0 is the underlying's
/// `buf_len`). Created by [`IoBufMut::uninit`]; recover the buffer with
/// [`into_inner`](Uninit::into_inner).
#[derive(Debug)]
pub struct Uninit<B> {
    buf: B,
    begin: usize,
}

impl<B> Uninit<B> {
    /// Recover the underlying buffer, with whatever was read into the spare now
    /// part of its initialized region.
    #[inline]
    pub fn into_inner(self) -> B {
        self.buf
    }
}

// SAFETY: a spare view exposes no readable bytes, `as_init` is empty.
unsafe impl<B: IoBuf> IoBuf for Uninit<B> {
    #[inline]
    fn as_init(&self) -> &[u8] {
        &[]
    }
}

impl<B: SetLen + IoBuf> SetLen for Uninit<B> {
    #[inline]
    unsafe fn set_len(&mut self, len: usize) {
        // `len` is relative to the spare's start, declare `begin + len` init on the
        // underlying buffer.
        unsafe { self.buf.set_len(self.begin + len) };
    }
}

// SAFETY: `[begin, capacity)` of `buf`'s backing is owned, writable spare: same
// stability contract as `buf`.
unsafe impl<B: IoBufMut> IoBufMut for Uninit<B> {
    #[inline]
    fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        let begin = self.begin;
        &mut self.buf.as_uninit()[begin..]
    }
}

/// An owned buffer slot
///
/// The buffer slot threaded through [`poll_read_owned`](AsyncReadOwned::poll_read_owned)
/// / [`poll_write_owned`](AsyncWriteOwned::poll_write_owned). It names *who owns
/// the buffer* during an in-flight op, so the in-flight state is never an
/// ambiguous `None`, and dropping it is always safe:
///
/// - [`Ready`](BufSlot::Ready): the buffer is here, idle; read into / write from it.
/// - [`InFlight`](BufSlot::InFlight): a **completion** backend moved the buffer
///   into its op-slab, the slot holds nothing. Dropping is safe, the leaf reaps it.
/// - [`Parked`](BufSlot::Parked): a **readiness** backend (tokio) keeps the
///   buffer here between polls (it has no kernel op to hold it). Nothing is DMA-ing
///   into it, so dropping is safe too.
///
///
/// # Usage
/// The consumer holds it in a **persistent field**, hands a buffer in once, and it
/// is reused: tokio recycles via `Ready`/`Parked`, a completion backend registers
/// it (`InFlight`) and hands it back. Construct with [`new`](BufSlot::new), read
/// the result via [`ready_mut`](BufSlot::ready_mut). The buffer-carrying variants
/// are constructed only by leaves (via [`park`](BufSlot::park) /
/// [`fill`](BufSlot::fill)), so a consumer can't fish a buffer out mid-op.
#[derive(Debug)]
pub enum BufSlot<B> {
    /// The buffer is here and idle, no op in flight, so it can be read or handed
    /// to a new op. This is both a fresh buffer and one holding a completed result,
    /// the slot tracks where the buffer is, not what's in it.
    Ready(B),
    /// In flight on a completion backend, the buffer is in the leaf's op-slab.
    InFlight,
    /// Held by a readiness backend between polls (buffer present, mid-operation).
    Parked(B),
}

impl<B> BufSlot<B> {
    /// A fresh slot holding `buf`, ready to read into / write from.
    #[inline]
    pub fn new(buf: B) -> Self {
        Self::Ready(buf)
    }

    /// The completed buffer by shared ref, only when idle ([`Ready`](Self::Ready),
    /// the op finished). `None` while a read/write is still in flight (`InFlight`
    /// *or* readiness-held `Parked`): a mid-operation buffer is never handed out for
    /// reading.
    #[inline]
    pub fn ready(&self) -> Option<&B> {
        match self {
            Self::Ready(b) => Some(b),
            _ => None,
        }
    }

    /// The buffer when idle ([`Ready`](Self::Ready)), where the consumer reads
    /// the result after a completed read. `None` while in flight.
    #[inline]
    pub fn ready_mut(&mut self) -> Option<&mut B> {
        match self {
            Self::Ready(b) => Some(b),
            _ => None,
        }
    }

    /// Take the completed buffer, consuming the slot, only when idle
    /// ([`Ready`](Self::Ready), the op finished). `None` if a read/write is still in
    /// flight (`InFlight` *or* readiness-held `Parked`), so a caller can't mistake a
    /// mid-operation buffer for a result. This is the normal "the read/write
    /// returned `Ready`, give me my buffer back" path. To recover the buffer
    /// *regardless* of op state, use [`reclaim`](Self::reclaim).
    #[inline]
    pub fn take_ready(self) -> Option<B> {
        match self {
            Self::Ready(b) => Some(b),
            _ => None,
        }
    }

    /// Recover the buffer whenever it's present (idle `Ready` *or* readiness-held
    /// `Parked`), consuming the slot. `None` only while a completion op owns it
    /// (`InFlight`). For adapters that drive the poll themselves and reclaim the
    /// buffer across a `Pending`/`Err` (e.g. reusing its staging capacity,
    /// or a racing timeout short-circuiting a read): the contents may be
    /// mid-operation, so this is *recovery*, not result extraction, use
    /// [`take_ready`](Self::take_ready) for the latter.
    #[inline]
    pub fn reclaim(self) -> Option<B> {
        match self {
            Self::Ready(b) | Self::Parked(b) => Some(b),
            Self::InFlight => None,
        }
    }

    /// Whether the buffer is idle and here ([`Ready`](Self::Ready)), i.e. it can
    /// be read into / written from right now. `false` means a read/write is still
    /// in flight (`InFlight` on a completion backend, `Parked` on a readiness one)
    /// and must be resumed via the leaf before the buffer is touched again.
    #[inline]
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    /// Take the buffer to drive an op, leaving the slot [`InFlight`](Self::InFlight).
    /// A readiness leaf restores it with [`park`](Self::park)/[`fill`](Self::fill);
    /// a completion leaf leaves it `InFlight` until the op returns it via `fill`.
    #[inline]
    pub fn take(&mut self) -> Option<B> {
        match core::mem::replace(self, Self::InFlight) {
            Self::Ready(b) | Self::Parked(b) => Some(b),
            Self::InFlight => None,
        }
    }

    /// Put the buffer back as idle (a read/write completed).
    #[inline]
    pub fn fill(&mut self, buf: B) {
        *self = Self::Ready(buf);
    }

    /// Park the buffer (a readiness backend holds it across `Pending`).
    #[inline]
    pub fn park(&mut self, buf: B) {
        *self = Self::Parked(buf);
    }
}

/// Read bytes into an owned buffer, returning the buffer with the result.
///
/// The read **overwrites from offset 0** and, on success, sets the initialized
/// length to the bytes read, so reusing a buffer without clearing it is safe.
/// Pass a buffer with capacity (e.g. `Vec::with_capacity(n)`), a zero-capacity
/// buffer has nowhere to read into. To *accumulate* on top of prior bytes instead,
/// read into [`buf.uninit()`](IoBufMut::uninit) (a spare-view that appends).
pub trait AsyncReadOwned {
    /// **The primitive.** Poll a read into the owned buffer in `slot`, returning
    /// the bytes read (`0` = EOF). The buffer is moved *through* the read op:
    ///
    /// - **readiness backend (tokio)**: take the buffer, `poll_read` into it from
    ///   offset 0, put it back, the buffer sits in `slot` across `Pending`.
    /// - **completion backend (io_uring)**: take the buffer, submit the op (the
    ///   op-slab owns it, `slot` left `InFlight`), on the CQE return it filled.
    ///
    /// Zero-copy on both, never lends a borrowed buffer to the kernel. Generic
    /// (so not object-safe), the dyn erasure boundaries add a concrete shim.
    ///
    /// Pass a buffer with capacity, the read overwrites from offset 0 and sets the
    /// initialized length to the bytes read.
    fn poll_read_owned<B: IoBufMut>(
        &mut self,
        cx: &mut Context<'_>,
        slot: &mut BufSlot<B>,
    ) -> Poll<io::Result<usize>>;

    /// Derived async convenience over [`poll_read_owned`](Self::poll_read_owned):
    /// move `buf` in, drive to completion, hand it back filled. **Not a second
    /// impl**: every owned reader gets it for free, relays and `read_exact_into`
    /// use it.
    ///
    /// `async fn read(buf) -> BufResult` is the primitive completion runtimes
    /// (compio / monoio) settled on. We keep it *derived* rather than primitive
    /// because a manual `Future::poll` consumer (e.g. hyper's connection core)
    /// can't drive an `async fn` without boxing its future, so `poll_read_owned`
    /// stays the real primitive.
    fn read_owned<B: IoBufMut>(
        &mut self,
        buf: B,
    ) -> impl Future<Output = BufResult<usize, B>> + Send
    where
        Self: Send,
    {
        async move {
            let mut slot = BufSlot::new(buf);
            let res = poll_fn(|cx| self.poll_read_owned(cx, &mut slot)).await;
            #[expect(
                clippy::expect_used,
                reason = "poll_fn resolved the op, so the slot holds the buffer"
            )]
            let buf = slot
                .reclaim()
                .expect("the op resolved (Ok or Err), leaving the buffer in the slot");
            (res, buf)
        }
    }
}

/// Write bytes from an owned buffer, returning the buffer with the result.
pub trait AsyncWriteOwned {
    /// **The primitive.** Poll a write of the initialized bytes `[0, buf_len)`
    /// of the buffer in `slot`, returning the bytes written. The buffer is moved
    /// *through* the write op (readiness: borrowed-then-restored; completion /
    /// SEND_ZC: moved into the op, `slot` left `InFlight`, returned on the NOTIF) and
    /// left back in `slot` on `Ready`. The caller advances its own cursor by the
    /// returned count.
    fn poll_write_owned<B: IoBuf>(
        &mut self,
        cx: &mut Context<'_>,
        slot: &mut BufSlot<B>,
    ) -> Poll<io::Result<usize>>;

    /// Poll a flush of any buffered data to the underlying sink.
    fn poll_flush_owned(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    /// Poll a shutdown of the write side of this connection.
    fn poll_shutdown_owned(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    /// Hint whether vectored writes are efficient on this writer (mirrors
    /// [`tokio::io::AsyncWrite::is_write_vectored`]), lets a frame encoder pick a
    /// chain threshold. Defaults to `false`, the blanket-over-tokio impl and thin
    /// adapters forward the underlying writer's answer.
    fn is_write_vectored_owned(&self) -> bool {
        false
    }

    // TODO add a dedicated poll_write_owned_vectored

    /// Derived async convenience over [`poll_write_owned`](Self::poll_write_owned):
    /// move `buf` in, issue one write, hand it back with the bytes written. **Not
    /// a second impl**: every owned writer gets it for free.
    ///
    /// `async fn write(buf) -> BufResult` is the primitive completion runtimes
    /// (compio / monoio) settled on. We keep it *derived* rather than primitive
    /// because a manual `Future::poll` consumer (e.g. hyper's connection core)
    /// can't drive an `async fn` without boxing its future, so `poll_write_owned`
    /// stays the real primitive.
    fn write_owned<B: IoBuf>(&mut self, buf: B) -> impl Future<Output = BufResult<usize, B>> + Send
    where
        Self: Send,
    {
        async move {
            let mut slot = BufSlot::new(buf);
            let res = poll_fn(|cx| self.poll_write_owned(cx, &mut slot)).await;
            #[expect(
                clippy::expect_used,
                reason = "poll_fn resolved the op, so the slot holds the buffer"
            )]
            let buf = slot
                .reclaim()
                .expect("the op resolved (Ok or Err), leaving the buffer in the slot");
            (res, buf)
        }
    }

    /// Derived async flush over [`poll_flush_owned`](Self::poll_flush_owned).
    fn flush_owned(&mut self) -> impl Future<Output = io::Result<()>> + Send
    where
        Self: Send,
    {
        async move { poll_fn(|cx| self.poll_flush_owned(cx)).await }
    }

    /// Derived async shutdown over [`poll_shutdown_owned`](Self::poll_shutdown_owned).
    fn shutdown_owned(&mut self) -> impl Future<Output = io::Result<()>> + Send
    where
        Self: Send,
    {
        async move { poll_fn(|cx| self.poll_shutdown_owned(cx)).await }
    }
}

// Every tokio `AsyncRead` is an owned reader for free: `read_owned` is an inlined
// shim over `poll_read` that moves the buffer in and out with no copy. Because
// `read_owned` is uniquely named, this never clashes with `AsyncReadExt::read`.
//
// Coherence: an owned-native backend (io_uring leaf, sans-io TLS stream) impls
// `AsyncReadOwned` directly and therefore must NOT also impl tokio `AsyncRead`,
// or it would overlap this blanket.
impl<T: AsyncRead + Unpin + Send + ?Sized> AsyncReadOwned for T {
    #[inline]
    fn poll_read_owned<B: IoBufMut>(
        &mut self,
        cx: &mut Context<'_>,
        slot: &mut BufSlot<B>,
    ) -> Poll<io::Result<usize>> {
        #[expect(
            clippy::expect_used,
            reason = "readiness never moves the buffer to a leaf, so the slot is filled here"
        )]
        let mut buf = slot
            .take()
            .expect("poll_read_owned: slot empty (readiness never moves the buffer to a leaf)");

        // overwrite-from-0: read into the whole buffer from offset 0 (the ecosystem
        // semantic). Accumulate via `buf.uninit()`, which passes a spare-view here.
        let (res, n) = {
            let mut rb = ReadBuf::uninit(buf.as_uninit());
            let res = Pin::new(&mut *self).poll_read(cx, &mut rb);
            let n = rb.filled().len();
            (res, n)
        };

        // SAFETY: `poll_read` initialized the first `n` bytes of the buffer.
        unsafe { buf.set_len(n) };

        match res {
            Poll::Ready(Ok(())) => {
                slot.fill(buf);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => {
                slot.fill(buf);
                Poll::Ready(Err(e))
            }
            // readiness parks the buffer in the slot across `Pending`.
            Poll::Pending => {
                slot.park(buf);
                Poll::Pending
            }
        }
    }
}

// Every tokio `AsyncWrite` is an owned writer for free (same shim story).
impl<T: AsyncWrite + Unpin + Send + ?Sized> AsyncWriteOwned for T {
    #[inline]
    fn poll_write_owned<B: IoBuf>(
        &mut self,
        cx: &mut Context<'_>,
        slot: &mut BufSlot<B>,
    ) -> Poll<io::Result<usize>> {
        // Take + park a buffer similar to how poll_read_owned works and
        // how a completion based backend would work. This way bugs surface
        // in the same way.
        #[expect(
            clippy::expect_used,
            reason = "readiness never moves the buffer to a leaf, so the slot is filled here"
        )]
        let buf = slot.take().expect("poll_write_owned: slot empty");
        match Pin::new(&mut *self).poll_write(cx, buf.as_init()) {
            Poll::Ready(res) => {
                slot.fill(buf);
                Poll::Ready(res)
            }
            Poll::Pending => {
                slot.park(buf);
                Poll::Pending
            }
        }
    }

    #[inline]
    fn poll_flush_owned(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown_owned(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self).poll_shutdown(cx)
    }

    #[inline]
    fn is_write_vectored_owned(&self) -> bool {
        Self::is_write_vectored(self)
    }
}

// SAFETY: a `Vec`'s heap allocation is stable across moves of the `Vec` handle,
// `len`/`capacity` bound the initialized and total regions; `set_len` is the
// canonical way to declare initialized bytes.
unsafe impl IoBuf for Vec<u8> {
    #[inline]
    fn as_init(&self) -> &[u8] {
        self
    }
}

impl SetLen for Vec<u8> {
    #[inline]
    unsafe fn set_len(&mut self, len: usize) {
        // SAFETY: forwarded contract: caller guarantees `len` bytes are
        // initialized and `len <= capacity()`.
        unsafe { Self::set_len(self, len) };
    }
}

unsafe impl IoBufMut for Vec<u8> {
    #[inline]
    fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        let cap = self.capacity();
        let ptr = self.as_mut_ptr().cast::<MaybeUninit<u8>>();
        // SAFETY: `[0, cap)` is the Vec's allocation, the init prefix stays valid
        // and the spare is writable.
        unsafe { std::slice::from_raw_parts_mut(ptr, cap) }
    }
}

// SAFETY: `BytesMut`'s allocation is stable across moves of the handle.
unsafe impl IoBuf for BytesMut {
    #[inline]
    fn as_init(&self) -> &[u8] {
        self
    }
}

impl SetLen for BytesMut {
    #[inline]
    unsafe fn set_len(&mut self, len: usize) {
        // SAFETY: forwarded contract: caller guarantees `len` bytes are
        // initialized and `len <= capacity()`.
        unsafe { Self::set_len(self, len) };
    }
}

unsafe impl IoBufMut for BytesMut {
    #[inline]
    fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        let cap = self.capacity();
        let ptr = self.as_mut_ptr().cast::<MaybeUninit<u8>>();
        // SAFETY: `[0, cap)` is `BytesMut`'s contiguous allocation, init prefix
        // stays valid and the spare is writable.
        unsafe { std::slice::from_raw_parts_mut(ptr, cap) }
    }
}

// `Bytes` is immutable shared storage: readable but not a valid read target
//
// SAFETY: `Bytes`'s backing storage is stable across moves of the handle.
unsafe impl IoBuf for Bytes {
    #[inline]
    fn as_init(&self) -> &[u8] {
        self
    }
}

/// A fixed-size, **inline** (stack) owned read buffer, no heap allocation.
///
/// The owned analogue of `arrayvec::ArrayVec<u8, N>`: an `[u8; N]` plus an
/// initialized-length counter, so a reader can fill it across multiple polls
/// (`spare_mut()` shrinks as bytes arrive). Backs the fixed-size field readers
/// so a wire-protocol parser reads a small header with zero per-call allocation.
/// io_uring-safe: like any [`IoBuf`] it is moved into the backend's op-slab for the
/// duration of an in-flight op, which pins its address for the kernel.
pub struct ArrayBuf<const N: usize> {
    buf: [MaybeUninit<u8>; N],
    init: usize,
}

impl<const N: usize> ArrayBuf<N> {
    /// A fresh, empty buffer (init `0`, capacity `N`).
    #[inline]
    pub const fn new() -> Self {
        Self {
            buf: [MaybeUninit::uninit(); N],
            init: 0,
        }
    }

    /// Try to recover the backing array.
    #[inline]
    pub fn try_into_array(self) -> Result<[u8; N], Self> {
        if self.init != N {
            return Err(self);
        }

        // SAFETY: `init == N`, so every element is initialized.
        Ok(self.buf.map(|b| unsafe { b.assume_init() }))
    }
}

impl<const N: usize> Default for ArrayBuf<N> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: the inline `[u8; N]` is the backing storage and `init <= N`. Address
// stability across an in-flight op is provided by the op-slab (see `IoBuf`).
unsafe impl<const N: usize> IoBuf for ArrayBuf<N> {
    #[inline]
    fn as_init(&self) -> &[u8] {
        // SAFETY: `[0, init)` is initialized (upheld by `SetLen::set_len`).
        unsafe { self.buf[..self.init].assume_init_ref() }
    }
}

impl<const N: usize> SetLen for ArrayBuf<N> {
    #[inline]
    unsafe fn set_len(&mut self, len: usize) {
        debug_assert!(len <= N);
        self.init = len;
    }
}

unsafe impl<const N: usize> IoBufMut for ArrayBuf<N> {
    #[inline]
    fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        &mut self.buf
    }
}

/// Split an IO into owned read and write halves usable concurrently.
///
/// The blanket impl over tokio IO delegates to [`tokio::io::split`] — whose
/// half-locking already handles concurrent read+write — and the resulting halves
/// are owned for free via the blanket owned impls. An owned-native backend (an
/// io_uring leaf) can implement this directly to split at the ring level.
pub trait SplitIo: Sized {
    /// The owned read half.
    type ReadHalf: AsyncReadOwned + Send;
    /// The owned write half.
    type WriteHalf: AsyncWriteOwned + Send;
    /// Split into owned read and write halves.
    fn split_io(self) -> (Self::ReadHalf, Self::WriteHalf);
}

impl<T: AsyncRead + AsyncWrite + Send> SplitIo for T {
    type ReadHalf = tokio::io::ReadHalf<T>;
    type WriteHalf = tokio::io::WriteHalf<T>;

    #[inline]
    fn split_io(self) -> (Self::ReadHalf, Self::WriteHalf) {
        tokio::io::split(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_buf_slice_rejects_overflowing_bounds() {
        let start = std::panic::catch_unwind(|| {
            b"abc"
                .to_vec()
                .slice((Bound::Excluded(usize::MAX), Bound::Unbounded))
        });
        start.unwrap_err();

        let end = std::panic::catch_unwind(|| {
            b"abc"
                .to_vec()
                .slice((Bound::Unbounded, Bound::Included(usize::MAX)))
        });
        end.unwrap_err();
    }

    #[test]
    fn array_buf_try_into_array_requires_full_init() {
        let mut partial = ArrayBuf::<4>::new();
        unsafe { partial.set_len(2) };
        let partial = partial.try_into_array().unwrap_err();
        assert_eq!(partial.buf_len(), 2);

        let mut full = ArrayBuf::<4>::new();
        full.as_uninit()[..4].copy_from_slice(&[
            MaybeUninit::new(b't'),
            MaybeUninit::new(b'e'),
            MaybeUninit::new(b's'),
            MaybeUninit::new(b't'),
        ]);
        unsafe { full.set_len(4) };

        let Ok(full) = full.try_into_array() else {
            panic!("fully initialized ArrayBuf should convert to an array")
        };
        assert_eq!(full, *b"test");
    }

    #[tokio::test]
    async fn owned_roundtrip_vec() {
        // a tokio duplex half is an owned transport for free (blanket).
        let (mut a, mut b) = tokio::io::duplex(64);

        let (r, wbuf) = a.write_owned(b"hello".to_vec()).await;
        assert_eq!(r.unwrap(), 5);
        // write returns the buffer intact (ownership round-trips, no consume).
        assert_eq!(wbuf, b"hello".to_vec());

        let (r, rbuf) = b.read_owned(Vec::with_capacity(16)).await;
        assert_eq!(r.unwrap(), 5);
        assert_eq!(&rbuf[..], b"hello");
        // set_len set the length to the bytes read.
        assert_eq!(rbuf.len(), 5);
    }

    #[tokio::test]
    async fn owned_read_overwrites_from_zero() {
        let (mut a, mut b) = tokio::io::duplex(64);

        let (w, _) = a.write_owned(b"world".to_vec()).await;
        assert_eq!(w.unwrap(), 5);

        let mut buf = Vec::with_capacity(16);
        buf.extend_from_slice(b"pre-"); // init len 4
        let (r, buf) = b.read_owned(buf).await;
        assert_eq!(r.unwrap(), 5);
        // overwrite-from-0: the read fills from the start, discarding "pre-".
        assert_eq!(&buf[..], b"world");
    }

    #[tokio::test]
    async fn owned_read_into_uninit_appends() {
        let (mut a, mut b) = tokio::io::duplex(64);

        let (w, _) = a.write_owned(b"world".to_vec()).await;
        assert_eq!(w.unwrap(), 5);

        let mut buf = Vec::with_capacity(16);
        buf.extend_from_slice(b"pre-"); // init len 4
        // `uninit()` is the explicit accumulate view: read into the spare.
        let (r, view) = b.read_owned(buf.uninit()).await;
        assert_eq!(r.unwrap(), 5);
        let buf = view.into_inner();
        assert_eq!(&buf[..], b"pre-world");
    }

    #[tokio::test]
    async fn owned_roundtrip_bytes_mut_and_bytes() {
        let (mut a, mut b) = tokio::io::duplex(64);

        // write from an immutable `Bytes` (IoBuf, not IoBufMut).
        let (w, _) = a.write_owned(Bytes::from_static(b"xyz")).await;
        assert_eq!(w.unwrap(), 3);

        let (r, buf) = b.read_owned(BytesMut::with_capacity(8)).await;
        assert_eq!(r.unwrap(), 3);
        assert_eq!(&buf[..], b"xyz");
    }

    #[tokio::test]
    async fn poll_read_owned_reads_then_signals_eof() {
        let (mut a, mut b) = tokio::io::duplex(64);

        let (w, _) = a.write_owned(b"chunk".to_vec()).await;
        w.unwrap();
        // poll_read_owned (blanket) fills the slot buffer.
        let mut slot = BufSlot::new(BytesMut::with_capacity(16));
        let n = core::future::poll_fn(|cx| b.poll_read_owned(cx, &mut slot))
            .await
            .unwrap();
        assert_eq!(&slot.ready_mut().unwrap()[..n], b"chunk");

        // dropping the writer -> EOF -> 0 bytes.
        drop(a);
        let mut slot = BufSlot::new(BytesMut::with_capacity(16));
        let eof = core::future::poll_fn(|cx| b.poll_read_owned(cx, &mut slot))
            .await
            .unwrap();
        assert_eq!(eof, 0);
    }

    #[tokio::test]
    async fn split_io_halves_are_owned_and_concurrent() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (a, mut b) = tokio::io::duplex(64);
        let (mut a_r, mut a_w) = a.split_io();

        // write via the owned write half, read on the plain tokio side.
        let (res, _) = a_w.write_owned(b"split".to_vec()).await;
        res.unwrap();
        let mut got = [0u8; 5];
        b.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"split");

        // read via the owned read half.
        b.write_all(b"back!").await.unwrap();
        let (res, buf) = a_r.read_owned(Vec::with_capacity(8)).await;
        assert_eq!(res.unwrap(), 5);
        assert_eq!(&buf[..], b"back!");
    }
}
