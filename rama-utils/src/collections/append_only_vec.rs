#![expect(
    clippy::panic,
    clippy::allow_attributes,
    reason = "derived from the `append-only-vec` crate; matches stdlib panicking conventions"
)]

use crate::std::alloc::handle_alloc_error;
use crate::std::boxed::Box;

use core::cell::UnsafeCell;
use core::fmt;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::ptr;

#[cfg(not(all(loom, test)))]
use crate::std::alloc::{Layout, alloc, dealloc};
#[cfg(not(all(loom, test)))]
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

#[cfg(all(loom, test))]
use loom::{
    alloc::{Layout, alloc, dealloc},
    sync::atomic::{AtomicPtr, AtomicUsize, Ordering},
};

/// Append only vec of items `T`.
///
/// This vec never moves and never removes items. As long as this vec is
/// around, references to all the data it stores stay valid, and items can be
/// added without a mutable reference to it.
///
/// The first `INLINE` items are stored in the vec itself, so a vec that never
/// outgrows them allocates nothing. Further items go to bins that are
/// allocated on demand, each double the size of the one before, starting at
/// `2^BIN_OFFSET` items. The directory of these bins is itself only allocated
/// once the inline items are used up. Capacity is bounded by memory and by
/// [`Self::MAX_LEN`]: `INLINE + 2^BIN_OFFSET * (2^32 - 1)` items, or what a
/// `usize` counts on smaller targets.
///
/// Pushes are not lock-free: items are published in index order, so a push
/// suspended between reserving and publishing its slot delays later pushes
/// until it resumes. Never push from a signal or interrupt handler.
///
/// Every push can carry a tag: [`Self::tags`] is the bitwise or of the tags of
/// all pushed items, which lets a reader skip a vec that cannot hold what it
/// looks for (see [`Self::push_tagged`]).
// `repr(C)`: what readers need first (length, tags) shares a cache line with
// the first inline items.
//
// Publication order (cited by the proofs below): a push gets the directory and
// bin of its slot through `Acquire` loads or CASes of pointers installed by
// `Release` (or `AcqRel`) CASes after their allocation was initialized, writes
// its item, and publishes it with a `Release` CAS of `count` from `idx` to
// `idx + 1`. All later CASes of `count` are read-modify-writes, so they extend
// the release sequence of every earlier one: an `Acquire` load of `count` that
// returns `n` synchronizes-with the publication of every item below `n`. Those
// item writes and the installs of their directory and bins then
// happen-before the load and whatever it happens-before; by write-read
// coherence, loads of `spill` and of directory entries ordered after it
// return the installed pointers, which never change while the vec lives.
#[repr(C)]
pub struct AppendOnlyVec<T, const INLINE: usize = 0, const BIN_OFFSET: u32 = 3> {
    /// Amount of items actually stored in this vec (this is updated when value is stored)
    // Safety invariant: items `0..count` are initialized and owned by the vec,
    // and are never moved, written or dropped while it is shared. `count`
    // grows only through the publication CAS above, so every item below it
    // was published in publication order.
    count: AtomicUsize,
    /// Bitwise or of the tags of all items pushed so far.
    tags: AtomicUsize,
    /// The bins of the items beyond `INLINE`, allocated on first use.
    // Safety invariant: null, or a directory allocated with `spill_layout()`
    // (bin 0 inside it), installed once and freed only when the vec is
    // dropped. Each directory entry (and `far`, and each entry of `far`) is
    // null or installed once with a bin of `bin_size(bin)` items allocated
    // with `Layout::array::<T>` (dangling when `T` is zero sized), or a
    // `Box<FarBins<T>>`, never changed or freed until the vec is dropped.
    spill: AtomicPtr<Spill<T>>,
    /// Amount of items reserved in this vec (this is updated immediately on insert)
    // Safety invariant: every index below `MAX_LEN` is returned by its
    // `fetch_add` to at most one push; a push that gets an index of
    // `MAX_LEN` or more undoes its add, so the value never drops below the
    // number of indices handed out.
    reserved: AtomicUsize,
    // The slots of items `0..INLINE`; see `count` for which are initialized.
    inline: [UnsafeCell<MaybeUninit<T>>; INLINE],
}

/// Spill bins listed in the directory that is allocated with the first bin:
/// with the default `BIN_OFFSET` room for `8 * (2^8 - 1)` items.
const NEAR_BINS: usize = 8;

/// Further spill bins, listed in a second directory allocated on first use:
/// in total room for `8 * (2^32 - 1)` items with the default `BIN_OFFSET`,
/// more than any process holds in memory (and on 32-bit targets more than
/// the address space can index).
const FAR_BINS: usize = 24;

type FarBins<T> = [AtomicPtr<T>; FAR_BINS];

/// The directory of the spill bins. Allocated together with the first bin,
/// which follows it in the same allocation (see [`AppendOnlyVec::spill_layout`]),
/// so its own entry stays null.
#[repr(C)]
struct Spill<T> {
    near: [AtomicPtr<T>; NEAR_BINS],
    far: AtomicPtr<FarBins<T>>,
}

impl<T, const INLINE: usize, const BIN_OFFSET: u32> AppendOnlyVec<T, INLINE, BIN_OFFSET> {
    const INITIAL_BIN_SIZE: usize = (2_usize).pow(BIN_OFFSET);

    /// The most items it holds: what its bins have room for, at most half a
    /// `usize`, so every index and the count past the last fit, and pushes past
    /// the limit, however many at once, undo their reservation without
    /// wrapping it.
    pub const MAX_LEN: usize = {
        let bins = NEAR_BINS + FAR_BINS;
        let spill = if bins >= usize::BITS as usize {
            usize::MAX
        } else {
            ((1_usize << bins) - 1).saturating_mul(Self::INITIAL_BIN_SIZE)
        };
        // A spill index plus the first bin's size must fit, see `spill_indices`.
        let spill = if spill > usize::MAX - Self::INITIAL_BIN_SIZE {
            usize::MAX - Self::INITIAL_BIN_SIZE
        } else {
            spill
        };
        let total = INLINE.saturating_add(spill);
        if total > usize::MAX / 2 {
            usize::MAX / 2
        } else {
            total
        }
    };

    /// Create a new, empty [`AppendOnlyVec`] of `T` items. Allocates nothing.
    ///
    /// ```compile_fail
    /// use rama_utils::collections::AppendOnlyVec;
    /// // This should fail because the first bin is too large for usize
    /// _ = AppendOnlyVec::<usize, 0, 40>::new();
    /// ```
    pub fn new() -> Self {
        const { Self::assert_params() }

        Self {
            count: AtomicUsize::new(0),
            tags: AtomicUsize::new(0),
            spill: AtomicPtr::new(ptr::null_mut()),
            reserved: AtomicUsize::new(0),
            inline: [const { UnsafeCell::new(MaybeUninit::uninit()) }; INLINE],
        }
    }

    /// Write an empty vec to `slot`, without touching its inline item storage.
    ///
    /// Same as writing [`Self::new`] there, minus moving the (uninitialized)
    /// inline storage: for a vec inside a larger allocation that copy is most
    /// of the cost of creating it.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `slot` is non-null, aligned for `Self`,
    /// valid for writes of `size_of::<Self>()` bytes, and not accessed by
    /// anything else during the call. Whatever it held is overwritten without
    /// being dropped. Afterwards `*slot` is an initialized, empty vec.
    pub unsafe fn init_in_place(slot: *mut Self) {
        const { Self::assert_params() }

        // The inline storage is `MaybeUninit`, so leaving it as is gives a
        // valid empty vec once these four fields are written.
        //
        // SAFETY: the place `(*slot).count` stays in bounds of `*slot`, which
        // is non-null, aligned and valid for writes of a whole `Self`
        // (precondition); the same holds for the other fields below.
        let count = unsafe { &raw mut (*slot).count };
        // SAFETY: `write` needs the field pointer aligned for its field and
        // valid for writes (same premises), with nothing else accessing
        // `*slot` during the call (precondition); likewise for the writes
        // below.
        unsafe { count.write(AtomicUsize::new(0)) };
        // SAFETY: see the first place above.
        let tags = unsafe { &raw mut (*slot).tags };
        // SAFETY: see the first write above.
        unsafe { tags.write(AtomicUsize::new(0)) };
        // SAFETY: see the first place above.
        let spill = unsafe { &raw mut (*slot).spill };
        // SAFETY: see the first write above.
        unsafe { spill.write(AtomicPtr::new(ptr::null_mut())) };
        // SAFETY: see the first place above.
        let reserved = unsafe { &raw mut (*slot).reserved };
        // SAFETY: see the first write above.
        unsafe { reserved.write(AtomicUsize::new(0)) };
    }

    /// Pushes an element and returns its index.
    ///
    /// # Panics
    ///
    /// Once it holds [`Self::MAX_LEN`] items, as a `Vec` past its capacity,
    /// leaving the vec as it was: see [`Self::try_push`].
    pub fn push(&self, element: T) -> usize {
        match self.try_push(element) {
            Ok(idx) => idx,
            Err(_) => capacity_overflow(),
        }
    }

    /// Pushes an element and returns its index, or gives it back once it holds
    /// [`Self::MAX_LEN`] items.
    pub fn try_push(&self, element: T) -> Result<usize, T> {
        let idx = self.reserved.fetch_add(1, Ordering::Relaxed);
        if idx >= Self::MAX_LEN {
            // Undone before anything is written: the vec is as it was.
            self.reserved.fetch_sub(1, Ordering::Relaxed);
            return Err(element);
        }
        // Later pushes wait for this one to publish: it must not unwind
        // (e.g. a failed allocation) between reserving and publishing.
        let mut guard = AbortOnUnwind { armed: true };
        let slot = if idx < INLINE {
            self.inline[idx].get().cast::<T>()
        } else {
            let (bin, offset) = Self::spill_indices(idx - INLINE);
            let bucket = self.create_bin_if_needed(bin);
            // SAFETY: `add` needs the result in bounds of the bin's
            // allocation: `bucket` is bin `bin` with room for `bin_size(bin)`
            // items (`create_bin_if_needed`'s safety-usable invariant), and
            // `offset < bin_size(bin)` (`spill_indices`'s). Zero sized items
            // move a dangling pointer by zero bytes.
            unsafe { bucket.add(offset) }
        };

        // SAFETY: `write` needs `slot` valid for writes of a `T` and aligned:
        // it is inline slot `idx` (an `UnsafeCell<MaybeUninit<T>>`, written
        // through `UnsafeCell::get`) or item `offset` of a bin allocated as an
        // array of `T`. No one else accesses it: `reserved` handed `idx` to
        // this push only, readers stop below `count <= idx`, and dropping
        // needs `&mut self`. The slot held no item, so nothing is leaked.
        unsafe { slot.write(element) };

        // Publish in index order, so `count` always covers a prefix of written items.
        let mut failures = 0;
        while self
            .count
            .compare_exchange(idx, idx + 1, Ordering::Release, Ordering::Relaxed)
            .is_err()
        {
            spin_wait(&mut failures);
        }
        guard.armed = false;

        Ok(idx)
    }

    /// Pushes an element tagged with `tag`, and returns its index.
    ///
    /// The tag is added to [`Self::tags`] before the element is published, so
    /// a reader that sees the element also sees its tag: a reader that finds
    /// a tag missing from [`Self::tags`] can skip this vec for it, as no item
    /// with that tag was published before.
    pub fn push_tagged(&self, element: T, tag: usize) -> usize {
        // The load skips the read-modify-write for a tag that is already set.
        if self.tags.load(Ordering::Relaxed) & tag != tag {
            self.tags.fetch_or(tag, Ordering::Relaxed);
        }
        self.push(element)
    }

    /// The bitwise or of the tags of all items pushed so far, see [`Self::push_tagged`].
    #[inline(always)]
    pub fn tags(&self) -> usize {
        self.tags.load(Ordering::Relaxed)
    }

    pub fn get(&self, idx: usize) -> Option<&T> {
        if idx >= self.len() {
            return None;
        }
        // SAFETY: `get_unchecked` needs item `idx` published before this call:
        // `idx` is below the `Acquire` load of `count` in `len` just above.
        Some(unsafe { self.get_unchecked(idx) })
    }

    pub fn is_empty(&self) -> bool {
        self.count.load(Ordering::Acquire) == 0
    }

    pub fn len(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// Returns an iterator over the elements currently in the vector.
    /// The iterator snapshots the length at creation time.
    pub fn iter(&self) -> Iter<'_, T, INLINE, BIN_OFFSET> {
        // Field invariant: `start = 0 <= end = n`, with `n` an `Acquire` load
        // of `count` on this thread, which happens-before any later use of
        // the iterator.
        Iter {
            vec: self,
            start: 0,
            end: self.len(),
        }
    }

    /// Returns the elements currently in the vector as contiguous slices, oldest first.
    ///
    /// The inline items are one slice and every bin is one more, so walking the
    /// elements with two nested loops does the bin arithmetic once per bin
    /// instead of once per element like [`Self::iter`]. Like [`Self::iter`] this
    /// snapshots the length at creation time. The iterator is double ended:
    /// `.rev()` yields the newest slice first.
    pub fn chunks(&self) -> Chunks<'_, T, INLINE, BIN_OFFSET> {
        let len = self.len();
        // Items beyond the inline ones are published, so the directory was
        // installed before `count` covered them.
        let spill = if len > INLINE {
            self.spill.load(Ordering::Acquire)
        } else {
            ptr::null_mut()
        };
        // Field invariant: `len` is an `Acquire` load of `count` on this
        // thread; when `len > INLINE`, the publication order makes `spill`
        // the installed directory; `front = 0 <= back = chunk_count(len)`.
        Chunks {
            vec: self,
            spill,
            len,
            front: 0,
            back: Self::chunk_count(len),
        }
    }

    /// The number of chunks (see [`Self::chunks`]) that hold the first `len` items.
    const fn chunk_count(len: usize) -> usize {
        if len == 0 {
            0
        } else if len <= INLINE {
            1
        } else {
            Self::INLINE_CHUNKS + Self::spill_indices(len - INLINE - 1).0 + 1
        }
    }

    /// Whether chunk 0 is the inline items.
    const INLINE_CHUNKS: usize = if INLINE > 0 { 1 } else { 0 };

    /// Offset of the first spill bin in the allocation of the directory.
    const FIRST_BIN_OFFSET: usize =
        size_of::<Spill<T>>().next_multiple_of(core::mem::align_of::<T>());

    /// The layout of the spill directory together with the first bin.
    ///
    /// # Safety-usable invariant
    ///
    /// Returns the same layout on every call (or panics): its size is not
    /// zero, it holds a `Spill<T>` at offset 0, and, unless `T` is zero sized,
    /// `INITIAL_BIN_SIZE` items of `T` from `FIRST_BIN_OFFSET` (aligned for
    /// `T`).
    fn spill_layout() -> Layout {
        if size_of::<T>() == 0 {
            // zero sized items need no room, nor alignment, for their bin
            return Layout::new::<Spill<T>>();
        }
        let Some(size) = size_of::<T>()
            .checked_mul(Self::INITIAL_BIN_SIZE)
            .and_then(|bin| bin.checked_add(Self::FIRST_BIN_OFFSET))
        else {
            capacity_overflow();
        };
        let align = core::mem::align_of::<Spill<T>>().max(core::mem::align_of::<T>());
        let Ok(layout) = Layout::from_size_align(size, align) else {
            capacity_overflow();
        };
        layout
    }

    /// The first spill bin, which lives in the allocation of the installed
    /// directory `spill`.
    ///
    /// Takes the pointer the directory was allocated as, not a reference to
    /// it: only the former may reach past the directory into the bin.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `spill` points to a live directory
    /// allocated with [`Self::spill_layout`]. The result is the first bin:
    /// room for `INITIAL_BIN_SIZE` items, aligned for `T` (dangling when `T`
    /// is zero sized).
    #[inline(always)]
    unsafe fn first_bin(spill: *mut Spill<T>) -> *mut T {
        if size_of::<T>() == 0 {
            ptr::NonNull::<T>::dangling().as_ptr()
        } else {
            // SAFETY: `add` needs the result in bounds of `spill`'s
            // allocation, which has `spill_layout()` (precondition) and so
            // extends past `FIRST_BIN_OFFSET` (its safety-usable invariant).
            unsafe { spill.cast::<u8>().add(Self::FIRST_BIN_OFFSET).cast::<T>() }
        }
    }

    /// Pointer to spill bin `bin` of the installed directory `spill`, as
    /// listed there (null if not installed).
    ///
    /// # Safety
    ///
    /// The caller must ensure that `spill` is the installed directory of a
    /// vec that stays alive during the call, that its install (the
    /// `AcqRel` CAS that published it, after `alloc_spill` initialized it)
    /// happens-before this call, that `bin < NEAR_BINS + FAR_BINS`, and, for
    /// `bin >= NEAR_BINS`, that the install of the far directory
    /// happens-before this call. Observing the pointer through a `Relaxed`
    /// load is not enough. A bin whose install happens-before this call is
    /// returned as installed.
    #[inline(always)]
    unsafe fn bin_ptr(spill: *mut Spill<T>, bin: usize) -> *mut T {
        if bin == 0 {
            // SAFETY: an installed directory is allocated with `spill_layout()`
            // (`spill` field invariant) and live (precondition).
            unsafe { Self::first_bin(spill) }
        } else if bin < NEAR_BINS {
            // SAFETY: the shared reference to `near[bin]` is to an aligned
            // field of the live, installed directory (precondition, `spill`
            // field invariant), whose initialization happens-before this call
            // (precondition), so the load does not race with it; afterwards
            // it is only accessed through shared references to its atomics
            // until the vec drops.
            unsafe { (*spill).near[bin].load(Ordering::Acquire) }
        } else {
            // SAFETY: as for `near[bin]` above, for the `far` field.
            let far = unsafe { (*spill).far.load(Ordering::Acquire) };
            // SAFETY: the far install happens-before this call (precondition),
            // so by coherence `far` is that installed, live `Box<FarBins<T>>`
            // (`spill` field invariant); `bin - NEAR_BINS < FAR_BINS`.
            unsafe { (*far)[bin - NEAR_BINS].load(Ordering::Acquire) }
        }
    }

    /// The directory entry of spill bin `bin` (not the first) of the installed
    /// directory, installing the far half of it if the bin is listed there.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the directory is installed and its install
    /// happens-before this call, and that `1 <= bin < NEAR_BINS + FAR_BINS`.
    unsafe fn bin_slot(&self, bin: usize) -> &AtomicPtr<T> {
        let spill = self.spill.load(Ordering::Acquire);
        if bin < NEAR_BINS {
            // SAFETY: by the precondition and coherence `spill` is the
            // installed directory, which lives while `self` is borrowed
            // (`spill` field invariant); `near[bin]` is an initialized,
            // aligned field only accessed through shared references.
            return unsafe { &(*spill).near[bin] };
        }
        // SAFETY: as for `near[bin]` above, for the `far` field.
        let far_slot = unsafe { &(*spill).far };
        let mut far = far_slot.load(Ordering::Acquire);
        if far.is_null() {
            let new = Box::into_raw(Box::new(core::array::from_fn::<_, FAR_BINS, _>(|_| {
                AtomicPtr::new(ptr::null_mut())
            })));
            match far_slot.compare_exchange(
                ptr::null_mut(),
                new,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => far = new,
                Err(found) => {
                    // SAFETY: `Box::from_raw` needs a pointer from
                    // `Box::into_raw` that no other owner uses: the failed CAS
                    // did not publish `new`, so this function owns it alone.
                    drop(unsafe { Box::from_raw(new) });
                    far = found;
                }
            }
        }
        // SAFETY: `far` is the installed far directory (our successful CAS, or
        // read by an `Acquire` load or failed CAS from the `AcqRel` CAS that
        // installed it), a live `Box<FarBins<T>>` until the vec drops; the
        // shared reference is to an initialized atomic in it, and
        // `bin - NEAR_BINS < FAR_BINS` by the precondition.
        unsafe { &(*far)[bin - NEAR_BINS] }
    }

    /// The spill directory, allocated on first use together with the first
    /// bin. Cooperative: concurrent callers race to install it and the losers
    /// free theirs.
    ///
    /// # Safety-usable invariant
    ///
    /// Returns the installed directory (non-null), whose install
    /// happens-before this return.
    fn spill_or_create(&self) -> *mut Spill<T> {
        let mut spill = self.spill.load(Ordering::Acquire);
        if spill.is_null() {
            let new = Self::alloc_spill();
            match self.spill.compare_exchange(
                ptr::null_mut(),
                new,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => spill = new,
                Err(found) => {
                    // SAFETY: `drop_in_place` needs a valid, initialized
                    // `Spill` that is not used afterwards: `alloc_spill`
                    // initialized it and the failed CAS did not publish it.
                    unsafe { ptr::drop_in_place(new) };
                    // SAFETY: `dealloc` needs the allocation's layout: it was
                    // allocated with `spill_layout()`, which returns the same
                    // layout on every call; nothing else holds `new`.
                    unsafe { dealloc(new.cast::<u8>(), Self::spill_layout()) };
                    spill = found;
                }
            }
        }
        spill
    }

    /// Allocate an empty directory (all bins null) with room for the first
    /// bin, which is left uninitialized.
    ///
    /// # Safety-usable invariant
    ///
    /// Returns the only pointer to a fresh allocation of `spill_layout()`
    /// holding an initialized `Spill` with every entry null.
    fn alloc_spill() -> *mut Spill<T> {
        let layout = Self::spill_layout();
        #[expect(
            clippy::cast_ptr_alignment,
            reason = "`alloc` aligns to `spill_layout()`, whose alignment is at least `Spill<T>`'s"
        )]
        // SAFETY: `alloc` needs a layout of non-zero size, which
        // `spill_layout()` returns (its safety-usable invariant).
        let new = unsafe { alloc(layout) }.cast::<Spill<T>>();
        if new.is_null() {
            handle_alloc_error(layout);
        }
        let empty = Spill {
            near: core::array::from_fn(|_| AtomicPtr::new(ptr::null_mut())),
            far: AtomicPtr::new(ptr::null_mut()),
        };
        // SAFETY: `write` needs `new` valid for writes of a `Spill<T>` and
        // aligned: the layout holds a `Spill<T>` at offset 0 with at least
        // its alignment, and the allocation is not shared yet.
        unsafe { new.write(empty) };
        new
    }

    /// Returns a pointer to the spill bin `bin`, allocating it if it does not exist.
    ///
    /// Note: this function supports cooperative allocations. Meaning it can be called
    /// in parallel/concurrently. In that case the first one to install the bin wins,
    /// the slower ones de-allocate theirs and use that one instead.
    ///
    /// # Safety-usable invariant
    ///
    /// Returns (or panics) the installed bin `bin`: room for `bin_size(bin)`
    /// items, aligned for `T` (dangling when `T` is zero sized), live until
    /// the vec drops, with its install and the directory's happening-before
    /// this return.
    fn create_bin_if_needed(&self, bin: usize) -> *mut T {
        let spill = self.spill_or_create();
        if bin == 0 {
            // SAFETY: `spill` is the installed, live directory
            // (`spill_or_create`'s safety-usable invariant).
            return unsafe { Self::first_bin(spill) };
        }
        if bin >= NEAR_BINS + FAR_BINS {
            capacity_overflow();
        }
        // SAFETY: the directory install happens-before this point
        // (`spill_or_create`), and `1 <= bin < NEAR_BINS + FAR_BINS` by the
        // checks above.
        let slot = unsafe { self.bin_slot(bin) };
        let ptr = slot.load(Ordering::Acquire);
        if !ptr.is_null() {
            return ptr;
        }
        // Make sure we support zero sized types
        let (layout, new_ptr) = if size_of::<T>() == 0 {
            (None, ptr::NonNull::<T>::dangling().as_ptr())
        } else {
            let Ok(layout) = Layout::array::<T>(Self::bin_size(bin)) else {
                capacity_overflow();
            };
            // SAFETY: `alloc` needs a layout of non-zero size: `T` is not zero
            // sized and `bin_size(bin) >= 1`.
            let ptr = unsafe { alloc(layout).cast::<T>() };
            if ptr.is_null() {
                handle_alloc_error(layout);
            }
            (Some(layout), ptr)
        };

        match slot.compare_exchange(
            ptr::null_mut(),
            new_ptr,
            Ordering::Release,
            Ordering::Acquire,
        ) {
            Ok(_) => new_ptr,
            // Another push installed the bin first: use that one, free ours.
            Err(found) => {
                if let Some(layout) = layout {
                    // SAFETY: `dealloc` needs the allocation's own layout:
                    // `new_ptr` was allocated above with `layout`, and the
                    // failed CAS did not publish it, so nothing else holds it.
                    unsafe { dealloc(new_ptr.cast::<u8>(), layout) };
                }
                found
            }
        }
    }

    /// The position of the spill item `i` (counted from the first item beyond
    /// the inline ones).
    ///
    /// Returns (bin_index, offset_in_this_bin)
    ///
    /// # Safety-usable invariant
    ///
    /// For `i < MAX_LEN - INLINE`, returns `(bin, offset)` with
    /// `offset < bin_size(bin)`: `i + INITIAL_BIN_SIZE` does not overflow
    /// (`MAX_LEN`), and lies in `[bin_size(bin), 2 * bin_size(bin))` for
    /// `bin = ilog2(i + INITIAL_BIN_SIZE) - BIN_OFFSET`.
    const fn spill_indices(i: usize) -> (usize, usize) {
        // offset this so we are aligned for ilog2
        let i = i + Self::INITIAL_BIN_SIZE;

        // remove the offset so we start counting bins from 0
        let bin = (i.ilog2() - BIN_OFFSET) as usize;

        // subtract bin_size to find where in this bin we should be
        let offset = i - Self::bin_size(bin);
        (bin, offset)
    }

    /// Get the size of a spill bin.
    ///
    /// We start with INITIAL_BIN_SIZE slots and then we always double the storage
    /// capacity (always double = bitshift)
    const fn bin_size(idx: usize) -> usize {
        Self::INITIAL_BIN_SIZE << idx
    }

    /// Pointer to the slot of item `idx`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that item `idx` is published and its
    /// publication happens-before this call (see [`Self::get_unchecked`]); with
    /// `&mut` access to the vec this holds for every index below `count`.
    ///
    /// The result points to the initialized item `idx`, in the inline storage
    /// (through `UnsafeCell::get`) or in the bin holding `idx`. It is aligned
    /// and valid for reads and writes of a `T` while the vec is live and not
    /// moved: inline slots move with the vec, bins stay in place until it
    /// drops. It grants no exclusivity: reads are allowed while the item is
    /// not written, and writes or moves out only by a caller that has
    /// exclusive access to the item (no live reference to it).
    unsafe fn slot(&self, idx: usize) -> *mut T {
        if idx < INLINE {
            return self.inline[idx].get().cast::<T>();
        }
        let (bin, offset) = Self::spill_indices(idx - INLINE);
        let spill = self.spill.load(Ordering::Acquire);
        // SAFETY: by the publication order, the initialization and install of
        // the directory, the install of the far directory (if `bin >=
        // NEAR_BINS`) and of bin `bin` happen-before this call, so by
        // coherence `spill` is the installed directory, which lives while
        // `self` is borrowed; `bin < NEAR_BINS + FAR_BINS` as the push of `idx`
        // installed it. So `bin_ptr`'s precondition holds and it returns the
        // installed bin.
        let bucket = unsafe { Self::bin_ptr(spill, bin) };
        // SAFETY: `add` needs the result in bounds of the bin's allocation:
        // the bin has room for `bin_size(bin)` items and `offset <
        // bin_size(bin)` (`spill_indices`, `idx < count <= MAX_LEN`).
        unsafe { bucket.add(offset) }
    }

    /// Get item with idx from this vec
    ///
    /// # Safety
    ///
    /// The caller must ensure that the push that published item `idx`
    /// happens-before this call. That holds when `idx` is below a value that
    /// an `Acquire` load of the length returned ([`Self::len`], or the length
    /// [`Self::iter`] and [`Self::chunks`] read) and that load happens-before
    /// this call, e.g. `idx < self.len()` on this thread. `idx` learned
    /// through a `Relaxed` channel from the pushing thread is not enough.
    ///
    /// The returned reference is valid while `self` is borrowed: published
    /// items are never moved, written or dropped while the vec is shared.
    pub unsafe fn get_unchecked(&self, idx: usize) -> &T {
        // SAFETY: `slot`'s precondition is this function's.
        let slot = unsafe { self.slot(idx) };
        // SAFETY: the shared reference needs `slot` aligned and pointing to an
        // initialized `T` that stays valid and is not written while `self` is
        // borrowed: `slot`'s postcondition (the borrow keeps the vec live and
        // in place), and item `idx` was written before its publication, which
        // happens-before this call (`count` field invariant: never written
        // again while shared).
        unsafe { &*slot }
    }

    /// Check at compile time that the parameters fit the system's pointer width.
    const fn assert_params() {
        if BIN_OFFSET >= usize::BITS / 2 {
            panic!("BIN_OFFSET is too large for the system's pointer width");
        }
    }

    /// Drop the items from `skip_items` on, and free all bins. The first
    /// `skip_items` were moved out already (see [`IntoIterOwned`]).
    ///
    /// Like a `Vec`, the items keep dropping and the storage is freed even
    /// if dropping an item unwinds.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `skip_items <= count`, that items
    /// `..skip_items` were moved out and are not used through the vec again,
    /// and that the vec is not used at all after this call (not even
    /// dropped): its items are dropped and its storage freed.
    unsafe fn drop_manual(&mut self, skip_items: usize) {
        #[cfg(not(all(loom, test)))]
        let len = *self.count.get_mut();

        #[cfg(all(test, loom))]
        let len = self.count.with_mut(|v| *v);

        #[cfg(not(all(loom, test)))]
        let spill = *self.spill.get_mut();

        #[cfg(all(test, loom))]
        let spill = self.spill.with_mut(|ptr| *ptr);

        // Declared first, so it frees the storage after the items dropped.
        // Field invariant: `spill` is this vec's directory (or null), which
        // the precondition lets this call free.
        let _storage = FreeSpill::<T, INLINE, BIN_OFFSET> { spill };
        // Field invariant: items `skip_items..len` are initialized
        // (`count` field invariant, minus those moved out) and, by the
        // precondition, owned by this call alone.
        DropItems {
            vec: self,
            from: skip_items,
            len,
        }
        .drop_run();
    }

    /// The `run` contiguous items from `from`, which must be below `len`:
    /// the rest of `from`'s chunk, at most up to `len`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `from < len` and that [`Self::slot`]'s
    /// precondition holds for `len - 1` (and so for every index below it).
    /// The result points to `run >= 1` slots `from..from + run`, contiguous
    /// in one allocation, with `from + run <= len`, valid as [`Self::slot`]'s
    /// result is (while the vec is live and not moved).
    unsafe fn run(&self, from: usize, len: usize) -> (*mut T, usize) {
        if from < INLINE {
            // From the whole inline array, not one slot: the run spans several.
            // SAFETY: `add` needs the result in bounds of the inline array,
            // which holds `INLINE > from` slots laid out as `T`s
            // (`UnsafeCell<MaybeUninit<T>>` has the layout of `T`).
            let first = unsafe { self.inline.as_ptr().cast::<T>().cast_mut().add(from) };
            return (first, INLINE.min(len) - from);
        }
        let (bin, offset) = Self::spill_indices(from - INLINE);
        // SAFETY: `from < len`, so `slot`'s precondition for `len - 1` covers
        // `from`. The bin has room for `bin_size(bin) - offset` items from it.
        let first = unsafe { self.slot(from) };
        (first, (Self::bin_size(bin) - offset).min(len - from))
    }
}

/// Drops the items `from..len` of a vec, one contiguous run at a time. If
/// dropping one unwinds, the guard made for the rest still drops it.
struct DropItems<'a, T, const INLINE: usize, const BIN_OFFSET: u32> {
    vec: &'a AppendOnlyVec<T, INLINE, BIN_OFFSET>,
    // Safety invariant: `len <= vec.count` with every push to `vec`
    // happening-before; items `from..len` are initialized and owned by this
    // guard alone (dropped by it, used by nothing else).
    from: usize,
    len: usize,
}

impl<T, const INLINE: usize, const BIN_OFFSET: u32> DropItems<'_, T, INLINE, BIN_OFFSET> {
    fn drop_run(&mut self) {
        if self.from >= self.len {
            return;
        }
        // SAFETY: `from < len` (checked above) and `len <= count` with every
        // push happening-before (field invariant): `slot`'s precondition for
        // `len - 1`.
        let (first, run) = unsafe { self.vec.run(self.from, self.len) };
        // Field invariant: hands items `from + run..len` to the new guard.
        let _rest = DropItems {
            vec: self.vec,
            from: self.from + run,
            len: self.len,
        };
        // Field invariant: this guard now owns nothing.
        self.from = self.len;
        // SAFETY: `drop_in_place` needs a valid, aligned slice of initialized
        // `T`s that is not used afterwards: `first..first + run` are
        // contiguous slots in one allocation (`run`'s postcondition) of
        // initialized items that only this call owns (taken from the field
        // invariant above). Whether or not the slice's drop continues after a
        // panic, no item is dropped twice: `_rest` owns only later items.
        unsafe { ptr::drop_in_place(ptr::slice_from_raw_parts_mut(first, run)) };
    }
}

impl<T, const INLINE: usize, const BIN_OFFSET: u32> Drop for DropItems<'_, T, INLINE, BIN_OFFSET> {
    fn drop(&mut self) {
        self.drop_run();
    }
}

/// Frees the spill directory (if any) and every bin it lists when dropped.
struct FreeSpill<T, const INLINE: usize, const BIN_OFFSET: u32> {
    // Safety invariant: null, or a vec's directory (see `spill` of
    // `AppendOnlyVec`) that this guard owns alone, with every install
    // happening-before; its items were dropped or moved out before this guard
    // drops.
    spill: *mut Spill<T>,
}

impl<T, const INLINE: usize, const BIN_OFFSET: u32> Drop for FreeSpill<T, INLINE, BIN_OFFSET> {
    fn drop(&mut self) {
        let spill = self.spill;
        if spill.is_null() {
            return;
        }
        // SAFETY: the `&mut` is to an initialized, aligned field of the live
        // directory, which this guard owns alone (field invariant).
        let near = unsafe { &mut (*spill).near };
        // Bin 0 lives in the directory's allocation. Later bins can be
        // installed out of order by concurrent pushes, so look at all.
        for (bin, slot) in near.iter_mut().enumerate().skip(1) {
            // SAFETY: entry `bin` of the directory is null or bin `bin`
            // (`spill` field invariant of `AppendOnlyVec`), owned by this
            // guard, whose items are gone (field invariant).
            unsafe { AppendOnlyVec::<T, INLINE, BIN_OFFSET>::dealloc_bin(bin, slot) };
        }
        // SAFETY: as for `near`, for the `far` field; `near` is not used again.
        let far = unsafe { &mut (*spill).far };
        #[cfg(not(all(loom, test)))]
        let far = *far.get_mut();

        #[cfg(all(test, loom))]
        let far = far.with_mut(|ptr| *ptr);

        if !far.is_null() {
            // SAFETY: `Box::from_raw` needs a pointer from `Box::into_raw`
            // with no other owner: a non-null `far` is the installed
            // `Box<FarBins<T>>` (`spill` field invariant), owned by this guard.
            let mut far = unsafe { Box::from_raw(far) };
            for (bin, slot) in far.iter_mut().enumerate() {
                // SAFETY: as for the near entries, for bin `NEAR_BINS + bin`.
                unsafe {
                    AppendOnlyVec::<T, INLINE, BIN_OFFSET>::dealloc_bin(NEAR_BINS + bin, slot)
                };
            }
        }
        // SAFETY: `drop_in_place` needs an initialized `Spill` not used
        // afterwards: the directory is owned by this guard and freed next.
        unsafe { ptr::drop_in_place(spill) };
        // SAFETY: `dealloc` needs the allocation's layout: the directory was
        // allocated with `spill_layout()`, which returns the same layout on
        // every call; nothing uses it afterwards.
        unsafe {
            dealloc(
                spill.cast::<u8>(),
                AppendOnlyVec::<T, INLINE, BIN_OFFSET>::spill_layout(),
            )
        };
    }
}

/// Turns an unwind into an abort while armed: a push that unwound between
/// reserving and publishing its slot would leave every later push waiting
/// forever.
///
/// This keeps later pushes live; no unsafe code relies on it, as an
/// unpublished slot is never read or dropped (`count` stays below it). It
/// relies on a panic in a destructor during unwinding aborting, which the
/// `Drop` docs say it "will likely" do; with `panic = "abort"` there is no
/// unwinding at all.
struct AbortOnUnwind {
    armed: bool,
}

impl Drop for AbortOnUnwind {
    fn drop(&mut self) {
        if self.armed {
            // only reached while unwinding, where a second panic aborts
            panic!("append only vec: a push unwound before publishing its item")
        }
    }
}

impl<T, const INLINE: usize, const BIN_OFFSET: u32> AppendOnlyVec<T, INLINE, BIN_OFFSET> {
    /// Free spill bin `bin`, if `slot` lists one. Its items are dropped already.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `slot` is null or holds bin `bin`, as
    /// allocated for it (see `spill` of `AppendOnlyVec`), that this call owns
    /// it, and that nothing uses it afterwards.
    unsafe fn dealloc_bin(bin: usize, slot: &mut AtomicPtr<T>) {
        #[cfg(not(all(loom, test)))]
        let bucket = *slot.get_mut();

        #[cfg(all(test, loom))]
        let bucket = slot.with_mut(|ptr| *ptr);

        if bucket.is_null() || size_of::<T>() == 0 {
            return;
        }
        #[allow(
            clippy::expect_used,
            reason = "this layout was valid when the bin was allocated"
        )]
        let layout = Layout::array::<T>(Self::bin_size(bin)).expect("layout of a bin");

        // SAFETY: `dealloc` needs the allocation's layout: a non-null bin of a
        // non-zero-sized `T` was allocated with `Layout::array::<T>(bin_size(bin))`
        // (precondition), recomputed here; nothing uses it afterwards.
        unsafe { dealloc(bucket.cast::<u8>(), layout) };
    }
}

#[cold]
fn capacity_overflow() -> ! {
    panic!("append only vec capacity overflow")
}

fn spin_wait(failures: &mut usize) {
    #[cfg(not(all(test, loom)))]
    {
        *failures = failures.saturating_add(1);
        if *failures <= 10 {
            core::hint::spin_loop();
        } else {
            #[cfg(feature = "std")]
            std::thread::yield_now();

            #[cfg(not(feature = "std"))]
            core::hint::spin_loop();
        }
    }

    #[cfg(all(test, loom))]
    {
        _ = failures;
        loom::thread::yield_now();
    }
}

// SAFETY: the vec owns its items and its allocations; moving it to another
// thread moves the `T`s there (`T: Send`). Its raw pointers are to storage it
// owns, with no thread affinity.
unsafe impl<T: Send, const INLINE: usize, const BIN_OFFSET: u32> Send
    for AppendOnlyVec<T, INLINE, BIN_OFFSET>
{
}

// SAFETY: through `&AppendOnlyVec` threads get `&T` (`T: Sync`) and push `T`s
// that the owner later drops or moves out on its thread (`T: Send`). Shared
// state is changed only through atomics and through slots that `reserved`
// hands to one push each, published in publication order.
unsafe impl<T: Send + Sync, const INLINE: usize, const BIN_OFFSET: u32> Sync
    for AppendOnlyVec<T, INLINE, BIN_OFFSET>
{
}

impl<T, const INLINE: usize, const BIN_OFFSET: u32> Drop for AppendOnlyVec<T, INLINE, BIN_OFFSET> {
    fn drop(&mut self) {
        // SAFETY: `drop_manual(0)` needs no item moved out, true while the vec
        // owns all of them, and no later use, as the vec is being dropped.
        unsafe { self.drop_manual(0) };
    }
}

impl<T, const INLINE: usize, const BIN_OFFSET: u32> Default
    for AppendOnlyVec<T, INLINE, BIN_OFFSET>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T: fmt::Debug, const INLINE: usize, const BIN_OFFSET: u32> fmt::Debug
    for AppendOnlyVec<T, INLINE, BIN_OFFSET>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

use core::ops::Index;

impl<T, const INLINE: usize, const BIN_OFFSET: u32> Index<usize>
    for AppendOnlyVec<T, INLINE, BIN_OFFSET>
{
    type Output = T;

    fn index(&self, idx: usize) -> &Self::Output {
        // Bounds check + Acquire ordering to ensure data visibility
        assert!(idx < self.len(), "Index out of bounds");

        // SAFETY: `get_unchecked` needs item `idx` published before this call:
        // `idx` is below the `Acquire` load of `count` in `len` just above.
        unsafe { self.get_unchecked(idx) }
    }
}

/// A double-ended iterator over the inline items and the bins of an
/// [`AppendOnlyVec`] as slices, created by [`AppendOnlyVec::chunks`].
pub struct Chunks<'a, T, const INLINE: usize, const BIN_OFFSET: u32> {
    vec: &'a AppendOnlyVec<T, INLINE, BIN_OFFSET>,
    /// The spill directory if the first `len` items reach beyond the inline
    /// ones, else null. Kept as allocated, see [`AppendOnlyVec::first_bin`].
    // Safety invariant: null if `len <= INLINE`, else `vec`'s installed
    // directory.
    spill: *mut Spill<T>,
    /// Length of the vec when the iterator was created.
    // Safety invariant: a value an `Acquire` load of `vec.count` returned,
    // which happens-before every use of this iterator.
    len: usize,
    /// Next chunk to yield from the front.
    // Safety invariant: `front <= back <= chunk_count(len)`.
    front: usize,
    /// One past the last chunk to yield from the back.
    back: usize,
}

impl<'a, T, const INLINE: usize, const BIN_OFFSET: u32> Chunks<'a, T, INLINE, BIN_OFFSET> {
    /// The initialized part of chunk `chunk`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `chunk < chunk_count(self.len)`, so it
    /// holds at least one of the first `self.len` items.
    unsafe fn chunk(&self, chunk: usize) -> &'a [T] {
        type Vec<T, const I: usize, const O: u32> = AppendOnlyVec<T, I, O>;
        let (ptr, count) = if chunk < Vec::<T, INLINE, BIN_OFFSET>::INLINE_CHUNKS {
            let count = core::cmp::min(self.len, INLINE);
            (self.vec.inline.as_ptr().cast::<T>(), count)
        } else {
            let bin = chunk - Vec::<T, INLINE, BIN_OFFSET>::INLINE_CHUNKS;
            // Index of the first spill item of this bin: all earlier bins are full.
            let first = Vec::<T, INLINE, BIN_OFFSET>::bin_size(bin)
                - Vec::<T, INLINE, BIN_OFFSET>::INITIAL_BIN_SIZE;
            let count = core::cmp::min(
                self.len - INLINE - first,
                Vec::<T, INLINE, BIN_OFFSET>::bin_size(bin),
            );
            // Spill chunks are only counted when the items reach the directory.
            if self.spill.is_null() {
                return &[];
            }
            // SAFETY: `self.spill` is the installed directory (field
            // invariant, `len > INLINE` as this is a spill chunk) and lives as
            // long as `'a`; `bin < NEAR_BINS + FAR_BINS` since it holds a
            // published item; that item's publication, and so the
            // initialization and install of the directory, of the far
            // directory and of this bin, happens-before this call (the `len`
            // field invariant, publication order).
            let ptr = unsafe { Vec::<T, INLINE, BIN_OFFSET>::bin_ptr(self.spill, bin) };
            (ptr.cast_const(), count)
        };
        // SAFETY: `from_raw_parts` needs a non-null pointer, aligned for `T`,
        // to `count` initialized `T`s in one allocation, not written for `'a`,
        // with `count * size_of::<T>() <= isize::MAX`. `ptr` is the inline
        // array or this chunk's installed bin (aligned, non-null, dangling for
        // zero sized `T`), and `count` is at most its room. These are items
        // below `len`, published before this call (field invariant), so
        // initialized and never written, moved or dropped while `'a` borrows
        // the vec (`count` field invariant).
        unsafe { core::slice::from_raw_parts(ptr, count) }
    }
}

// SAFETY: a `Chunks` only reads: it yields `&[T]` of published items (sharing
// them needs `T: Sync`) and reaches no push, so no `T` moves between threads.
// Its directory pointer is read-only access to storage `vec` owns.
unsafe impl<T: Sync, const INLINE: usize, const BIN_OFFSET: u32> Send
    for Chunks<'_, T, INLINE, BIN_OFFSET>
{
}

// SAFETY: as for `Send`; `&Chunks` allows no mutation at all.
unsafe impl<T: Sync, const INLINE: usize, const BIN_OFFSET: u32> Sync
    for Chunks<'_, T, INLINE, BIN_OFFSET>
{
}

impl<'a, T, const INLINE: usize, const BIN_OFFSET: u32> Iterator
    for Chunks<'a, T, INLINE, BIN_OFFSET>
{
    type Item = &'a [T];

    fn next(&mut self) -> Option<Self::Item> {
        if self.front < self.back {
            let chunk = self.front;
            self.front += 1;
            // SAFETY: `chunk < back <= chunk_count(len)` (field invariant).
            Some(unsafe { self.chunk(chunk) })
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let chunks = self.back - self.front;
        (chunks, Some(chunks))
    }
}

impl<'a, T, const INLINE: usize, const BIN_OFFSET: u32> DoubleEndedIterator
    for Chunks<'a, T, INLINE, BIN_OFFSET>
{
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front < self.back {
            self.back -= 1;
            // SAFETY: `back` was at most `chunk_count(len)` (field invariant)
            // and was decremented.
            Some(unsafe { self.chunk(self.back) })
        } else {
            None
        }
    }
}

impl<'a, T, const INLINE: usize, const BIN_OFFSET: u32> ExactSizeIterator
    for Chunks<'a, T, INLINE, BIN_OFFSET>
{
}

/// A double-ended iterator for [`AppendOnlyVec`]
pub struct Iter<'a, T, const INLINE: usize, const BIN_OFFSET: u32> {
    vec: &'a AppendOnlyVec<T, INLINE, BIN_OFFSET>,
    // Safety invariant: `start <= end <= n`, where `n` is a value an
    // `Acquire` load of `vec.count` returned, and that load happens-before
    // every use of this iterator.
    start: usize,
    end: usize,
}

impl<'a, T, const INLINE: usize, const BIN_OFFSET: u32> Iterator
    for Iter<'a, T, INLINE, BIN_OFFSET>
{
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start < self.end {
            let pos = self.start;
            self.start += 1;
            // SAFETY: `get_unchecked` needs item `pos` published before this
            // call: `pos < end <= n` (checked above, field invariant), with
            // `n` from an `Acquire` load of `count` that happens-before this
            // call. `start` advanced past `pos`, keeping `start <= end`.
            Some(unsafe { self.vec.get_unchecked(pos) })
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.end - self.start;
        (len, Some(len))
    }
}

impl<'a, T, const INLINE: usize, const BIN_OFFSET: u32> DoubleEndedIterator
    for Iter<'a, T, INLINE, BIN_OFFSET>
{
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.start < self.end {
            self.end -= 1;
            let pos = self.end;
            // SAFETY: as in `next`: `pos = old_end - 1 < old_end <= n`, and
            // `start <= pos = end` keeps the field invariant.
            Some(unsafe { self.vec.get_unchecked(pos) })
        } else {
            None
        }
    }
}

impl<'a, T, const INLINE: usize, const BIN_OFFSET: u32> ExactSizeIterator
    for Iter<'a, T, INLINE, BIN_OFFSET>
{
}

impl<T, const INLINE: usize, const BIN_OFFSET: u32> FromIterator<T>
    for AppendOnlyVec<T, INLINE, BIN_OFFSET>
{
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let this = Self::new();
        for item in iter {
            this.push(item);
        }
        this
    }
}

impl<'a, T, const INLINE: usize, const BIN_OFFSET: u32> IntoIterator
    for &'a AppendOnlyVec<T, INLINE, BIN_OFFSET>
{
    type Item = &'a T;
    type IntoIter = Iter<'a, T, INLINE, BIN_OFFSET>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct IntoIterOwned<T, const INLINE: usize, const BIN_OFFSET: u32> {
    // We need to manually handle dropping of items that we didn't iter over
    vec: ManuallyDrop<AppendOnlyVec<T, INLINE, BIN_OFFSET>>,
    // Safety invariant: `consumed <= vec.count`; items `..consumed` were moved
    // out and items `consumed..count` are still owned by `vec`.
    consumed: usize,
}

impl<T, const INLINE: usize, const BIN_OFFSET: u32> IntoIterator
    for AppendOnlyVec<T, INLINE, BIN_OFFSET>
{
    type Item = T;
    type IntoIter = IntoIterOwned<T, INLINE, BIN_OFFSET>;

    fn into_iter(self) -> Self::IntoIter {
        // Field invariant: nothing moved out yet.
        IntoIterOwned {
            vec: ManuallyDrop::new(self),
            consumed: 0,
        }
    }
}

impl<T, const INLINE: usize, const BIN_OFFSET: u32> Iterator
    for IntoIterOwned<T, INLINE, BIN_OFFSET>
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.consumed < self.vec.len() {
            let idx = self.consumed;
            // Field invariant: item `idx` is moved out below.
            self.consumed += 1;

            // SAFETY: owning the vec, every push to it happens-before this
            // call, and `idx < count`: `slot`'s precondition.
            let slot = unsafe { self.vec.slot(idx) };
            // SAFETY: `ptr::read` needs `slot` valid for reads, aligned and
            // pointing to an initialized `T`: `slot`'s postcondition (the vec
            // is not moved since the call above) with item `idx < count`, not
            // moved out (`consumed` was `idx`). Owning the vec, this has
            // exclusive access to the item. The bitwise copy takes it over;
            // `consumed` past `idx` stops any later drop of it.
            Some(unsafe { ptr::read(slot) })
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.vec.len() - self.consumed;
        (remaining, Some(remaining))
    }
}

impl<T, const INLINE: usize, const BIN_OFFSET: u32> Drop for IntoIterOwned<T, INLINE, BIN_OFFSET> {
    fn drop(&mut self) {
        // SAFETY: `drop_manual` needs `consumed <= count` with items
        // `..consumed` moved out (field invariant), and no later use of the
        // vec: it is in a `ManuallyDrop` that is never dropped or used again.
        unsafe { self.vec.drop_manual(self.consumed) };
    }
}

impl<T, const INLINE: usize, const BIN_OFFSET: u32> Extend<T>
    for AppendOnlyVec<T, INLINE, BIN_OFFSET>
{
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        for item in iter {
            self.push(item);
        }
    }
}

// Since we only need &self to push items we can also implement this for &AppendOnlyVec

impl<T, const INLINE: usize, const BIN_OFFSET: u32> Extend<T>
    for &AppendOnlyVec<T, INLINE, BIN_OFFSET>
{
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        for item in iter {
            self.push(item);
        }
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    mod full {
        use super::*;

        type Zst = AppendOnlyVec<(), 0, 0>;

        /// A vec of zero sized items made to look full, which takes no memory.
        /// It has no directory although `count` covers spill items, so it
        /// breaks the publication invariant: this wrapper (its field private
        /// to this module) only exposes operations that never reach an item,
        /// and never drops the vec, which would visit every pretend item.
        pub(super) struct FullOfZeroSized(std::mem::ManuallyDrop<Zst>);

        impl FullOfZeroSized {
            pub(super) fn new() -> Self {
                let vec = Zst::new();
                vec.reserved.store(Zst::MAX_LEN, Ordering::Relaxed);
                vec.count.store(Zst::MAX_LEN, Ordering::Relaxed);
                Self(std::mem::ManuallyDrop::new(vec))
            }

            /// As if `extra` pushes reserved past the limit and have yet to
            /// undo it: `reserved` stays at or above `MAX_LEN`, so pushes
            /// still return before touching a slot.
            pub(super) fn reserve_past_the_limit(&self, extra: usize) {
                self.0
                    .reserved
                    .store(Zst::MAX_LEN + extra, Ordering::Relaxed);
            }

            pub(super) fn reserved(&self) -> usize {
                self.0.reserved.load(Ordering::Relaxed)
            }

            pub(super) fn len(&self) -> usize {
                self.0.len()
            }

            pub(super) fn try_push(&self) -> Result<usize, ()> {
                self.0.try_push(())
            }

            pub(super) fn push(&self) -> usize {
                self.0.push(())
            }
        }
    }

    use full::FullOfZeroSized;

    #[test]
    fn a_full_vec_gives_the_item_back_and_stays_as_it_was() {
        let vec = FullOfZeroSized::new();
        assert_eq!(vec.try_push(), Err(()));
        assert_eq!(vec.len(), AppendOnlyVec::<(), 0, 0>::MAX_LEN);
        assert_eq!(vec.reserved(), AppendOnlyVec::<(), 0, 0>::MAX_LEN);
    }

    #[test]
    fn pushes_past_the_limit_at_once_never_wrap_the_reservation() {
        let vec = FullOfZeroSized::new();
        vec.reserve_past_the_limit(1_000);
        assert_eq!(vec.try_push(), Err(()));
        assert_eq!(vec.reserved(), AppendOnlyVec::<(), 0, 0>::MAX_LEN + 1_000);
    }

    #[test]
    fn a_push_past_the_limit_panics_without_aborting() {
        let vec = FullOfZeroSized::new();
        let pushed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| vec.push()));
        pushed.unwrap_err();
        assert_eq!(vec.len(), AppendOnlyVec::<(), 0, 0>::MAX_LEN);
    }

    #[test]
    fn the_limit_leaves_room_for_every_index_and_the_count() {
        const {
            assert!(AppendOnlyVec::<(), 0, 0>::MAX_LEN <= usize::MAX / 2);
            // The spill part of the last index, plus the first bin's size.
            assert!(AppendOnlyVec::<u8, 4, 3>::MAX_LEN - 4 <= usize::MAX - 8);
        }
        let (bin, _) =
            AppendOnlyVec::<(), 0, 3>::spill_indices(AppendOnlyVec::<(), 0, 3>::MAX_LEN - 1);
        assert!(bin < NEAR_BINS + FAR_BINS);
    }

    #[test]
    fn we_can_add_items_and_iter_them() {
        let vec: AppendOnlyVec<usize> = AppendOnlyVec::new();
        vec.push(1);
        vec.push(3);

        let mut iter = vec.iter();
        assert_eq!(iter.size_hint().0, 2);
        assert_eq!(*iter.next().unwrap(), 1);
        assert_eq!(*iter.next().unwrap(), 3);
    }

    #[derive(Clone, Debug)]
    struct NoSize;

    #[test]
    fn support_zero_sized_types() {
        let vec: AppendOnlyVec<NoSize> = AppendOnlyVec::new();
        vec.push(NoSize);
        vec.push(NoSize);
        let inline: AppendOnlyVec<NoSize, 2> = AppendOnlyVec::new();
        for _ in 0..20 {
            inline.push(NoSize);
        }
        assert_eq!(inline.iter().count(), 20);
    }

    fn assert_pushes_cross_boundaries<const INLINE: usize, const BIN_OFFSET: u32>() {
        let vec: AppendOnlyVec<usize, INLINE, BIN_OFFSET> = AppendOnlyVec::new();
        for i in 0..300 {
            assert_eq!(vec.push(i), i);
            assert_eq!(vec.len(), i + 1);
            assert_eq!(vec[i], i);
            assert_eq!(vec.get(i + 1), None);
        }
        let items: Vec<usize> = vec.iter().copied().collect();
        assert_eq!(items, (0..300).collect::<Vec<_>>());
        let reversed: Vec<usize> = vec.iter().rev().copied().collect();
        assert_eq!(reversed, (0..300).rev().collect::<Vec<_>>());
    }

    #[test]
    fn push_crosses_inline_and_bin_boundaries_with_stable_order() {
        assert_pushes_cross_boundaries::<0, 3>();
        assert_pushes_cross_boundaries::<1, 0>();
        assert_pushes_cross_boundaries::<4, 3>();
        assert_pushes_cross_boundaries::<5, 2>();
        assert_pushes_cross_boundaries::<16, 1>();
    }

    #[test]
    fn grows_far_beyond_any_fixed_bin_count() {
        // used to be the fixed capacity of an extensions level
        let n: u32 = if cfg!(miri) { 3_000 } else { 40_000 };
        let vec: AppendOnlyVec<u32, 4> = AppendOnlyVec::new();
        for i in 0..n {
            vec.push(i);
        }
        assert_eq!(vec.len(), n as usize);
        assert_eq!(vec[n as usize - 1], n - 1);
        let sum = u64::from(n) * u64::from(n - 1) / 2;
        assert_eq!(vec.iter().map(|v| u64::from(*v)).sum::<u64>(), sum);
    }

    #[test]
    fn spills_into_the_far_directory() {
        // bins of 1, 2, 4, ...: the near directory holds 255 items
        let vec: AppendOnlyVec<u16, 2, 0> = AppendOnlyVec::new();
        for i in 0..1000 {
            vec.push(i);
        }
        // SAFETY: 1000 items exceed the inline ones, so `spill` is the
        // installed directory, live while `vec` is; this thread did the pushes.
        let far = unsafe {
            (*vec.spill.load(Ordering::Relaxed))
                .far
                .load(Ordering::Relaxed)
        };
        assert!(!far.is_null());
        assert_eq!(
            vec.iter().copied().collect::<Vec<_>>(),
            (0..1000).collect::<Vec<_>>()
        );
        assert_eq!(
            vec.chunks().rev().flat_map(|c| c.iter().rev()).count(),
            1000
        );
    }

    #[test]
    fn concurrent_pushes_install_the_far_directory_once() {
        use std::sync::Arc;
        for _ in 0..if cfg!(miri) { 3 } else { 20 } {
            let vec: Arc<AppendOnlyVec<usize, 1, 0>> = Arc::new(AppendOnlyVec::new());
            let writers: Vec<_> = (0..4)
                .map(|t| {
                    let vec = vec.clone();
                    std::thread::spawn(move || {
                        for i in 0..if cfg!(miri) { 80 } else { 300 } {
                            vec.push(t * 1000 + i);
                        }
                    })
                })
                .collect();
            for writer in writers {
                writer.join().unwrap();
            }
            let per = if cfg!(miri) { 80 } else { 300 };
            let mut items: Vec<usize> = vec.iter().copied().collect();
            items.sort_unstable();
            let mut expected: Vec<usize> = (0..4)
                .flat_map(|t| (0..per).map(move |i| t * 1000 + i))
                .collect();
            expected.sort_unstable();
            assert_eq!(items, expected);
        }
    }

    #[test]
    fn inline_items_allocate_nothing_and_drop() {
        use std::rc::Rc;
        let counter = Rc::new(());
        {
            let vec: AppendOnlyVec<Rc<()>, 4> = AppendOnlyVec::new();
            for _ in 0..3 {
                vec.push(counter.clone());
            }
            assert!(vec.spill.load(Ordering::Relaxed).is_null());
            assert_eq!(Rc::strong_count(&counter), 4);
            vec.push(counter.clone());
            assert!(vec.spill.load(Ordering::Relaxed).is_null());
            vec.push(counter.clone());
            assert!(!vec.spill.load(Ordering::Relaxed).is_null());
            assert_eq!(Rc::strong_count(&counter), 6);
        }
        assert_eq!(Rc::strong_count(&counter), 1);
    }

    #[test]
    fn partially_consumed_into_iter_drops_the_rest() {
        use std::rc::Rc;
        let counter = Rc::new(());
        let vec: AppendOnlyVec<Rc<()>, 2, 1> = AppendOnlyVec::new();
        for _ in 0..9 {
            vec.push(counter.clone());
        }
        let mut iter = vec.into_iter();
        let first = iter.next().unwrap();
        let second = iter.next().unwrap();
        let third = iter.next().unwrap();
        assert_eq!(Rc::strong_count(&counter), 10);
        drop(iter);
        assert_eq!(Rc::strong_count(&counter), 4);
        drop((first, second, third));
        assert_eq!(Rc::strong_count(&counter), 1);
    }

    #[test]
    fn a_panicking_item_drop_still_drops_the_others() {
        use std::rc::Rc;
        struct Bomb {
            _alive: Rc<()>,
            explodes: bool,
        }
        impl Drop for Bomb {
            fn drop(&mut self) {
                if self.explodes {
                    panic!("boom");
                }
            }
        }
        let counter = Rc::new(());
        let vec: AppendOnlyVec<Bomb, 2, 1> = AppendOnlyVec::new();
        for i in 0..9 {
            vec.push(Bomb {
                _alive: counter.clone(),
                explodes: i == 3,
            });
        }
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(vec)));
        assert!(unwound.is_err());
        // every item dropped (released its clone) despite the panic
        assert_eq!(Rc::strong_count(&counter), 1);
    }

    #[test]
    fn tags_are_the_union_of_pushed_tags() {
        let vec: AppendOnlyVec<usize, 2> = AppendOnlyVec::new();
        assert_eq!(vec.tags(), 0);
        vec.push_tagged(1, 0b0001);
        vec.push(2);
        vec.push_tagged(3, 0b0100);
        vec.push_tagged(4, 0b0101);
        assert_eq!(vec.tags(), 0b0101);
        assert_eq!(vec.len(), 4);
    }

    #[test]
    fn iter_is_a_snapshot_of_length_at_creation() {
        let vec: AppendOnlyVec<usize, 0, 1> = AppendOnlyVec::new();
        vec.push(1);

        let iter = vec.iter();
        vec.push(2);

        let items: Vec<usize> = iter.copied().collect();
        assert_eq!(items, vec![1]);
        assert_eq!(vec.len(), 2);
    }

    fn assert_chunks_match_iter<const INLINE: usize, const BIN_OFFSET: u32>() {
        let vec: AppendOnlyVec<usize, INLINE, BIN_OFFSET> = AppendOnlyVec::new();
        assert_eq!(vec.chunks().count(), 0);

        for len in 1..=100 {
            vec.push(len - 1);

            let chunks: Vec<&[usize]> = vec.chunks().collect();
            let flat: Vec<usize> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
            assert_eq!(flat, (0..len).collect::<Vec<_>>(), "len {len}");
            assert_eq!(flat, vec.iter().copied().collect::<Vec<_>>());
            assert_eq!(vec.chunks().len(), chunks.len());

            // the inline items are one chunk, every bin one more; only the
            // last chunk may be partially filled, and none is empty
            for (i, chunk) in chunks.iter().enumerate() {
                assert!(!chunk.is_empty());
                let full = match (INLINE, i) {
                    (0, i) => (1 << BIN_OFFSET) << i,
                    (_, 0) => INLINE,
                    (_, i) => (1 << BIN_OFFSET) << (i - 1),
                };
                assert!(
                    chunk.len() == full || i == chunks.len() - 1,
                    "len {len} chunk {i}"
                );
            }

            let reversed: Vec<usize> = vec
                .chunks()
                .rev()
                .flat_map(|c| c.iter().rev().copied())
                .collect();
            assert_eq!(reversed, (0..len).rev().collect::<Vec<_>>());
        }
    }

    #[test]
    fn chunks_are_the_inline_items_and_bins_in_order_and_match_iter() {
        assert_chunks_match_iter::<0, 2>();
        assert_chunks_match_iter::<1, 0>();
        assert_chunks_match_iter::<4, 3>();
        assert_chunks_match_iter::<3, 1>();
    }

    #[test]
    fn chunks_is_a_snapshot_of_length_at_creation() {
        let vec: AppendOnlyVec<usize, 1, 1> = AppendOnlyVec::new();
        vec.push(1);

        let chunks = vec.chunks();
        vec.push(2);
        vec.push(3);

        let items: Vec<usize> = chunks.flat_map(|c| c.iter().copied()).collect();
        assert_eq!(items, vec![1]);
        assert_eq!(vec.chunks().flat_map(|c| c.iter().copied()).count(), 3);
    }

    #[test]
    fn chunks_of_zero_sized_types() {
        let vec: AppendOnlyVec<NoSize, 3> = AppendOnlyVec::new();
        for _ in 0..20 {
            vec.push(NoSize);
        }
        assert_eq!(vec.chunks().map(<[NoSize]>::len).sum::<usize>(), 20);
    }

    #[test]
    fn chunks_meet_in_the_middle_from_both_ends() {
        let vec: AppendOnlyVec<usize, 2, 1> = AppendOnlyVec::new();
        for i in 0..16 {
            vec.push(i);
        }
        let mut chunks = vec.chunks();
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks.next().unwrap(), &[0, 1]);
        assert_eq!(chunks.next_back().unwrap(), &[8, 9, 10, 11, 12, 13, 14, 15]);
        assert_eq!(chunks.next().unwrap(), &[2, 3]);
        assert_eq!(chunks.next_back().unwrap(), &[4, 5, 6, 7]);
        assert!(chunks.next().is_none());
        assert!(chunks.next_back().is_none());
    }

    #[test]
    fn concurrent_pushes_and_reads_across_the_inline_boundary() {
        use std::sync::Arc;
        for _ in 0..if cfg!(miri) { 3 } else { 50 } {
            let vec: Arc<AppendOnlyVec<usize, 4, 1>> = Arc::new(AppendOnlyVec::new());
            let writers: Vec<_> = (0..4)
                .map(|t| {
                    let vec = vec.clone();
                    std::thread::spawn(move || {
                        for i in 0..64 {
                            vec.push_tagged(t * 1000 + i, 1 << t);
                        }
                    })
                })
                .collect();
            let reader = {
                let vec = vec.clone();
                std::thread::spawn(move || {
                    for _ in 0..if cfg!(miri) { 5 } else { 200 } {
                        let seen: usize = vec.chunks().map(<[usize]>::len).sum();
                        assert!(seen <= 256);
                        for (i, item) in vec.iter().enumerate() {
                            assert_eq!(vec[i], *item);
                        }
                    }
                })
            };
            for writer in writers {
                writer.join().unwrap();
            }
            reader.join().unwrap();
            assert_eq!(vec.len(), 256);
            assert_eq!(vec.tags(), 0b1111);
            let mut items: Vec<usize> = vec.iter().copied().collect();
            items.sort_unstable();
            let mut expected: Vec<usize> = (0..4)
                .flat_map(|t| (0..64).map(move |i| t * 1000 + i))
                .collect();
            expected.sort_unstable();
            assert_eq!(items, expected);
        }
    }

    /// A value that counts how many of its kind are alive, to catch leaked
    /// and double dropped items.
    #[derive(Debug)]
    struct Tracked {
        value: u16,
        alive: std::rc::Rc<std::cell::Cell<isize>>,
    }

    impl Tracked {
        fn new(value: u16, alive: &std::rc::Rc<std::cell::Cell<isize>>) -> Self {
            alive.set(alive.get() + 1);
            Self {
                value,
                alive: alive.clone(),
            }
        }
    }

    impl Drop for Tracked {
        fn drop(&mut self) {
            self.alive.set(self.alive.get() - 1);
        }
    }

    /// Push `values` (with their tags) one by one and compare every view of the
    /// vec with a plain `Vec` after each push; then consume `consumed` items
    /// through `into_iter` and drop the rest.
    fn matches_vec_model<const INLINE: usize, const BIN_OFFSET: u32>(
        values: &[(u16, u8)],
        consumed: usize,
    ) -> bool {
        let alive = std::rc::Rc::new(std::cell::Cell::new(0));
        let vec: AppendOnlyVec<Tracked, INLINE, BIN_OFFSET> = AppendOnlyVec::new();
        let mut model: Vec<u16> = Vec::new();
        let mut tags = 0usize;
        for &(value, tag) in values {
            let tag = usize::from(tag);
            if vec.push_tagged(Tracked::new(value, &alive), tag) != model.len() {
                return false;
            }
            model.push(value);
            tags |= tag;

            let values_of =
                |items: Vec<&Tracked>| items.iter().map(|t| t.value).collect::<Vec<_>>();
            let reversed: Vec<u16> = model.iter().rev().copied().collect();
            let chunks: Vec<&[Tracked]> = vec.chunks().collect();
            let chunk_sizes_ok = chunks.iter().enumerate().all(|(i, chunk)| {
                let full = match (INLINE, i) {
                    (0, i) => (1 << BIN_OFFSET) << i,
                    (_, 0) => INLINE,
                    (_, i) => (1 << BIN_OFFSET) << (i - 1),
                };
                !chunk.is_empty() && (chunk.len() == full || i == chunks.len() - 1)
            });
            if vec.len() != model.len()
                || vec.tags() != tags
                || vec.get(model.len()).is_some()
                || (0..model.len()).any(|i| vec.get(i).map(|t| t.value) != Some(model[i]))
                || values_of(vec.iter().collect()) != model
                || values_of(vec.iter().rev().collect()) != reversed
                || values_of(chunks.iter().flat_map(|c| c.iter()).collect()) != model
                || values_of(vec.chunks().rev().flat_map(|c| c.iter().rev()).collect()) != reversed
                || vec.chunks().len() != chunks.len()
                || !chunk_sizes_ok
            {
                return false;
            }
        }
        if alive.get() != model.len() as isize {
            return false;
        }
        let consumed = consumed.min(model.len());
        let mut owned = vec.into_iter();
        let taken: Vec<Tracked> = owned.by_ref().take(consumed).collect();
        if taken.iter().map(|t| t.value).collect::<Vec<_>>() != model[..consumed] {
            return false;
        }
        drop(owned);
        if alive.get() != consumed as isize {
            return false;
        }
        drop(taken);
        alive.get() == 0
    }

    #[test]
    fn behaves_like_a_vec_for_any_push_sequence() {
        #[expect(
            clippy::needless_pass_by_value,
            reason = "quickcheck hands properties owned inputs"
        )]
        fn prop(values: Vec<(u16, u8)>, consumed: usize) -> bool {
            matches_vec_model::<0, 0>(&values, consumed)
                && matches_vec_model::<0, 3>(&values, consumed)
                && matches_vec_model::<1, 0>(&values, consumed)
                && matches_vec_model::<3, 1>(&values, consumed)
                && matches_vec_model::<6, 4>(&values, consumed)
                && matches_vec_model::<8, 3>(&values, consumed)
        }
        quickcheck::QuickCheck::new()
            .tests(if cfg!(miri) { 4 } else { 300 })
            .rng(quickcheck::Gen::new(if cfg!(miri) { 40 } else { 200 }))
            .quickcheck(prop as fn(Vec<(u16, u8)>, usize) -> bool);
    }
}

#[cfg(all(test, loom))]
mod loom_tests {
    use std::sync::Arc;

    use loom::thread;

    use super::*;

    fn create_builder() -> loom::model::Builder {
        let mut builder = loom::model::Builder::new();
        builder.max_branches = 100000;
        builder
    }

    #[test]
    fn basic() {
        create_builder().check(|| {
            let vec: Arc<AppendOnlyVec<usize>> = Arc::new(AppendOnlyVec::new());
            vec.push(8);

            let vec_cl = vec.clone();

            let x = thread::spawn(move || {
                vec_cl.push(16);
            });

            x.join().unwrap();
            assert_eq!(vec.len(), 2);
        });
    }

    #[test]
    fn concurrent_push() {
        create_builder().check(|| {
            let vec = Arc::new(AppendOnlyVec::<usize, 0, 1>::new());

            let vec_cl = vec.clone();
            let t1 = loom::thread::spawn(move || vec_cl.push(1));
            let vec_cl = vec.clone();
            let t2 = loom::thread::spawn(move || vec_cl.clone().push(2));

            t1.join().unwrap();
            t2.join().unwrap();
            assert_eq!(vec.len(), 2);

            // Ensure both values are present (order might vary)
            let sum: usize = vec.iter().sum();
            assert_eq!(sum, 3);
        });
    }

    #[test]
    fn concurrent_push_across_the_inline_boundary() {
        create_builder().check(|| {
            // one inline slot: one of the pushes installs the spill directory
            let vec = Arc::new(AppendOnlyVec::<usize, 1, 0>::new());

            let vec_cl = vec.clone();
            let t1 = loom::thread::spawn(move || vec_cl.push(1));
            let vec_cl = vec.clone();
            let t2 = loom::thread::spawn(move || vec_cl.push(2));

            if let Some(first) = vec.get(0) {
                assert!(*first == 1 || *first == 2);
            }

            t1.join().unwrap();
            t2.join().unwrap();
            assert_eq!(vec.len(), 2);
            assert_eq!(vec.iter().sum::<usize>(), 3);
        });
    }

    #[test]
    fn read_while_push() {
        create_builder().check(|| {
            let vec = Arc::new(AppendOnlyVec::<usize, 0, 1>::new());
            let v1 = vec.clone();

            let t1 = loom::thread::spawn(move || {
                v1.push(42);
            });

            // If len = 1 we should be able to read it, meaning len should only be updated after
            // the data is available
            if vec.len() == 1 {
                assert_eq!(*vec.get(0).unwrap(), 42);
            }

            // Make sure to wait for this thread to finish so loom can cleanup everything while this
            // closure is still active, otherwise it will panick
            t1.join().unwrap();
        });
    }

    #[test]
    fn read_inline_while_push() {
        create_builder().check(|| {
            let vec = Arc::new(AppendOnlyVec::<usize, 2, 1>::new());
            let v1 = vec.clone();

            let t1 = loom::thread::spawn(move || {
                v1.push(42);
            });

            if vec.len() == 1 {
                assert_eq!(*vec.get(0).unwrap(), 42);
            }

            t1.join().unwrap();
        });
    }

    #[test]
    fn chunks_read_while_push() {
        create_builder().check(|| {
            // one inline item then bins of 2 and 4 items: the third push opens a new bin
            let vec = Arc::new(AppendOnlyVec::<usize, 1, 1>::new());
            vec.push(1);
            vec.push(2);
            vec.push(3);
            let v1 = vec.clone();

            let t1 = loom::thread::spawn(move || {
                v1.push(4);
            });

            // Whatever the chunks report as present must be readable, in order.
            let seen: Vec<usize> = vec.chunks().flat_map(|c| c.iter().copied()).collect();
            assert!(seen == [1, 2, 3] || seen == [1, 2, 3, 4], "{seen:?}");

            t1.join().unwrap();
        });
    }

    #[test]
    fn a_seen_item_has_its_tag() {
        create_builder().check(|| {
            let vec = Arc::new(AppendOnlyVec::<usize, 1, 0>::new());
            vec.push_tagged(1, 0b01);
            let v1 = vec.clone();

            let t1 = loom::thread::spawn(move || {
                v1.push_tagged(2, 0b10);
            });

            // A reader that sees the item must also see its tag.
            let len = vec.len();
            let tags = vec.tags();
            if len == 2 {
                assert_eq!(tags, 0b11);
            } else {
                assert_eq!(tags & 0b01, 0b01);
            }

            t1.join().unwrap();
            assert_eq!(vec.tags(), 0b11);
        });
    }

    #[test]
    fn tag_seen_after_a_synchronized_push() {
        use loom::sync::atomic::AtomicBool;
        create_builder().check(|| {
            let vec = Arc::new(AppendOnlyVec::<usize, 1, 0>::new());
            let done = Arc::new(AtomicBool::new(false));
            let (v1, d1) = (vec.clone(), done.clone());

            let t1 = loom::thread::spawn(move || {
                v1.push_tagged(7, 0b100);
                d1.store(true, Ordering::Release);
            });

            // A push that happened-before the check must never be skipped.
            if done.load(Ordering::Acquire) {
                assert_eq!(vec.tags() & 0b100, 0b100);
                assert_eq!(vec.len(), 1);
            }

            t1.join().unwrap();
        });
    }

    #[derive(Clone, Debug)]
    struct NoSize;

    #[test]
    fn zero_sized_types() {
        create_builder().check(|| {
            let vec = AppendOnlyVec::<NoSize, 1, 1>::new();

            // Zero sized types should not cause memory leaks, or alloc errors
            vec.push(NoSize);
            vec.push(NoSize);
            vec.push(NoSize);
        });
    }

    #[test]
    fn drop_of_partial_consumed_into_iter() {
        create_builder().check(|| {
            let vec = AppendOnlyVec::<String, 1, 1>::new();
            vec.push("a".to_owned());
            vec.push("b".to_owned());
            vec.push("c".to_owned());
            vec.push("d".to_owned());

            let mut iter = vec.into_iter();

            let item = iter.next();
            assert_eq!(item.unwrap(), "a");

            // This should de-allocate all remaining items and the buckets
            drop(iter);
        });
    }
}
