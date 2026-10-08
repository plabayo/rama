#![expect(
    clippy::panic,
    clippy::multiple_unsafe_ops_per_block,
    clippy::allow_attributes,
    reason = "derived from the `append-only-vec` crate; matches stdlib panicking conventions"
)]

use crate::std::alloc::handle_alloc_error;

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
/// once the inline items are used up. There is no capacity limit short of
/// running out of memory.
///
/// Every push can carry a tag: [`Self::tags`] is the bitwise or of the tags of
/// all pushed items, which lets a reader skip a vec that cannot hold what it
/// looks for (see [`Self::push_tagged`]).
// `repr(C)`: what readers need first (length, tags) shares a cache line with
// the first inline items.
#[repr(C)]
pub struct AppendOnlyVec<T, const INLINE: usize = 0, const BIN_OFFSET: u32 = 3> {
    /// Amount of items actually stored in this vec (this is updated when value is stored)
    count: AtomicUsize,
    /// Bitwise or of the tags of all items pushed so far.
    tags: AtomicUsize,
    /// The bins of the items beyond `INLINE`, allocated on first use.
    spill: AtomicPtr<Spill<T>>,
    /// Amount of items reserved in this vec (this is updated immediately on insert)
    reserved: AtomicUsize,
    inline: [UnsafeCell<MaybeUninit<T>>; INLINE],
}

/// Number of spill bins: with the default `BIN_OFFSET` room for
/// `8 * (2^32 - 1)` items, more than any process holds in memory (and on
/// 32-bit targets more than the address space can index).
const SPILL_BINS: usize = 32;

/// The directory of the spill bins. Allocated together with the first bin,
/// which follows it in the same allocation (see [`AppendOnlyVec::spill_layout`]),
/// so its own entry stays null.
#[repr(C)]
struct Spill<T> {
    bins: [AtomicPtr<T>; SPILL_BINS],
}

impl<T, const INLINE: usize, const BIN_OFFSET: u32> AppendOnlyVec<T, INLINE, BIN_OFFSET> {
    const INITIAL_BIN_SIZE: usize = (2_usize).pow(BIN_OFFSET);

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

    /// Pushes an element and returns its index.
    pub fn push(&self, element: T) -> usize {
        let idx = self.reserved.fetch_add(1, Ordering::Relaxed);
        let slot = if idx < INLINE {
            self.inline[idx].get().cast::<T>()
        } else {
            let (bin, offset) = Self::spill_indices(idx - INLINE);
            let bucket = self.create_bin_if_needed(bin);
            // Safety: the bin holds `bin_size(bin)` items, and `offset` is below that.
            unsafe { bucket.add(offset) }
        };

        // Safety:
        // - the slot is in bounds of the inline items or of an allocated bin
        // - `reserved` handed this index to this push only
        unsafe {
            slot.write(element);
        }

        // Publish in index order, so `count` always covers a prefix of written items.
        let mut failures = 0;
        while self
            .count
            .compare_exchange(idx, idx + 1, Ordering::Release, Ordering::Relaxed)
            .is_err()
        {
            spin_wait(&mut failures);
        }

        idx
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
        // Safety: this is safe because we check if idx is within bounds
        unsafe { Some(self.get_unchecked(idx)) }
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
    fn spill_layout() -> Layout {
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
    #[inline(always)]
    fn first_bin(spill: *mut Spill<T>) -> *mut T {
        if size_of::<T>() == 0 {
            ptr::NonNull::<T>::dangling().as_ptr()
        } else {
            // Safety: the first bin starts at this offset of the directory's allocation.
            unsafe { spill.cast::<u8>().add(Self::FIRST_BIN_OFFSET).cast::<T>() }
        }
    }

    /// Pointer to spill bin `bin` of the installed directory `spill`; the bin
    /// must be installed.
    #[inline(always)]
    fn bin_ptr(spill: *mut Spill<T>, bin: usize) -> *mut T {
        if bin == 0 {
            Self::first_bin(spill)
        } else {
            // Safety: an installed directory lives as long as the vec.
            unsafe { (*spill).bins[bin].load(Ordering::Acquire) }
        }
    }

    /// The spill directory, allocated on first use together with the first
    /// bin. Cooperative: concurrent callers race to install it and the losers
    /// free theirs.
    fn spill_or_create(&self) -> *mut Spill<T> {
        let mut spill = self.spill.load(Ordering::Acquire);
        if spill.is_null() {
            let layout = Self::spill_layout();
            let new = Self::alloc_spill(layout);
            match self.spill.compare_exchange(
                ptr::null_mut(),
                new,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => spill = new,
                Err(found) => {
                    // Safety: `new` was just allocated with this layout and never shared.
                    unsafe {
                        ptr::drop_in_place(new);
                        dealloc(new.cast::<u8>(), layout);
                    }
                    spill = found;
                }
            }
        }
        spill
    }

    /// Allocate an empty directory (all bins null) with room for the first bin.
    #[cfg(not(all(loom, test)))]
    fn alloc_spill(layout: Layout) -> *mut Spill<T> {
        // Safety: the layout holds the directory, so it is not zero sized.
        let new = unsafe { crate::std::alloc::alloc_zeroed(layout) };
        if new.is_null() {
            handle_alloc_error(layout);
        }
        // All bits zero is a directory of null bins.
        new.cast::<Spill<T>>()
    }

    /// Allocate an empty directory (all bins null) with room for the first bin.
    #[cfg(all(loom, test))]
    fn alloc_spill(layout: Layout) -> *mut Spill<T> {
        // Safety: the layout holds the directory, so it is not zero sized.
        let new = unsafe { alloc(layout) }.cast::<Spill<T>>();
        if new.is_null() {
            handle_alloc_error(layout);
        }
        // Safety: the allocation starts with room for an aligned directory.
        unsafe {
            new.write(Spill {
                bins: core::array::from_fn(|_| AtomicPtr::new(ptr::null_mut())),
            });
        }
        new
    }

    /// Returns a pointer to the spill bin `bin`, allocating it if it does not exist.
    ///
    /// Note: this function supports cooperative allocations. Meaning it can be called
    /// in parallel/concurrently. In that case the first one to install the bin wins,
    /// the slower ones de-allocate theirs and use that one instead.
    fn create_bin_if_needed(&self, bin: usize) -> *mut T {
        let spill = self.spill_or_create();
        if bin == 0 {
            return Self::first_bin(spill);
        }
        if bin >= SPILL_BINS {
            capacity_overflow();
        }
        // Safety: an installed directory lives as long as the vec.
        let slot = unsafe { &(*spill).bins[bin] };
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
            // Safety: `T` is not zero sized, so neither is the layout
            let ptr = unsafe { alloc(layout) as *mut T };
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
                    // Safety:
                    // - We just allocated this ptr so it exists
                    // - Layout matches the exact layout of creation
                    unsafe { dealloc(new_ptr as *mut u8, layout) };
                }
                found
            }
        }
    }

    /// The position of the spill item `i` (counted from the first item beyond
    /// the inline ones).
    ///
    /// Returns (bin_index, offset_in_this_bin)
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
    /// The slot must exist: `idx` is below a length read from `count` (with
    /// `Acquire`), or below `reserved` with exclusive access to the vec.
    unsafe fn slot(&self, idx: usize) -> *mut T {
        if idx < INLINE {
            return self.inline[idx].get().cast::<T>();
        }
        let (bin, offset) = Self::spill_indices(idx - INLINE);
        // Safety: the item exists, so the directory and its bin were installed
        // before `count` (or `reserved`) covered it.
        unsafe { Self::bin_ptr(self.spill.load(Ordering::Acquire), bin).add(offset) }
    }

    /// Get item with idx from this vec
    ///
    /// # Safety
    /// This function is safe if idx < self.len()
    pub unsafe fn get_unchecked(&self, idx: usize) -> &T {
        // Safety: this is safe if idx < self.len()
        unsafe { &*self.slot(idx) }
    }

    /// Check at compile time that the parameters fit the system's pointer width.
    const fn assert_params() {
        if BIN_OFFSET >= usize::BITS / 2 {
            panic!("BIN_OFFSET is too large for the system's pointer width");
        }
    }

    /// Drop the items from `skip_items` on, and free all bins. The first
    /// `skip_items` were moved out already (see [`IntoIterOwned`]).
    fn drop_manual(&mut self, skip_items: usize) {
        #[cfg(not(all(loom, test)))]
        let len = *self.count.get_mut();

        #[cfg(all(test, loom))]
        let len = self.count.with_mut(|v| *v);

        for idx in skip_items..len {
            // Safety:
            // - idx is below the published length and we have exclusive access
            // - every item is dropped once, the moved out ones are skipped
            unsafe { ptr::drop_in_place(self.slot(idx)) };
        }

        #[cfg(not(all(loom, test)))]
        let spill = *self.spill.get_mut();

        #[cfg(all(test, loom))]
        let spill = self.spill.with_mut(|ptr| *ptr);

        if spill.is_null() {
            return;
        }
        if size_of::<T>() != 0 {
            // Safety: we have exclusive access to the installed directory.
            let bins = unsafe { &mut (*spill).bins };
            // Bin 0 lives in the directory's allocation. Later bins can be
            // installed out of order by concurrent pushes, so look at all.
            for (bin, slot) in bins.iter_mut().enumerate().skip(1) {
                #[cfg(not(all(loom, test)))]
                let bucket = *slot.get_mut();

                #[cfg(all(test, loom))]
                let bucket = slot.with_mut(|ptr| *ptr);

                if bucket.is_null() {
                    continue;
                }
                #[allow(
                    clippy::expect_used,
                    reason = "this layout was valid when the bin was allocated"
                )]
                let layout = Layout::array::<T>(Self::bin_size(bin)).expect("layout of a bin");

                // Safety:
                // - We allocated this ptr with this exact layout
                // - nobody else can access the vec anymore
                unsafe { dealloc(bucket as *mut u8, layout) };
            }
        }
        // Safety: allocated with this layout, and nobody else can access the vec anymore.
        unsafe {
            ptr::drop_in_place(spill);
            dealloc(spill.cast::<u8>(), Self::spill_layout());
        }
    }
}

#[cold]
fn capacity_overflow() -> ! {
    panic!("append only vec capacity overflow")
}

fn spin_wait(failures: &mut usize) {
    #[cfg(not(all(test, loom)))]
    {
        *failures += 1;
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

// Safety:
// - This vec is Send if and only if all items send
unsafe impl<T: Send, const INLINE: usize, const BIN_OFFSET: u32> Send
    for AppendOnlyVec<T, INLINE, BIN_OFFSET>
{
}

// Safety:
// - This vec is Sync if and only if all items Sync
// - But it also needs Send for the entire collection to be sync
unsafe impl<T: Send + Sync, const INLINE: usize, const BIN_OFFSET: u32> Sync
    for AppendOnlyVec<T, INLINE, BIN_OFFSET>
{
}

impl<T, const INLINE: usize, const BIN_OFFSET: u32> Drop for AppendOnlyVec<T, INLINE, BIN_OFFSET> {
    fn drop(&mut self) {
        self.drop_manual(0);
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

        // Safety: we just check if idx is within bounds
        unsafe { self.get_unchecked(idx) }
    }
}

/// A double-ended iterator over the inline items and the bins of an
/// [`AppendOnlyVec`] as slices, created by [`AppendOnlyVec::chunks`].
pub struct Chunks<'a, T, const INLINE: usize, const BIN_OFFSET: u32> {
    vec: &'a AppendOnlyVec<T, INLINE, BIN_OFFSET>,
    /// The spill directory if the first `len` items reach beyond the inline
    /// ones, else null. Kept as allocated, see [`AppendOnlyVec::first_bin`].
    spill: *mut Spill<T>,
    /// Length of the vec when the iterator was created.
    len: usize,
    /// Next chunk to yield from the front.
    front: usize,
    /// One past the last chunk to yield from the back.
    back: usize,
}

impl<'a, T, const INLINE: usize, const BIN_OFFSET: u32> Chunks<'a, T, INLINE, BIN_OFFSET> {
    /// The initialized part of chunk `chunk`, which must hold at least one of the first `self.len` elements.
    fn chunk(&self, chunk: usize) -> &'a [T] {
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
            // The bin holds published items, so it was installed before `count` covered them.
            let ptr = Vec::<T, INLINE, BIN_OFFSET>::bin_ptr(self.spill, bin);
            (ptr.cast_const(), count)
        };
        // Safety:
        // - `len` was read with `Acquire` from `count`, which is only advanced after the
        //   element (and its bin) was written, so the first `count` slots of this chunk are
        //   initialized (a zero sized bin is dangling but aligned)
        // - elements are never removed or moved while the vec is borrowed
        unsafe { core::slice::from_raw_parts(ptr, count) }
    }
}

// Safety: yields shared slices of the items only, like `&[T]` iterators.
unsafe impl<T: Sync, const INLINE: usize, const BIN_OFFSET: u32> Send
    for Chunks<'_, T, INLINE, BIN_OFFSET>
{
}

// Safety: yields shared slices of the items only, like `&[T]` iterators.
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
            Some(self.chunk(chunk))
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
            Some(self.chunk(self.back))
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
            // Safety: We are within the snapshot bounds captured at creation
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
            // Safety: We are within the snapshot bounds captured at creation
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
    consumed: usize,
}

impl<T, const INLINE: usize, const BIN_OFFSET: u32> IntoIterator
    for AppendOnlyVec<T, INLINE, BIN_OFFSET>
{
    type Item = T;
    type IntoIter = IntoIterOwned<T, INLINE, BIN_OFFSET>;

    fn into_iter(self) -> Self::IntoIter {
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
            self.consumed += 1;

            // Safety: This is safe because consume < total, and since we own this
            // structure no one else can change this
            unsafe { Some(ptr::read(self.vec.slot(idx))) }
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
        self.vec.drop_manual(self.consumed);
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
        for _ in 0..if cfg!(miri) { 1 } else { 50 } {
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
