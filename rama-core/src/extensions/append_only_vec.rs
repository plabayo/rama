use std::alloc::{Layout, alloc, dealloc};
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

#[derive(Debug)]
/// Append only vec of items `T`.
///
/// This vec will never re-allocate and never remove items. This means
/// that as long as this vec is around, we can have valid references to
/// all the data it stores. This also means that we can add items to the
/// vec without having a mutable reference to it.
///
///
/// AMOUNT_OF_BINS is total amount of item bins (=arrays). Each bin has double
/// the capacity then the one before, so even with a low number here,
/// we should be able to store a huge amount of items.
///
/// BIN_OFFSET calculates the offset of the first bin. Effectively this mean our
/// first bin will have 2^BIN_OFFSET size.
pub struct AppendOnlyVec<T, const AMOUNT_OF_BINS: usize = 32, const BIN_OFFSET: u32 = 3> {
    count: AtomicUsize,
    reserved: AtomicUsize,

    data: [AtomicPtr<T>; AMOUNT_OF_BINS],
}

impl<T, const AMOUNT_OF_BINS: usize, const BIN_OFFSET: u32>
    AppendOnlyVec<T, AMOUNT_OF_BINS, BIN_OFFSET>
{
    const INITIAL_BIN_SIZE: usize = (2 as usize).pow(BIN_OFFSET);

    pub fn new() -> Self {
        Self {
            count: AtomicUsize::new(0),
            reserved: AtomicUsize::new(0),
            data: std::array::from_fn(|_| AtomicPtr::new(std::ptr::null_mut())),
        }
    }

    pub fn push(&self, element: T) -> usize {
        let idx = self.reserved.fetch_add(1, Ordering::Relaxed);
        let (array_idx, offset) = Self::indices(idx);

        let bucket_ptr = if offset == 0 {
            self.create_bin_if_needed(array_idx as usize)
        } else {
            let mut failures = 0;
            let mut ptr = self.data[array_idx as usize].load(Ordering::Acquire);
            while ptr.is_null() {
                spin_wait(&mut failures);
                ptr = self.data[array_idx as usize].load(Ordering::Acquire);
            }
            ptr
        };

        unsafe {
            bucket_ptr.add(offset).write(element);
        }

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

    pub fn reserve(&self, additional: usize) {
        let current_reserved = self.reserved.load(Ordering::Relaxed);
        let target_idx = current_reserved.saturating_add(additional);
        if target_idx == 0 {
            return;
        }

        let (max_bin, _) = Self::indices(target_idx - 1);
        for bin_idx in 0..=max_bin {
            if bin_idx >= AMOUNT_OF_BINS as u32 {
                break;
            }
            self.create_bin_if_needed(bin_idx as usize);
        }
    }

    pub fn get(&self, idx: usize) -> Option<&T> {
        if idx >= self.len() {
            return None;
        }
        unsafe { Some(self.get_unchecked(idx)) }
    }

    pub fn len(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// Returns the maximum number of elements this configuration can hold.
    /// Total capacity = initial_bin_size * (2^AMOUNT_OF_BINS - 1)
    pub const fn capacity(&self) -> usize {
        Self::INITIAL_BIN_SIZE * ((1 << AMOUNT_OF_BINS) - 1)
    }

    /// Returns an iterator over the elements currently in the vector.
    /// The iterator snapshots the length at creation time.
    pub fn iter(&self) -> Iter<'_, T, AMOUNT_OF_BINS, BIN_OFFSET> {
        Iter {
            vec: self,
            start: 0,
            end: self.len(),
        }
    }

    /// Internal helper to ensure a bin is allocated
    fn create_bin_if_needed(&self, bin_idx: usize) -> *mut T {
        let mut ptr = self.data[bin_idx].load(Ordering::Acquire);
        if ptr.is_null() {
            let (layout, new_ptr) = if std::mem::size_of::<T>() == 0 {
                (None, std::ptr::NonNull::<T>::dangling().as_ptr())
            } else {
                let layout = Layout::array::<T>(Self::bin_size(bin_idx as u32)).unwrap();
                (Some(layout), unsafe { alloc(layout) as *mut T })
            };

            match self.data[bin_idx].compare_exchange(
                ptr::null_mut(),
                new_ptr,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => ptr = new_ptr,
                Err(found) => {
                    if let Some(layout) = layout {
                        unsafe { dealloc(new_ptr as *mut u8, layout) };
                    }
                    ptr = found;
                }
            }
        }
        ptr
    }

    /// Calculate the position in our data structure
    ///
    /// Returns (bin_index, offset_in_this_bin)
    const fn indices(i: usize) -> (u32, usize) {
        // offset this so we are alligned for ilog2
        let i = i + Self::INITIAL_BIN_SIZE;

        // remove the offset so we start counting bins from 0
        let bin = i.ilog2() - BIN_OFFSET;

        // substract bin_size to find where in this bin we should be
        let offset = i - Self::bin_size(bin);
        (bin, offset)
    }

    /// Get the size of a bin.
    ///
    /// We start with INITIAL_BIN_SIZE slots and then we always double the storage
    /// capacity (alwasy double = bitshift)
    const fn bin_size(array: u32) -> usize {
        Self::INITIAL_BIN_SIZE << array
    }

    pub unsafe fn get_unchecked(&self, idx: usize) -> &T {
        let (array, offset) = Self::indices(idx);
        let bucket = self.data[array as usize].load(Ordering::Acquire);
        unsafe { &*bucket.add(offset) }
    }
}

fn spin_wait(failures: &mut usize) {
    *failures += 1;
    if *failures <= 10 {
        std::hint::spin_loop();
    } else {
        std::thread::yield_now();
    }
}

unsafe impl<T: Send, const AMOUNT_OF_BINS: usize, const BIN_OFFSET: u32> Send
    for AppendOnlyVec<T, AMOUNT_OF_BINS, BIN_OFFSET>
{
}
unsafe impl<T: Sync, const AMOUNT_OF_BINS: usize, const BIN_OFFSET: u32> Sync
    for AppendOnlyVec<T, AMOUNT_OF_BINS, BIN_OFFSET>
{
}

impl<T, const AMOUNT_OF_BINS: usize, const BIN_OFFSET: u32> Drop
    for AppendOnlyVec<T, AMOUNT_OF_BINS, BIN_OFFSET>
{
    fn drop(&mut self) {
        let mut remaining = *self.count.get_mut();
        let is_zst = std::mem::size_of::<T>() == 0;

        for (i, atomic_ptr) in self.data.iter_mut().enumerate() {
            let bucket_ptr = *atomic_ptr.get_mut();
            if bucket_ptr.is_null() || remaining == 0 {
                break;
            }

            let bin_cap = Self::bin_size(i as u32);
            let to_drop = std::cmp::min(remaining, bin_cap);

            // Drop individual elements in the bucket
            unsafe {
                for offset in 0..to_drop {
                    ptr::drop_in_place(bucket_ptr.add(offset));
                }
            }

            // Deallocate the bucket itself is not zst
            if !is_zst {
                let layout = Layout::array::<T>(bin_cap).unwrap();
                unsafe { dealloc(bucket_ptr as *mut u8, layout) };
            }

            remaining -= to_drop;
        }
    }
}

impl<T, const AMOUNT_OF_BINS: usize, const BIN_OFFSET: u32> Default
    for AppendOnlyVec<T, AMOUNT_OF_BINS, BIN_OFFSET>
{
    fn default() -> Self {
        Self::new()
    }
}

use std::ops::Index;

impl<T, const AMOUNT_OF_BINS: usize, const BIN_OFFSET: u32> Index<usize>
    for AppendOnlyVec<T, AMOUNT_OF_BINS, BIN_OFFSET>
{
    type Output = T;

    fn index(&self, idx: usize) -> &Self::Output {
        // Bounds check + Acquire ordering to ensure data visibility
        assert!(idx < self.len(), "Index out of bounds");

        unsafe { self.get_unchecked(idx) }
    }
}

impl<T, const AMOUNT_OF_BINS: usize, const BIN_OFFSET: u32>
    AppendOnlyVec<T, AMOUNT_OF_BINS, BIN_OFFSET>
{
}

/// A double-ended iterator for ExtensionVec
pub struct Iter<'a, T, const AMOUNT_OF_BINS: usize, const BIN_OFFSET: u32> {
    vec: &'a AppendOnlyVec<T, AMOUNT_OF_BINS, BIN_OFFSET>,
    start: usize,
    end: usize,
}

impl<'a, T, const AMOUNT_OF_BINS: usize, const BIN_OFFSET: u32> Iterator
    for Iter<'a, T, AMOUNT_OF_BINS, BIN_OFFSET>
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

impl<'a, T, const AMOUNT_OF_BINS: usize, const BIN_OFFSET: u32> DoubleEndedIterator
    for Iter<'a, T, AMOUNT_OF_BINS, BIN_OFFSET>
{
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.start < self.end {
            self.end -= 1;
            let pos = self.end;
            Some(unsafe { self.vec.get_unchecked(pos) })
        } else {
            None
        }
    }
}

impl<'a, T, const AMOUNT_OF_BINS: usize, const BIN_OFFSET: u32> ExactSizeIterator
    for Iter<'a, T, AMOUNT_OF_BINS, BIN_OFFSET>
{
}

impl<T, const AMOUNT_OF_BINS: usize, const BIN_OFFSET: u32> FromIterator<T>
    for AppendOnlyVec<T, AMOUNT_OF_BINS, BIN_OFFSET>
{
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let this = Self::new();
        for item in iter {
            this.push(item);
        }
        this
    }
}
