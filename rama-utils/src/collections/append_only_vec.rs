use std::ptr;

#[cfg(not(all(loom, test)))]
use std::{
    alloc::{Layout, alloc, dealloc},
    sync::atomic::{AtomicPtr, AtomicUsize, Ordering},
};

#[cfg(all(loom, test))]
use loom::{
    alloc::{Layout, alloc, dealloc},
    sync::atomic::{AtomicPtr, AtomicUsize, Ordering},
};

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

        // Only allocate a bin if offset = 0. This means there will only ever be one thread
        // that allocates a buffer.

        // Note that create_bin_if_needed supports cooperative allocation, so in case we ever
        // which to use that, we just need to always call create_bin_if_needed regardless of offset.
        // Also note that we do already use the cooperative logic in case reserve() is used.

        // The pros and cons of either approach are:
        // Not cooperative: single allocation, but other threads need to use spin_wait until this allocation is finished
        // Cooperative: potential of many allocations for the same bin (dropped after, so only short spike), who-ever is fastest wins

        // One first sight cooperative seems nicer, but also note that our idx and length logic is sequential, so even
        // if we make the allocation cooperative and not blocking, we will mostly be moving the spin_wait to that step.
        // For our use case we also don't expect many (if any) concurrent/parallel pushes to this vec.

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

    // NOTE: right now we don't support reserve since it's actually quite complex to implement,
    // and there are many different ways of doing if for a datastructure like this which has
    // shared push() access. This is fine for our use case since this AppendOnlyVec never
    // re-allocates. If we ever need reserve() in the future it's definetely possible to add it,
    // but for now I prefer a simple (and hopefully bugfree) datastructure.

    // Eg some questions for reserve:
    // - Does reserve() allocate slots for the caller only, or is this best effort
    // - Does it return a size hint of what was reserved, if so what hint
    // - Does calling it multiple times reserve new blocks, or do we consider not used blocks also.
    //   In case we need to support calling this multiple times we will need another Atomic to track this.
    // - Is reserving cooperative with push(), or do we need synchronisation between the two

    // pub fn reserve(&self, amount: usize) -> usize {}

    pub fn get(&self, idx: usize) -> Option<&T> {
        if idx >= self.len() {
            return None;
        }
        // Safety: this is safe because we check if idx is within bounds
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

    /// Returns a pointer to the bin with bin_idx. If this bin does not exist it will be created.
    ///
    /// Note: this functions supports cooperative allocations. Meaning it can be called
    /// in parallel/concurrently. In that case the first one to update `self.data[bin_idx]` will win.
    /// The slower ones will de-allocate and use that pointer instead.
    fn create_bin_if_needed(&self, bin_idx: usize) -> *mut T {
        let mut ptr = self.data[bin_idx].load(Ordering::Acquire);
        if ptr.is_null() {
            // Make sure we support zero sized traits
            let (layout, new_ptr) = if std::mem::size_of::<T>() == 0 {
                (None, std::ptr::NonNull::<T>::dangling().as_ptr())
            } else {
                let layout = Layout::array::<T>(Self::bin_size(bin_idx)).unwrap();
                (Some(layout), unsafe { alloc(layout) as *mut T })
            };

            match self.data[bin_idx].compare_exchange(
                ptr::null_mut(),
                new_ptr,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => ptr = new_ptr,
                // If another thread already updated data[bin_idx], use that bin, and de-allocate
                // the bin we just allocated
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
    const fn indices(i: usize) -> (usize, usize) {
        // offset this so we are alligned for ilog2
        let i = i + Self::INITIAL_BIN_SIZE;

        // remove the offset so we start counting bins from 0
        let bin = (i.ilog2() - BIN_OFFSET) as usize;

        // substract bin_size to find where in this bin we should be
        let offset = i - Self::bin_size(bin);
        (bin, offset)
    }

    /// Get the size of a bin.
    ///
    /// We start with INITIAL_BIN_SIZE slots and then we always double the storage
    /// capacity (alwasy double = bitshift)
    const fn bin_size(idx: usize) -> usize {
        Self::INITIAL_BIN_SIZE << idx
    }

    /// Get item with idx from this vec
    ///
    /// Safety: this function is safe if idx < self.len()
    pub unsafe fn get_unchecked(&self, idx: usize) -> &T {
        let (array, offset) = Self::indices(idx);
        let bucket = self.data[array as usize].load(Ordering::Acquire);
        unsafe { &*bucket.add(offset) }
    }
}

fn spin_wait(failures: &mut usize) {
    #[cfg(not(all(test, loom)))]
    {
        *failures += 1;
        if *failures <= 10 {
            std::hint::spin_loop();
        } else {
            std::thread::yield_now();
        }
    }

    #[cfg(all(test, loom))]
    {
        let _ = failures;
        loom::thread::yield_now();
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
        #[cfg(not(all(loom, test)))]
        let mut remaining = *self.count.get_mut();

        #[cfg(all(test, loom))]
        let mut remaining = self.count.with_mut(|v| *v);

        let is_zst = std::mem::size_of::<T>() == 0;

        for (i, atomic_ptr) in self.data.iter_mut().enumerate() {
            #[cfg(not(all(loom, test)))]
            let bucket_ptr = *atomic_ptr.get_mut();

            #[cfg(all(test, loom))]
            let bucket_ptr = atomic_ptr.with_mut(|ptr| *ptr);

            // Before `reserve()` was added we also stopped if remaining == 0`. However
            // with reserve it's possible that we already created bins that have no items
            // in them, so make sure to also clean those up.
            if bucket_ptr.is_null() {
                break;
            }

            let bin_cap = Self::bin_size(i);
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

#[cfg(test)]
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
            let vec = Arc::new(AppendOnlyVec::<usize, 2, 1>::new());

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
    fn read_while_push() {
        create_builder().check(|| {
            let vec = Arc::new(AppendOnlyVec::<usize, 2, 1>::new());
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

    // reserve() was removed because it's actually quite tricky to implement, but in case we ever
    // add it again, this test can be used for it

    // #[test]
    // fn reserve_and_push() {
    //     create_builder().check(|| {
    //         let vec = Arc::new(AppendOnlyVec::<usize, 5, 1>::new());
    //         let v1 = vec.clone();
    //         let v2 = vec.clone();

    //         // Both of these will race to allocate, but it should handle that
    //         let t1 = loom::thread::spawn(move || v1.reserve(10));
    //         let t2 = loom::thread::spawn(move || v2.push(100));

    //         t1.join().unwrap();
    //         t2.join().unwrap();
    //     });
    // }

    #[derive(Clone, Debug)]
    struct NoSize;

    #[test]
    fn zero_sized_types() {
        create_builder().check(|| {
            let vec = AppendOnlyVec::<NoSize, 5, 1>::new();

            // Zero sized types should not cause memory leaks, or alloc errors
            vec.push(NoSize);
            vec.push(NoSize);
        });
    }
}
