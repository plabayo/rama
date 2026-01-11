use core::panic;
use itertools::Itertools;
use parking_lot::RwLock;
use std::fmt::Debug;
use std::ptr;
use std::time::Instant;
use std::{
    any::{Any, TypeId},
    sync::Arc,
};

use std::alloc::{Layout, alloc, dealloc};
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

type Element = (Instant, StoredExtension);

#[derive(Debug)]
pub struct ExtensionVec {
    count: AtomicUsize,
    reserved: AtomicUsize,

    // 64 bins for broad architecture support
    data: [AtomicPtr<Element>; 64],
}

impl ExtensionVec {
    pub fn new() -> Self {
        const EMPTY: AtomicPtr<Element> = AtomicPtr::new(ptr::null_mut());
        Self {
            count: AtomicUsize::new(0),
            reserved: AtomicUsize::new(0),
            data: [EMPTY; 64],
        }
    }

    // /// Appends a new extension with the current timestamp.
    // pub fn push<T: ExtensionType>(&self, val: T) -> usize {
    //     let extension = StoredExtension {
    //         type_id: TypeId::of::<T>(),
    //         value: Arc::new(val),
    //     };
    //     self.push_raw((Instant::now(), extension))
    // }

    fn push_raw(&self, element: Element) -> usize {
        let idx = self.reserved.fetch_add(1, Ordering::Relaxed);
        let (array_idx, offset) = indices(idx);

        let mut bucket_ptr = self.data[array_idx as usize].load(Ordering::Acquire);

        if bucket_ptr.is_null() {
            if offset == 0 {
                let layout = Layout::array::<Element>(bin_size(array_idx)).unwrap();
                let new_ptr = unsafe { alloc(layout) } as *mut Element;

                if let Err(found) = self.data[array_idx as usize].compare_exchange(
                    ptr::null_mut(),
                    new_ptr,
                    Ordering::Release,
                    Ordering::Acquire,
                ) {
                    unsafe { dealloc(new_ptr as *mut u8, layout) };
                    bucket_ptr = found;
                } else {
                    bucket_ptr = new_ptr;
                }
            } else {
                let mut failures = 0;
                while bucket_ptr.is_null() {
                    spin_wait(&mut failures);
                    bucket_ptr = self.data[array_idx as usize].load(Ordering::Acquire);
                }
            }
        }

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

    pub fn get(&self, idx: usize) -> Option<&Element> {
        if idx >= self.len() {
            return None;
        }
        let (array, offset) = indices(idx);
        let bucket = self.data[array as usize].load(Ordering::Acquire);
        unsafe { Some(&*bucket.add(offset)) }
    }

    pub fn len(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }
}

// --- Utilities ---

const fn indices(i: usize) -> (u32, usize) {
    let i = i + 8;
    let bin = (usize::BITS - 1) - i.leading_zeros();
    let bin = bin - 3;
    let offset = i - bin_size(bin);
    (bin, offset)
}

const fn bin_size(array: u32) -> usize {
    8 << array
}

fn spin_wait(failures: &mut usize) {
    *failures += 1;
    if *failures <= 10 {
        std::hint::spin_loop();
    } else {
        std::thread::yield_now();
    }
}

impl Drop for ExtensionVec {
    fn drop(&mut self) {
        let length = self.len();
        for i in 0..length {
            let (array, offset) = indices(i);
            let bucket = unsafe { *self.data[array as usize].as_ptr() };
            unsafe {
                ptr::drop_in_place(bucket.add(offset));
            }
        }
        for array in 0..64 {
            let bucket = *self.data[array].get_mut();
            if !bucket.is_null() {
                let layout = Layout::array::<Element>(bin_size(array as u32)).unwrap();
                unsafe { dealloc(bucket as *mut u8, layout) };
            } else {
                break;
            }
        }
    }
}

impl Default for ExtensionVec {
    fn default() -> Self {
        Self::new()
    }
}

use std::ops::Index;

use rama_utils::collections::append_only_vec::AppendOnlyVec;

impl Index<usize> for ExtensionVec {
    type Output = Element;

    fn index(&self, idx: usize) -> &Self::Output {
        // Bounds check + Acquire ordering to ensure data visibility
        assert!(idx < self.len(), "Index out of bounds");

        let (array, offset) = indices(idx);
        // Safety: The len() check above uses Acquire ordering, which synchronizes
        // with the Release store in push_raw. This guarantees the pointer is non-null.
        let bucket = self.data[array as usize].load(Ordering::Relaxed);
        unsafe { &*bucket.add(offset) }
    }
}

impl ExtensionVec {
    /// Returns an iterator over the elements currently in the vector.
    /// The iterator snapshots the length at creation time.
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            vec: self,
            start: 0,
            end: self.len(),
        }
    }
}

/// A double-ended iterator for ExtensionVec
pub struct Iter<'a> {
    vec: &'a ExtensionVec,
    start: usize,
    end: usize,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a Element;

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

impl<'a> DoubleEndedIterator for Iter<'a> {
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

impl<'a> ExactSizeIterator for Iter<'a> {}

impl ExtensionVec {
    /// Internal helper for fast access without re-checking bounds or ordering.
    /// Used by the iterator which already validated indices against a snapshot len.
    unsafe fn get_unchecked(&self, idx: usize) -> &Element {
        let (array, offset) = indices(idx);
        let bucket = self.data[array as usize].load(Ordering::Relaxed);
        unsafe { &*bucket.add(offset) }
    }
}
