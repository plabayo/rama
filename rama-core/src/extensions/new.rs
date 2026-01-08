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

#[derive(Debug, Clone)]
/// Combined view of all extensions that apply at a specific place
pub struct Extensions {
    stores: Vec<ExtensionStore>,
}

impl Default for Extensions {
    fn default() -> Self {
        Self::new()
    }
}

impl Extensions {
    pub fn new() -> Self {
        let store = ExtensionStore::new("todo".to_owned());
        Self {
            stores: vec![store.clone()],
        }
    }

    pub fn add_new_store(&mut self, store: ExtensionStore) {
        self.stores.push(store.clone());
    }

    pub fn insert<T: ExtensionType>(&self, val: T) {
        self.main_store().insert(val);
    }

    fn main_store(&self) -> &ExtensionStore {
        &self.stores[0]
    }

    // TODO implement this efficienlty for our use case (this is possible with our structure)
    fn unified_view(&self) -> Vec<(Instant, String, StoredExtension)> {
        let mut all_extensions = Vec::new();

        for store in &self.stores {
            all_extensions.extend(
                store
                    .storage
                    .iter()
                    .map(|item| (item.0, store.name.clone(), item.1.clone())),
            );
        }

        // Sort by Instant (the first element of the tuple)
        all_extensions.sort_by_key(|(instant, _, _)| *instant);

        all_extensions
    }

    pub fn get<T: ExtensionType>(&self) -> Option<&T> {
        println!("get {:?}", TypeId::of::<T>());
        self.get_inner::<T>().and_then(|ext| {
            println!("found: {ext:?}");
            let down = ext.downcast_ref::<T>();
            println!("down: {down:?}");
            down
        })
    }

    pub fn get_clone<T: ExtensionType>(&self) -> Option<Arc<T>> {
        println!("get {:?}", TypeId::of::<T>());
        self.get_inner::<T>()
            .and_then(|ext| ext.cloned_downcast::<T>())
    }

    fn get_inner<T: ExtensionType>(&self) -> Option<&StoredExtension> {
        let type_id = TypeId::of::<T>();

        let mut latest: Option<(Instant, &StoredExtension)> = None;

        // TODO improve early stop if instant < found
        println!("searching {type_id:?}");
        for store in &self.stores {
            println!("checking store {store:?}");
            if let Some(found) = store.storage.iter().rev().find(|item| {
                println!("checking item {:?}: {}", item.1, item.1.type_id == type_id);
                item.1.type_id == type_id
            }) {
                match latest {
                    None => latest = Some((found.0, &found.1)),
                    Some((current_instant, _)) if found.0 > current_instant => {
                        latest = Some((found.0, &found.1));
                    }
                    _ => {}
                }
            }
        }

        println!("latest: {latest:?}");
        latest.map(|item| item.1)
    }

    pub fn contains<T: ExtensionType>(&self) -> bool {
        let type_id = TypeId::of::<T>();

        for store in &self.stores {
            if store
                .storage
                .iter()
                .rev()
                .any(|item| item.1.type_id == type_id)
            {
                return true;
            }
        }

        false
    }

    pub fn iter<'a, T: ExtensionType>(&'a self) -> impl Iterator<Item = (Instant, Arc<T>)> + 'a {
        let type_id = TypeId::of::<T>();

        let mut cursors = vec![0; self.stores.len()];

        std::iter::from_fn(move || {
            let mut best_store = None;
            let mut earliest_time = None;

            for (i, store) in self.stores.iter().enumerate() {
                let storage = &store.storage;
                while cursors[i] < storage.len() && storage[cursors[i]].1.type_id != type_id {
                    cursors[i] += 1;
                }

                if cursors[i] == storage.len() {
                    continue;
                }

                let item = &storage[cursors[i]];

                if earliest_time.is_none() || item.0 < earliest_time.unwrap() {
                    earliest_time = Some(item.0);
                    best_store = Some(i);
                }
            }

            if let Some(i) = best_store {
                let item = &self.stores[i].storage[cursors[i]];
                let val = item.1.cloned_downcast::<T>();
                cursors[i] += 1;

                return Some((item.0, val?));
            }

            None
        })
    }

    pub fn extend(&mut self, extensions: Self) {
        let store = extensions.stores.into_iter().next().unwrap();
        self.main_store().extend(store);
    }
}

#[derive(Debug, Clone)]
/// Single extensions store, this is readonly and appendonly, we use &self for everything
pub struct ExtensionStore {
    // again no string later, but for proto type this works
    name: String,
    // we have external crate options here, or we can implement some of these algorithms
    // for now we just do it as simple as possible. But with our setup we can do this much
    // more efficient
    // storage: Arc<ExtensionVec>,
    storage: Arc<AppendOnlyVec<(Instant, StoredExtension), 30, 3>>,
}

impl ExtensionStore {
    pub fn new(name: String) -> Self {
        Self {
            name,
            storage: Default::default(),
        }
    }

    /// Insert a new value in this [`ExtensionStore`]
    pub fn insert<T: ExtensionType>(&self, value: T) {
        let extension = StoredExtension::new(value);
        self.storage.push((Instant::now(), extension));
    }

    /// Extend this [`Extensions`] store with the [`Extension`]s from the provided store
    pub fn extend(&self, extensions: Self) {
        // TODO we need to make sure this insert is orded...
        // Or de we just use timestamp now?
        let now = Instant::now();
        for (_, item) in extensions.storage.iter().cloned() {
            self.storage.push((now, item));
        }
    }
}

#[derive(Clone, Debug)]
/// A [`StoredExtension`] is a type erased item which can be stored in an [`ExtensionStore`]
pub struct StoredExtension {
    type_id: TypeId,
    value: Arc<dyn ExtensionType>,
}

impl StoredExtension {
    /// Create a new [`StoredExtension`]
    fn new<T: ExtensionType>(value: T) -> Self {
        println!("inserting {:?}: {:?}", value, TypeId::of::<T>());
        Self {
            type_id: TypeId::of::<T>(),
            value: Arc::new(value),
        }
    }

    fn cloned_downcast<T: ExtensionType>(&self) -> Option<Arc<T>> {
        let any = self.value.clone() as Arc<dyn Any + Send + Sync>;
        any.clone().downcast::<T>().ok()
    }

    fn downcast_ref<T: ExtensionType>(&self) -> Option<&T> {
        println!("value: {:?}", &self.value);
        let inner_any = self.value.as_ref() as &dyn Any;
        (inner_any).downcast_ref::<T>()
    }
}

pub trait ExtensionType: Any + Send + Sync + std::fmt::Debug + 'static {}

// TODO remove this blacket impl
impl<T: Send + Sync + std::fmt::Debug + 'static> ExtensionType for T {}

mod tests {
    use super::*;

    #[derive(Clone, Debug)]
    struct NoRetry;

    #[derive(Clone, Debug)]
    struct TargetHttpVersion;

    #[derive(Clone, Debug)]
    struct ConnectionInfo;

    #[derive(Clone, Debug)]
    struct RequestInfoInner;

    #[derive(Clone, Debug)]
    struct BrokenConnection;

    #[derive(Clone, Debug)]
    struct IsHealth(bool);

    #[test]
    fn setup() {
        let req_store = ExtensionStore::new("request".to_owned());
        let mut request = Extensions::new();

        request.insert(NoRetry);
        request.insert(TargetHttpVersion);

        println!("request extensions {request:?}");

        // 1. now we go to connector setup
        // 2. we create the extensions for our connector
        // 3. we add request extensions to this, and vice versa
        let conn_store = ExtensionStore::new("connection".to_owned());
        let connection = Extensions::new();

        // We add connector extensions also to our request
        request.add_new_store(connection.main_store().clone());

        // In connector setup now we only edit connection extension
        connection.insert(ConnectionInfo);
        connection.insert(IsHealth(true));

        // We also have access to request to read thing, but all connection specific things
        // should add this point be copied over the connection which should survive a single request
        // flow. Here this would be TargetHttpVersion since this is used by connector.

        // if Some(version) = request.get::<TargetHttpVersion>() {
        //     connection.insert(version)
        // }

        request.insert(RequestInfoInner);

        // This should have the complete view, unified view is basically a combined time sorted view
        // all events/extensions added in correct order
        println!("request extensions: {:#?}", request.unified_view());

        // This should only see intial request extensions and the connection extensions
        println!("connection extensions: {:#?}", connection.unified_view());

        println!("is healthy {:?}", request.get::<IsHealth>());

        // // Now our connection's internal state machine detect it is broken
        // // and inserts this in extensions, our request should also be able to see this
        // connection.insert(BrokenConnection);
        // connection.insert(IsHealth(false));

        // // println!("request extensions: {:#?}", request.unified_view());

        // println!("is healthy {:?}", request.get_clone::<IsHealth>());

        // let history: Vec<_> = request.iter::<IsHealth>().collect();
        // println!("health history {history:#?}");
    }

    #[test]
    fn basic() {
        let mut request = Extensions::new();
        request.insert(IsHealth(true));
        println!("is healthy {:?}", request.get_clone::<IsHealth>());
    }
}

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

use crate::extensions::append_only_vec::AppendOnlyVec;

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
