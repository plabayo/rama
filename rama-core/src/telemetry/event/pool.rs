use core::cell::{RefCell, UnsafeCell};
use core::mem::MaybeUninit;
use core::ptr::NonNull;

use parking_lot::Mutex;
use thread_local::ThreadLocal;

use crate::std::{boxed::Box, vec::Vec};

const FIRST_PAGE: usize = 32;
const MAX_PAGE: usize = 4096;
const BATCH: usize = 64;

/// Storage for the state a [`SpanAdapter`] keeps per span, owned by the core.
///
/// A value put in keeps its address until it is taken out, so a span holds a
/// pointer instead of a key, and reading it costs no lookup. Slots are reused
/// through a free list per thread, with batches handed over through a shared
/// list, so a span that opens on one thread and closes on another does not
/// starve the opening thread.
///
/// The memory is only ever added to: pages stay where they are until the pool
/// itself is dropped. Values still in the pool when that happens are leaked,
/// which is why this is meant for span adapters that live as long as the
/// process.
///
/// [`SpanAdapter`]: super::SpanAdapter
pub(super) struct StatePool<T: Send> {
    // Safety invariant: every slot of `pages` is either uninit and in exactly
    // one list of `free` or `shared`, or init and behind exactly one live
    // `ErasedSlotPtr`.
    pages: Mutex<Vec<Box<[Slot<T>]>>>,
    free: ThreadLocal<RefCell<Vec<SlotPtr<T>>>>,
    shared: Mutex<Vec<Vec<SlotPtr<T>>>>,
}

#[repr(transparent)]
struct Slot<T>(UnsafeCell<MaybeUninit<T>>);

struct SlotPtr<T>(NonNull<Slot<T>>);

// SAFETY: a slot pointer is only stored inside the pool that owns its page, so
// it never outlives that page. Moving the right to use that address to another
// thread is sound as long as `T` may move between threads too.
unsafe impl<T: Send> Send for SlotPtr<T> {}

/// A `SlotPtr` without its type, the handle to a slot that holds a value.
///
/// Not clonable, so the pool can rely on exactly one handle per value. A span
/// keeps one per span adapter and hands it back when it closes.
pub(super) struct ErasedSlotPtr(NonNull<()>);

// SAFETY: the handle is an address, not a reference, and the pool it belongs
// to is `Sync`. Reading or taking the value behind it is `unsafe`, and its
// contract is what keeps a take apart from every read, not this impl.
unsafe impl Send for ErasedSlotPtr {}
// SAFETY: see the `Send` impl; sharing the handle grants no access by itself.
unsafe impl Sync for ErasedSlotPtr {}

impl core::fmt::Debug for ErasedSlotPtr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("ErasedSlotPtr")
            .field(&self.0.as_ptr())
            .finish()
    }
}

// SAFETY: by the invariant on `pages` every slot has one owner at a time: the
// free list that holds it, or the handle `insert` returned. Only the owner
// writes it. Values move between threads through `take`, hence `T: Send`, and
// several threads may `get` the same value at once, hence `T: Sync`. The auto
// impl would only ask for `T: Send`, as every field sits behind a `Mutex` or a
// `ThreadLocal`.
unsafe impl<T: Send + Sync> Sync for StatePool<T> {}

impl<T: Send> Default for StatePool<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Send> StatePool<T> {
    /// An empty pool. The first insert allocates the first page.
    #[must_use]
    pub(super) fn new() -> Self {
        Self {
            pages: Mutex::new(Vec::new()),
            free: ThreadLocal::new(),
            shared: Mutex::new(Vec::new()),
        }
    }

    /// Put a value in the pool and get its handle.
    pub(super) fn insert(&self, value: T) -> ErasedSlotPtr {
        let slot = self.claim();
        let cell = cell_of(slot.0);

        // SAFETY: by the invariant on `pages` a claimed slot is in no list and
        // behind no handle, so this thread is its only owner until the handle
        // below exists. The page it lives in stays put for the life of the pool.
        unsafe { (*cell).write(value) };

        ErasedSlotPtr(slot.0.cast())
    }

    /// Read the value behind a handle.
    ///
    /// # Safety
    ///
    /// `ptr` must come from [`insert`](Self::insert) on this pool.
    #[expect(
        clippy::unused_self,
        reason = "the returned reference borrows the pool that keeps the value alive"
    )]
    pub(super) unsafe fn get<'a>(&'a self, ptr: &'a ErasedSlotPtr) -> &'a T {
        let slot = ptr.0.cast();
        let cell = cell_of::<T>(slot);

        // SAFETY: by the contract above the slot belongs to this pool, which
        // keeps its page alive. `take` consumes the handle, so while `ptr`
        // is borrowed for `'a` the value is not taken, and by the invariant on
        // `pages` its slot is not written either.
        let value = unsafe { &*cell };

        // SAFETY: a handle that exists was not taken yet, so by the invariant
        // on `pages` the slot holds its value.
        unsafe { value.assume_init_ref() }
    }

    /// Take the value behind a handle out of the pool.
    ///
    /// # Safety
    ///
    /// `ptr` must come from [`insert`](Self::insert) on this pool. Consuming
    /// the handle means this can happen only once per value, as long as the
    /// handle was not forged.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "consuming the handle is what makes a second take impossible"
    )]
    pub(super) unsafe fn take(&self, ptr: ErasedSlotPtr) -> T {
        let slot = ptr.0.cast();
        let cell = cell_of::<T>(slot);

        // SAFETY: by the contract above the slot belongs to this pool. The
        // handle is moved in here, so no reference from `get` borrowing it is
        // still alive, and nobody else can be taking it.
        let held = unsafe { &*cell };

        // SAFETY: the slot still holds its value, and this is the only take
        // of this handle, so the value is moved out exactly once.
        let value = unsafe { held.assume_init_read() };

        self.release(SlotPtr(slot));
        value
    }

    fn claim(&self) -> SlotPtr<T> {
        let free = self.free.get_or_default();

        if let Some(slot) = free.borrow_mut().pop() {
            return slot;
        }

        self.refill(&mut free.borrow_mut())
    }

    #[cold]
    fn refill(&self, free: &mut Vec<SlotPtr<T>>) -> SlotPtr<T> {
        if let Some(batch) = self.shared.lock().pop() {
            free.extend(batch);
        } else {
            let mut pages = self.pages.lock();
            let size = page_size(pages.len());
            let page: Box<[Slot<T>]> = (0..size).map(|_| Slot::new()).collect();
            pages.push(page);

            // The page is read back from where it now lives, so the pointers
            // belong to the box the pool owns and not to a moved local.
            let page = pages.last().map(AsRef::as_ref).unwrap_or_default();
            free.extend(page.iter().map(|slot| SlotPtr(NonNull::from(slot))));
        }

        #[expect(
            clippy::expect_used,
            reason = "a refill either took a non-empty batch or allocated a page"
        )]
        free.pop().expect("a refill leaves at least one free slot")
    }

    fn release(&self, slot: SlotPtr<T>) {
        let free = self.free.get_or_default();
        let mut free = free.borrow_mut();
        free.push(slot);

        let len = free.len();
        if len >= 2 * BATCH {
            let batch = free.split_off(len - BATCH);
            self.shared.lock().push(batch);
        }
    }
}

impl<T> Slot<T> {
    fn new() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }
}

// A slot is a transparent wrapper around its cell, and `raw_get` needs no
// reference to it, so getting at the storage takes no unsafe code of its own.
fn cell_of<T>(slot: NonNull<Slot<T>>) -> *mut MaybeUninit<T> {
    UnsafeCell::raw_get(slot.as_ptr().cast::<UnsafeCell<MaybeUninit<T>>>())
}

// 32 slots, doubling per page, capped. Past the cap the shift itself would
// overflow, so it is compared before shifting.
fn page_size(pages: usize) -> usize {
    let doublings = u32::try_from(pages).unwrap_or(u32::MAX);
    if doublings >= MAX_PAGE.trailing_zeros() {
        return MAX_PAGE;
    }
    (FIRST_PAGE << doublings).min(MAX_PAGE)
}

impl<T: Send> core::fmt::Debug for StatePool<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StatePool")
            .field("pages", &self.pages.lock().len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    };

    use super::{BATCH, FIRST_PAGE, StatePool, page_size};

    impl<T: Send> StatePool<T> {
        fn pages_len(&self) -> usize {
            self.pages.lock().len()
        }

        fn shared_batches(&self) -> usize {
            self.shared.lock().len()
        }
    }

    struct Counted(Arc<AtomicUsize>, u64);

    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn a_value_goes_in_and_comes_back_out() {
        let pool = StatePool::new();
        let ptr = pool.insert(7u64);

        // SAFETY: the handle comes from this pool and was not taken yet.
        assert_eq!(unsafe { *pool.get(&ptr) }, 7);
        // SAFETY: the handle comes from this pool and is consumed here.
        assert_eq!(unsafe { pool.take(ptr) }, 7);
    }

    #[test]
    fn a_slot_is_reused_without_growing_the_pool() {
        let pool = StatePool::new();

        for round in 0..1000u64 {
            let ptr = pool.insert(round);
            // SAFETY: the handle comes from this pool and is consumed here.
            assert_eq!(unsafe { pool.take(ptr) }, round);
        }

        assert_eq!(pool.pages_len(), 1, "one page serves a serial user");
    }

    #[test]
    fn pages_grow_while_values_stay_readable() {
        let pool = StatePool::new();
        let ptrs: Vec<_> = (0..FIRST_PAGE * 4).map(|i| pool.insert(i as u64)).collect();

        assert!(pool.pages_len() > 1, "more slots than the first page holds");

        for (expected, ptr) in ptrs.iter().enumerate() {
            // SAFETY: every handle comes from this pool and none was taken yet.
            assert_eq!(unsafe { *pool.get(ptr) }, expected as u64);
        }
        for (expected, ptr) in ptrs.into_iter().enumerate() {
            // SAFETY: the handles are distinct and each is consumed once.
            assert_eq!(unsafe { pool.take(ptr) }, expected as u64);
        }
    }

    #[test]
    fn page_sizes_double_up_to_the_cap() {
        assert_eq!(page_size(0), FIRST_PAGE);
        assert_eq!(page_size(1), FIRST_PAGE * 2);
        assert_eq!(
            page_size(7),
            super::MAX_PAGE,
            "capped once doubling gets there"
        );
        assert_eq!(page_size(usize::MAX), super::MAX_PAGE, "no overflow");
    }

    #[test]
    fn a_taken_value_is_dropped_once_by_its_owner() {
        let drops = Arc::new(AtomicUsize::new(0));
        let pool = StatePool::new();

        let ptr = pool.insert(Counted(drops.clone(), 1));
        assert_eq!(drops.load(Ordering::Relaxed), 0, "the pool holds it");

        // SAFETY: the handle comes from this pool and is consumed here.
        let value = unsafe { pool.take(ptr) };
        assert_eq!(value.1, 1);
        assert_eq!(drops.load(Ordering::Relaxed), 0, "the caller holds it");

        drop(value);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_value_inserted_on_one_thread_is_taken_on_another() {
        let pool: Arc<StatePool<u64>> = Arc::new(StatePool::new());
        let ptr = pool.insert(42);

        let value = std::thread::spawn(move || {
            // SAFETY: the handle came from this pool, moved here by value, and is
            // consumed on this thread only.
            unsafe { pool.take(ptr) }
        })
        .join()
        .unwrap();

        assert_eq!(value, 42);
    }

    #[test]
    fn a_thread_that_only_takes_hands_batches_to_a_thread_that_only_inserts() {
        let pool: Arc<StatePool<u64>> = Arc::new(StatePool::new());
        let ptrs: Vec<_> = (0..3 * BATCH).map(|i| pool.insert(i as u64)).collect();
        let pages_after_inserting = pool.pages_len();

        let taker = pool.clone();
        std::thread::spawn(move || {
            for ptr in ptrs {
                // SAFETY: each handle came from this pool and is consumed once,
                // on this thread.
                _ = unsafe { taker.take(ptr) };
            }
        })
        .join()
        .unwrap();

        assert!(
            pool.shared_batches() > 0,
            "the taking thread handed slots over"
        );

        let inserter = pool.clone();
        std::thread::spawn(move || {
            let ptr = inserter.insert(1);
            // SAFETY: the handle comes from this pool and is consumed here.
            assert_eq!(unsafe { inserter.take(ptr) }, 1);
        })
        .join()
        .unwrap();

        assert_eq!(
            pool.pages_len(),
            pages_after_inserting,
            "a fresh thread refilled from the shared list instead of allocating"
        );
    }

    #[test]
    fn concurrent_users_keep_their_own_values() {
        const THREADS: usize = 8;
        const PER_THREAD: u64 = 2000;

        let pool: Arc<StatePool<u64>> = Arc::new(StatePool::new());
        let start = Arc::new(Barrier::new(THREADS));

        let handles: Vec<_> = (0..THREADS)
            .map(|thread| {
                let pool = pool.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    for round in 0..PER_THREAD {
                        let value = thread as u64 * PER_THREAD + round;
                        let ptr = pool.insert(value);
                        // SAFETY: this thread owns the handle it just got, and no
                        // other thread has it.
                        assert_eq!(unsafe { *pool.get(&ptr) }, value);
                        // SAFETY: same handle, consumed once, on this thread.
                        assert_eq!(unsafe { pool.take(ptr) }, value);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }
}
