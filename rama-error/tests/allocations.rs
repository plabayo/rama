//! Heap allocations made by the common ways of creating an error.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    hint::black_box,
};

use rama_error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _};

struct Counting;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

fn count() {
    if COUNTING.with(Cell::get) {
        ALLOCATIONS.with(|allocations| allocations.set(allocations.get() + 1));
    }
}

// SAFETY: forwards every call to the system allocator unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count();
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Allocations made on this thread while building the error.
fn allocations(create: impl FnOnce() -> BoxError) -> usize {
    ALLOCATIONS.with(|allocations| allocations.set(0));
    COUNTING.with(|counting| counting.set(true));
    let error = black_box(create());
    COUNTING.with(|counting| counting.set(false));
    drop(error);
    ALLOCATIONS.with(Cell::get)
}

fn io() -> std::io::Error {
    std::io::Error::from(std::io::ErrorKind::TimedOut)
}

#[test]
fn a_static_message_and_its_context_share_one_allocation() {
    assert_eq!(allocations(|| BoxError::from_static_str("x")), 1);
    assert_eq!(
        allocations(|| BoxError::from_static_str("x").context("y")),
        1
    );
    assert_eq!(
        allocations(|| BoxError::from_static_str("x")
            .context("y")
            .context_field("k", "v")),
        1
    );
    assert_eq!(
        allocations(|| None::<u8>.context("missing").unwrap_err()),
        1
    );
}

#[test]
fn context_values_other_than_static_strings_are_boxed() {
    assert_eq!(
        allocations(|| BoxError::from_static_str("x").context_field("k", 1u16)),
        2
    );
    // Two fields fit inline, a third spills into a vector.
    assert_eq!(
        allocations(|| BoxError::from_static_str("x")
            .context_field("a", "1")
            .context_field("b", "2")
            .context_field("c", "3")),
        2
    );
}

#[test]
fn context_on_another_error_takes_one_wrapper() {
    assert_eq!(allocations(|| io().into_box_error()), 1);
    assert_eq!(allocations(|| io().context("y")), 2);
    assert_eq!(
        allocations(|| Err::<(), _>(io()).context("y").unwrap_err()),
        2
    );
    assert_eq!(
        allocations(|| io().context("y").context_field("k", 1u16)),
        3
    );
}

#[test]
fn lazy_context_on_success_allocates_nothing() {
    assert_eq!(
        allocations(|| {
            let value = Ok::<u8, std::io::Error>(1)
                .with_context(|| "not built on success")
                .unwrap();
            black_box(value);
            BoxError::from_static_str("x")
        }),
        1
    );
}
