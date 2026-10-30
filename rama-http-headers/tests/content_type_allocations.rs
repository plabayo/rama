#![allow(
    unsafe_code,
    reason = "the allocation contract requires a process-global counting allocator"
)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use rama_http_headers::{ContentType, HeaderMapExt};
use rama_http_types::{HeaderMap, HeaderValue, header::CONTENT_TYPE};

struct CountingAllocator;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

/// Never panics: a destroyed thread-local is skipped, not unwrapped.
fn allocated() {
    if COUNTING.try_with(Cell::get) == Ok(true) {
        let _thread_exited = ALLOCATIONS.try_with(|n| n.set(n.get().saturating_add(1)));
    }
}

// SAFETY: every block this allocator returns comes from `System`, and every free or
// resize passes the same pointer and layout on to `System`, so `System`'s `GlobalAlloc`
// impl meets the contract. The bookkeeping uses only `LocalKey::try_with` on
// const-initialized `Cell`s and `saturating_add`, none of which panic, so no method unwinds.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocated();
        // SAFETY: `System.alloc` has this method's contract (`layout` has non-zero size),
        // which the caller upholds.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the caller passes a block this allocator returned for `layout`; every
        // such block comes from `System` with that same layout, as `dealloc` requires.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        allocated();
        // SAFETY: as for `dealloc`, `pointer` is a `System` block allocated with `layout`;
        // `new_size` meets `realloc`'s size rules by the caller's contract.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn measured(operation: impl FnOnce()) -> usize {
    ALLOCATIONS.set(0);
    COUNTING.set(true);
    operation();
    COUNTING.set(false);
    ALLOCATIONS.get()
}

#[test]
fn static_typed_content_types_encode_without_allocating() {
    const GRPC: ContentType = ContentType::grpc();

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));

    let allocations = measured(|| {
        headers.typed_insert(GRPC);
        headers.typed_insert(ContentType::grpc_web());
        headers.typed_insert(ContentType::grpc_web_proto());
        headers.typed_insert(ContentType::grpc_web_text_proto());
        headers.typed_insert(ContentType::protobuf());
    });

    assert_eq!(allocations, 0, "static typed encoding allocated");
    assert_eq!(headers.get(CONTENT_TYPE).unwrap(), "application/x-protobuf");
}
