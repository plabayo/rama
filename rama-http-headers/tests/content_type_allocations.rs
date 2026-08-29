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

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        COUNTING.with(|counting| {
            if counting.get() {
                ALLOCATIONS.set(ALLOCATIONS.get().saturating_add(1));
            }
        });
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        COUNTING.with(|counting| {
            if counting.get() {
                ALLOCATIONS.set(ALLOCATIONS.get().saturating_add(1));
            }
        });
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
