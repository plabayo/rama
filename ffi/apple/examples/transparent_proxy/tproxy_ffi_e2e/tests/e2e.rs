#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "integration tests use explicit assertions and panics for clarity"
)]

//! Apple FFI end-to-end coverage for the transparent proxy example static library.

mod cases;

pub(crate) mod shared;

/// Check the allocator in the linked engine, not just the test driver's build
/// flags. A custom allocator can otherwise bypass ASan's heap poisoning.
#[cfg(rama_asan)]
#[tokio::test]
#[serial_test::serial]
async fn asan_observes_linked_ffi_allocation_lifetime() {
    unsafe extern "C" {
        fn __asan_address_is_poisoned(address: *const std::ffi::c_void) -> std::ffi::c_int;
    }

    let env = shared::env::setup_env().await;
    let address = env.engine.raw.cast::<std::ffi::c_void>();
    // SAFETY: the ASan interface examines shadow memory without dereferencing
    // the supplied address, both before and after the FFI engine is released.
    assert_eq!(unsafe { __asan_address_is_poisoned(address) }, 0);
    drop(env);
    assert_ne!(
        unsafe { __asan_address_is_poisoned(address) },
        0,
        "ASan did not poison the allocation freed by the linked FFI library"
    );
}
