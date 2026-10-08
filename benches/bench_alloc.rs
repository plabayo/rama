//! Benches run on the allocator rama binaries ship (see `rama-cli`), wrapped
//! so divan reports allocations: measuring on the system allocator would
//! misjudge allocation-heavy paths.

#[cfg(target_family = "unix")]
#[global_allocator]
static ALLOC: divan::AllocProfiler<jemallocator::Jemalloc> =
    divan::AllocProfiler::new(jemallocator::Jemalloc);

#[cfg(windows)]
#[global_allocator]
static ALLOC: divan::AllocProfiler<mimalloc::MiMalloc> =
    divan::AllocProfiler::new(mimalloc::MiMalloc);
