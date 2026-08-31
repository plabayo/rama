//! Shared setup for the tests that exercise the dial9 integration.

/// Serializes tests that build an enabled dial9 recorder (a second `build()`
/// while one is alive returns a disabled recorder).
pub(crate) fn recorder_slot() -> parking_lot::MutexGuard<'static, ()> {
    static SLOT: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    SLOT.lock()
}

/// Build an enabled recorder writing into `trace_dir`.
///
/// Callers must hold [`recorder_slot`].
pub(crate) fn recorder(trace_dir: &std::path::Path) -> ::dial9::Recorder {
    let writer = ::dial9::DiskBuffer::builder()
        .base_path(trace_dir)
        .max_file_size(mib(1))
        .max_total_size(mib(4))
        .build();
    let recorder = ::dial9::recorder_or_disabled(writer).build();
    assert!(
        recorder.handle().is_enabled(),
        "expected an enabled recorder, is another recorder still alive?"
    );
    recorder
}
