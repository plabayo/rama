//! Allocator startup policy and on-demand accounting. Snapshot queries only
//! refresh `epoch`; they never purge, flush caches, or change allocator policy.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct AllocatorStatsReply {
    available: bool,
    allocator: &'static str,
    pid: u32,
    sampled_at_unix_ms: Option<u64>,
    stats: Option<JemallocStats>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct JemallocStats {
    epoch: u64,
    allocated: usize,
    active: usize,
    resident: usize,
    metadata: usize,
    mapped: usize,
    retained: usize,
    pdirty: usize,
    pmuzzy: usize,
    page_size: usize,
    narenas: u32,
    background_thread: Setting<bool>,
    opt_background_thread: Setting<bool>,
    opt_dirty_decay_ms: Setting<isize>,
    opt_muzzy_decay_ms: Setting<isize>,
    arenas_dirty_decay_ms: Setting<isize>,
    arenas_muzzy_decay_ms: Setting<isize>,
}

/// A missing platform option is distinct from a disabled/zero-valued option.
#[derive(Debug, Serialize)]
struct Setting<T> {
    value: Option<T>,
    error: Option<String>,
}

#[cfg(feature = "jemallocator")]
impl<T> From<Result<T, String>> for Setting<T> {
    fn from(result: Result<T, String>) -> Self {
        match result {
            Ok(value) => Self {
                value: Some(value),
                error: None,
            },
            Err(error) => Self {
                value: None,
                error: Some(error),
            },
        }
    }
}

pub(crate) fn snapshot() -> AllocatorStatsReply {
    #[cfg(feature = "jemallocator")]
    let (allocator, result) = ("jemalloc", jemalloc::snapshot());
    #[cfg(not(feature = "jemallocator"))]
    let (allocator, result): (_, Result<JemallocStats, String>) = (
        "system",
        Err("jemalloc statistics unavailable: built without the jemallocator feature".into()),
    );
    let (stats, error) = match result {
        Ok(stats) => (Some(stats), None),
        Err(error) => (None, Some(error)),
    };
    AllocatorStatsReply {
        available: stats.is_some(),
        allocator,
        pid: std::process::id(),
        sampled_at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| elapsed.as_millis().try_into().ok()),
        stats,
        error,
    }
}

#[cfg(feature = "jemallocator")]
mod jemalloc {
    use std::ffi::{CStr, c_char, c_int, c_void};

    use super::JemallocStats;

    type Mallctl =
        unsafe extern "C" fn(*const c_char, *mut c_void, *mut usize, *mut c_void, usize) -> c_int;

    // Keep this private and limited to integers: every returned bit pattern is
    // valid. Read C bool into u8 and validate it before constructing a Rust bool.
    trait ControlValue: Copy + Default {}
    impl ControlValue for u8 {}
    impl ControlValue for u32 {}
    impl ControlValue for u64 {}
    impl ControlValue for usize {}
    impl ControlValue for isize {}

    /// Read (and, with `new`, write) one jemalloc control through `call`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `call` follows the `mallctl(3)` contract (reads
    /// the NUL-terminated `name`, writes at most `*oldlenp` bytes to `oldp`, reads
    /// `newlen` bytes from `newp`, retains no pointer) and that `name`'s documented
    /// value type is an integer of exactly `size_of::<T>()` bytes (C `bool` as `u8`).
    unsafe fn control<T: ControlValue>(
        name: &'static CStr,
        mut new: Option<T>,
        call: Mallctl,
    ) -> Result<T, String> {
        let mut value = T::default();
        let expected = size_of::<T>();
        let mut length = expected;
        let newp = new.as_mut().map_or(std::ptr::null_mut(), |value| {
            std::ptr::from_mut(value).cast()
        });
        // SAFETY: `mallctl(3)` needs a NUL-terminated `name`, `oldp` with adequate
        // space for the value and `*oldlenp` its size, and `newp`/`newlen` describing
        // the new value (NULL/0 for none). `name` is a `CStr`; by this fn's
        // precondition the value is `T`-sized, and `value`/`length` are live, aligned
        // locals of exactly that size; `newp` is NULL with `newlen == 0` or points to
        // the live `T` in `new` with `newlen == size_of::<T>()`. `call` honours that
        // contract by precondition. `T: ControlValue` is a private set of integer
        // types, so any bytes written leave `value` valid.
        let code = unsafe {
            call(
                name.as_ptr(),
                std::ptr::from_mut(&mut value).cast(),
                &raw mut length,
                newp,
                if new.is_some() { expected } else { 0 },
            )
        };
        if code != 0 || length != expected {
            return Err(format!(
                "{}: mallctl errno={code}, expected {expected} bytes, returned {length}",
                name.to_string_lossy(),
            ));
        }
        Ok(value)
    }

    /// # Safety
    ///
    /// The caller must ensure `name`'s documented `mallctl` value type is an
    /// integer of exactly `size_of::<T>()` bytes.
    unsafe fn read<T: ControlValue>(name: &'static CStr) -> Result<T, String> {
        // SAFETY: `tikv_jemalloc_sys::mallctl` is jemalloc's `mallctl(3)`, and the
        // `name`/`T` pairing is this fn's precondition.
        unsafe { control(name, None, tikv_jemalloc_sys::mallctl) }
    }

    /// # Safety
    ///
    /// The caller must ensure `name`'s documented `mallctl` value type is `bool`.
    unsafe fn read_bool(name: &'static CStr) -> Result<bool, String> {
        // SAFETY: C `bool` is one byte on Apple targets, so `u8` matches the
        // value type this fn's precondition gives `name`.
        match unsafe { read::<u8>(name) }? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(format!(
                "{}: invalid C bool {value}",
                name.to_string_lossy()
            )),
        }
    }

    // Each `unsafe` below pairs a control with the value type jemalloc's MALLCTL
    // NAMESPACE documents for it (`size_t` = usize, `unsigned` = u32,
    // `ssize_t` = isize, `uint64_t` = u64, `bool`).
    pub(super) fn snapshot() -> Result<JemallocStats, String> {
        // SAFETY: `epoch` is `uint64_t` (rw); `mallctl` is jemalloc's `mallctl(3)`.
        let epoch = unsafe { control(c"epoch", Some(1_u64), tikv_jemalloc_sys::mallctl) }?;
        // SAFETY: `config.stats` is `bool`.
        if !unsafe { read_bool(c"config.stats") }? {
            return Err("jemalloc was built without statistics support".into());
        }
        Ok(JemallocStats {
            epoch,
            // SAFETY: `stats.allocated` is `size_t`.
            allocated: unsafe { read(c"stats.allocated") }?,
            // SAFETY: `stats.active` is `size_t`.
            active: unsafe { read(c"stats.active") }?,
            // SAFETY: `stats.resident` is `size_t`.
            resident: unsafe { read(c"stats.resident") }?,
            // SAFETY: `stats.metadata` is `size_t`.
            metadata: unsafe { read(c"stats.metadata") }?,
            // SAFETY: `stats.mapped` is `size_t`.
            mapped: unsafe { read(c"stats.mapped") }?,
            // SAFETY: `stats.retained` is `size_t`.
            retained: unsafe { read(c"stats.retained") }?,
            // jemalloc's documented MALLCTL_ARENAS_ALL = 4096 aggregates arenas.
            // SAFETY: `stats.arenas.<i>.pdirty` is `size_t`.
            pdirty: unsafe { read(c"stats.arenas.4096.pdirty") }?,
            // SAFETY: `stats.arenas.<i>.pmuzzy` is `size_t`.
            pmuzzy: unsafe { read(c"stats.arenas.4096.pmuzzy") }?,
            // SAFETY: `arenas.page` is `size_t`.
            page_size: unsafe { read(c"arenas.page") }?,
            // SAFETY: `arenas.narenas` is `unsigned`.
            narenas: unsafe { read(c"arenas.narenas") }?,
            // SAFETY: `background_thread` is `bool`.
            background_thread: unsafe { read_bool(c"background_thread") }.into(),
            // SAFETY: `opt.background_thread` is `bool`.
            opt_background_thread: unsafe { read_bool(c"opt.background_thread") }.into(),
            // SAFETY: `opt.dirty_decay_ms` is `ssize_t`.
            opt_dirty_decay_ms: unsafe { read(c"opt.dirty_decay_ms") }.into(),
            // SAFETY: `opt.muzzy_decay_ms` is `ssize_t`.
            opt_muzzy_decay_ms: unsafe { read(c"opt.muzzy_decay_ms") }.into(),
            // SAFETY: `arenas.dirty_decay_ms` is `ssize_t`.
            arenas_dirty_decay_ms: unsafe { read(c"arenas.dirty_decay_ms") }.into(),
            // SAFETY: `arenas.muzzy_decay_ms` is `ssize_t`.
            arenas_muzzy_decay_ms: unsafe { read(c"arenas.muzzy_decay_ms") }.into(),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// `mallctl(3)` stub for a few fake controls.
        ///
        /// # Safety
        ///
        /// The caller must pass a NUL-terminated `name` and a readable, writable,
        /// aligned `length`; for `epoch` and `signed`, `old` must be writable and `new`
        /// readable for `*length` and `new_length` bytes, aligned for the named type.
        unsafe extern "C" fn stub(
            name: *const c_char,
            old: *mut c_void,
            length: *mut usize,
            new: *mut c_void,
            new_length: usize,
        ) -> c_int {
            // SAFETY: `CStr::from_ptr` needs a NUL-terminated `name` not written while
            // borrowed: this fn's precondition.
            let name = unsafe { CStr::from_ptr(name) };
            // SAFETY: `length` is readable (precondition).
            let len = unsafe { length.read() };
            match name.to_bytes() {
                b"epoch" => {
                    assert_eq!(len, size_of::<u64>());
                    assert_eq!(new_length, size_of::<u64>());
                    // SAFETY: for `epoch`, `new` is readable and aligned for the
                    // `new_length` (asserted `u64`-sized) bytes (precondition).
                    let new = unsafe { new.cast::<u64>().read() };
                    assert_eq!(new, 1);
                    // SAFETY: for `epoch`, `old` is writable and aligned for the `*length`
                    // (asserted `u64`-sized) bytes (precondition).
                    unsafe { old.cast::<u64>().write(42) };
                }
                // SAFETY: `length` is writable (precondition).
                b"short" => unsafe { length.write(len - 1) },
                b"error" => return 22,
                b"signed" => {
                    assert!(new.is_null());
                    assert_eq!(new_length, 0);
                    assert_eq!(len, size_of::<isize>());
                    // SAFETY: for `signed`, `old` is writable and aligned for the
                    // `*length` (asserted `isize`-sized) bytes (precondition).
                    unsafe { old.cast::<isize>().write(-1) };
                }
                _ => return 2,
            }
            0
        }

        #[test]
        fn control_preserves_types_and_rejects_errors_and_short_reads() {
            // SAFETY: `control` needs `call` to follow `mallctl(3)` and the value type of
            // `name` to be `T`. It passes `stub` a `CStr` name and its live, aligned,
            // `T`-sized locals, which is `stub`'s precondition; `stub` writes `epoch` as
            // `u64`, matching `T`.
            let epoch = unsafe { control(c"epoch", Some(1_u64), stub) };
            assert_eq!(epoch.unwrap(), 42);
            // SAFETY: as above; `stub` writes `signed` as `isize`, matching `T`.
            let signed = unsafe { control::<isize>(c"signed", None, stub) };
            assert_eq!(signed.unwrap(), -1);
            // SAFETY: as above; `short` only shrinks `*length`.
            let short = unsafe { control::<usize>(c"short", None, stub) };
            assert!(short.unwrap_err().contains("errno=0"));
            // SAFETY: as above; `error` touches no buffer.
            let error = unsafe { control::<usize>(c"error", None, stub) };
            assert!(error.unwrap_err().contains("errno=22"));
            // SAFETY: as above; unknown names touch no buffer.
            let absent = unsafe { control::<usize>(c"absent", None, stub) };
            assert!(absent.unwrap_err().contains("errno=2"));
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn snapshot_reports_the_linked_allocator_and_process() {
        let snapshot = super::snapshot();
        assert_eq!(snapshot.pid, std::process::id());
        assert!(snapshot.sampled_at_unix_ms.is_some());
        #[cfg(feature = "jemallocator")]
        {
            assert_eq!(snapshot.allocator, "jemalloc");
            assert!(snapshot.available, "{:?}", snapshot.error);
            let stats = snapshot.stats.as_ref().unwrap();
            assert!(stats.allocated > 0);
            assert!(stats.active >= stats.allocated);
            assert!(stats.resident >= stats.metadata);
            assert!(stats.page_size.is_power_of_two());
            assert!(stats.narenas > 0);
        }
        #[cfg(not(feature = "jemallocator"))]
        {
            assert_eq!(snapshot.allocator, "system");
            assert!(!snapshot.available);
            assert!(snapshot.stats.is_none());
            assert!(
                snapshot
                    .error
                    .as_ref()
                    .unwrap()
                    .contains("without the jemallocator feature")
            );
        }
        let wire = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(wire["available"], snapshot.available);
        assert_eq!(wire["pid"], snapshot.pid);
    }
}
