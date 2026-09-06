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

    fn control<T: ControlValue>(
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
        // SAFETY: the name is NUL-terminated; both buffers are aligned, live T
        // values and their exact sizes are supplied. Only integer T is allowed.
        // Each production caller below pairs a fixed control name with its
        // documented jemalloc C type. Errors/short reads are never accepted.
        let code = unsafe {
            call(
                name.as_ptr(),
                std::ptr::from_mut(&mut value).cast(),
                &mut length,
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

    fn read<T: ControlValue>(name: &'static CStr) -> Result<T, String> {
        control(name, None, tikv_jemalloc_sys::mallctl)
    }

    fn read_bool(name: &'static CStr) -> Result<bool, String> {
        match read::<u8>(name)? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(format!(
                "{}: invalid C bool {value}",
                name.to_string_lossy()
            )),
        }
    }

    pub(super) fn snapshot() -> Result<JemallocStats, String> {
        let epoch = control(c"epoch", Some(1_u64), tikv_jemalloc_sys::mallctl)?;
        if !read_bool(c"config.stats")? {
            return Err("jemalloc was built without statistics support".into());
        }
        Ok(JemallocStats {
            epoch,
            allocated: read(c"stats.allocated")?,
            active: read(c"stats.active")?,
            resident: read(c"stats.resident")?,
            metadata: read(c"stats.metadata")?,
            mapped: read(c"stats.mapped")?,
            retained: read(c"stats.retained")?,
            // jemalloc's documented MALLCTL_ARENAS_ALL = 4096 aggregates arenas.
            pdirty: read(c"stats.arenas.4096.pdirty")?,
            pmuzzy: read(c"stats.arenas.4096.pmuzzy")?,
            page_size: read(c"arenas.page")?,
            narenas: read(c"arenas.narenas")?,
            background_thread: read_bool(c"background_thread").into(),
            opt_background_thread: read_bool(c"opt.background_thread").into(),
            opt_dirty_decay_ms: read(c"opt.dirty_decay_ms").into(),
            opt_muzzy_decay_ms: read(c"opt.muzzy_decay_ms").into(),
            arenas_dirty_decay_ms: read(c"arenas.dirty_decay_ms").into(),
            arenas_muzzy_decay_ms: read(c"arenas.muzzy_decay_ms").into(),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        unsafe extern "C" fn stub(
            name: *const c_char,
            old: *mut c_void,
            length: *mut usize,
            new: *mut c_void,
            new_length: usize,
        ) -> c_int {
            // SAFETY: the tested control helper supplies valid named buffers.
            unsafe {
                match CStr::from_ptr(name).to_bytes() {
                    b"epoch" => {
                        assert_eq!(*length, size_of::<u64>());
                        assert_eq!(new_length, size_of::<u64>());
                        assert_eq!(*new.cast::<u64>(), 1);
                        *old.cast::<u64>() = 42;
                    }
                    b"short" => *length -= 1,
                    b"error" => return 22,
                    b"signed" => {
                        assert!(new.is_null());
                        assert_eq!(new_length, 0);
                        assert_eq!(*length, size_of::<isize>());
                        *old.cast::<isize>() = -1;
                    }
                    _ => return 2,
                }
            }
            0
        }

        #[test]
        fn control_preserves_types_and_rejects_errors_and_short_reads() {
            assert_eq!(control(c"epoch", Some(1_u64), stub).unwrap(), 42);
            assert_eq!(control::<isize>(c"signed", None, stub).unwrap(), -1);
            assert!(
                control::<usize>(c"short", None, stub)
                    .unwrap_err()
                    .contains("errno=0")
            );
            assert!(
                control::<usize>(c"error", None, stub)
                    .unwrap_err()
                    .contains("errno=22")
            );
            assert!(
                control::<usize>(c"absent", None, stub)
                    .unwrap_err()
                    .contains("errno=2")
            );
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
