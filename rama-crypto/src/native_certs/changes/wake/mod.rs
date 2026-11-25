use platform::Wake;
#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as platform;

#[cfg(windows)]
mod windows;
use std::{fmt, io, time::Duration};

use parking_lot::{Condvar, Mutex};
#[cfg(windows)]
use windows as platform;

/// Interrupts a thread blocked in
/// [`NativeCertsChanges::wait_changed`](super::NativeCertsChanges::wait_changed).
pub struct NativeCertsWake {
    pub(crate) os: platform::Wake,
    // Interrupts the backoff used when the operating system wait cannot block.
    generation: Mutex<WakeGeneration>,
    backoff: Condvar,
}

#[derive(Default)]
struct WakeGeneration {
    issued: u64,
    consumed: u64,
}

impl NativeCertsWake {
    /// Allocate the operating system handle a waiting thread listens on.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            os: Wake::new()?,
            generation: Mutex::new(WakeGeneration::default()),
            backoff: Condvar::new(),
        })
    }

    /// End the current or next wait early. Wakes coalesce until a wait consumes them.
    pub fn wake(&self) {
        let mut generation = self.generation.lock();
        generation.issued = generation.issued.wrapping_add(1);
        self.os.wake();
        self.backoff.notify_all();
    }

    /// Sleep for `timeout` unless a wake arrives first.
    pub(crate) fn backoff(&self, timeout: Duration) {
        let mut generation = self.generation.lock();
        _ = self.backoff.wait_while_for(
            &mut generation,
            |generation| generation.issued == generation.consumed,
            timeout,
        );
        generation.consumed = generation.issued;
    }

    /// Consume a wake only if neither wait path has consumed its generation.
    pub(crate) fn consumed(&self) -> bool {
        let mut generation = self.generation.lock();
        let fresh = generation.issued != generation.consumed;
        generation.consumed = generation.issued;
        fresh
    }
}

impl fmt::Debug for NativeCertsWake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeCertsWake").finish_non_exhaustive()
    }
}

/// Milliseconds for a Windows wait: rounded up so the wait never ends just
/// before the next probe is due, and below `INFINITE` (`u32::MAX`).
#[cfg(any(windows, test))]
fn windows_wait_millis(timeout: Duration) -> u32 {
    u32::try_from(timeout.as_nanos().div_ceil(1_000_000))
        .map_or(u32::MAX - 1, |millis| millis.min(u32::MAX - 1))
}

#[cfg(test)]
mod tests;
