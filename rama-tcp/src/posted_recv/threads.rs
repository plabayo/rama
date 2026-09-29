use std::{num::NonZero, time::Duration};

use parking_lot::RwLock;
use rama_utils::macros::generate_set_and_with;

/// Most threads started by default, however many CPUs there are: each one
/// already handles a few GiB/s of receives.
const DEFAULT_MAX_THREADS: usize = 8;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How many threads complete the posted receives of the process.
///
/// Every [`PostedRecv`](super::PostedRecv) of the process shares these
/// threads, which only exist on Windows; elsewhere this configures nothing.
///
/// They start as needed: one when the first stream is wrapped, then another
/// whenever the running ones are all busy with a backlog of completions, up
/// to [`max_threads`](Self::max_threads). A thread that has nothing to do for
/// [`idle_timeout`](Self::idle_timeout) exits, as long as
/// [`min_threads`](Self::min_threads) keep running.
///
/// Use [`set_completion_threads`] to change it for the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompletionThreads {
    min_threads: usize,
    max_threads: usize,
    idle_timeout: Duration,
}

impl Default for CompletionThreads {
    fn default() -> Self {
        Self::new()
    }
}

impl CompletionThreads {
    /// The default: at least one thread, at most one per CPU up to eight,
    /// and a thread above the minimum exits after 30 seconds without work.
    #[must_use]
    pub fn new() -> Self {
        let cpus = std::thread::available_parallelism().map_or(1, NonZero::get);
        Self {
            min_threads: 1,
            max_threads: cpus.clamp(1, DEFAULT_MAX_THREADS),
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }

    /// Always exactly one thread, which never scales.
    #[must_use]
    pub fn single() -> Self {
        Self::new().with_min_threads(1).with_max_threads(1)
    }

    generate_set_and_with! {
        /// Threads kept running even without work (at least 1). Raises the
        /// maximum to match if needed.
        pub fn min_threads(mut self, threads: usize) -> Self {
            self.min_threads = threads.max(1);
            self.max_threads = self.max_threads.max(self.min_threads);
            self
        }
    }

    generate_set_and_with! {
        /// Most threads started under load (at least the minimum).
        pub fn max_threads(mut self, threads: usize) -> Self {
            self.max_threads = threads.max(self.min_threads);
            self
        }
    }

    generate_set_and_with! {
        /// How long a thread above the minimum waits for work before it
        /// exits (at least one millisecond).
        pub fn idle_timeout(mut self, timeout: Duration) -> Self {
            self.idle_timeout = timeout.max(Duration::from_millis(1));
            self
        }
    }

    /// Threads kept running even without work.
    #[must_use]
    pub const fn min_threads(&self) -> usize {
        self.min_threads
    }

    /// Most threads started under load.
    #[must_use]
    pub const fn max_threads(&self) -> usize {
        self.max_threads
    }

    /// How long a thread above the minimum waits for work before it exits.
    #[must_use]
    pub const fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }
}

static CONFIG: RwLock<Option<CompletionThreads>> = parking_lot::const_rwlock(None);

/// Configure the completion threads of the process, see
/// [`CompletionThreads`].
///
/// Takes effect right away: a higher minimum starts threads now, a lower
/// maximum stops the extra ones once they finish what they are doing.
pub fn set_completion_threads(config: CompletionThreads) {
    *CONFIG.write() = Some(config);
    #[cfg(target_os = "windows")]
    super::iocp::completion_threads_changed();
}

/// The configuration of the completion threads of the process.
#[must_use]
pub fn completion_threads() -> CompletionThreads {
    if let Some(config) = *CONFIG.read() {
        return config;
    }
    // Resolved once: the default asks the OS for the CPU count.
    *CONFIG.write().get_or_insert_with(CompletionThreads::new)
}

/// How many completion threads run right now; always 0 off Windows.
#[must_use]
pub fn running_completion_threads() -> usize {
    #[cfg(target_os = "windows")]
    {
        super::iocp::running_threads()
    }
    #[cfg(not(target_os = "windows"))]
    {
        0
    }
}

/// Why a completion thread started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ThreadStartReason {
    /// The first stream of the process was wrapped.
    FirstUse,
    /// Every running thread was busy with a backlog of completions.
    Backlog,
    /// The configured minimum was raised.
    Minimum,
}

impl ThreadStartReason {
    /// Stable code used in the trace.
    #[must_use]
    pub const fn dial9_code(self) -> u8 {
        match self {
            Self::FirstUse => 0,
            Self::Backlog => 1,
            Self::Minimum => 2,
        }
    }
}

/// Why a completion thread stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ThreadStopReason {
    /// It had nothing to do for the idle timeout.
    Idle,
    /// The configured maximum was lowered below the running threads.
    OverMaximum,
}

impl ThreadStopReason {
    /// Stable code used in the trace.
    #[must_use]
    pub const fn dial9_code(self) -> u8 {
        match self {
            Self::Idle => 0,
            Self::OverMaximum => 1,
        }
    }
}
