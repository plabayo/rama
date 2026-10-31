//! Overlapped receives kept posted on the socket, completed by a
//! process-wide pool of threads that scales with the load.
//!
//! mio attaches only its AFD helper handle to its own completion port, never
//! the socket, so the socket is free to be attached to ours. Tokio keeps
//! doing the writes; its read readiness goes stale, which is harmless since
//! nothing reads through it, except while no receive can be posted at all.
//!
//! Several threads may complete receives of the same flow at once: the flow
//! lock serializes them, and completions are put back in posting order.

use std::{
    collections::{BTreeMap, VecDeque},
    io, mem,
    os::windows::io::RawSocket,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use parking_lot::{Mutex, MutexGuard};
use rama_core::telemetry::tracing;
use tokio::io::ReadBuf;
use windows_sys::Win32::{
    Foundation::{
        ERROR_NO_SYSTEM_RESOURCES, ERROR_NONPAGED_SYSTEM_RESOURCES, ERROR_NOT_ENOUGH_QUOTA,
        ERROR_PAGED_SYSTEM_RESOURCES, ERROR_WORKING_SET_QUOTA, HANDLE, INVALID_HANDLE_VALUE,
        WAIT_TIMEOUT,
    },
    Networking::WinSock::{
        SOCKET, SOCKET_ERROR, WSA_IO_PENDING, WSA_NOT_ENOUGH_MEMORY, WSA_OPERATION_ABORTED, WSABUF,
        WSAENOBUFS, WSAGetLastError, WSAGetOverlappedResult, WSARecv,
    },
    System::{
        IO::{
            CancelIoEx, CreateIoCompletionPort, GetQueuedCompletionStatusEx, OVERLAPPED,
            OVERLAPPED_ENTRY, PostQueuedCompletionStatus,
        },
        Threading::{GetCurrentThread, INFINITE, SetThreadPriority, THREAD_PRIORITY_ABOVE_NORMAL},
    },
};

use super::{PostedRecvConfig, ThreadStartReason, ThreadStopReason, completion_threads};

/// Receives posted and not completed yet, across all flows.
#[cfg(test)]
static OUTSTANDING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// Flows whose socket is not closed yet, across all flows.
#[cfg(test)]
static LIVE_FLOWS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
pub(super) fn outstanding_receives() -> usize {
    OUTSTANDING.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
pub(super) fn live_flows() -> usize {
    LIVE_FLOWS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Completions sent back to the port because a reader held the flow.
#[cfg(test)]
static REQUEUED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// Completions whose thread waited for a reader that held the flow.
#[cfg(test)]
static WAITED_FOR_READER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Completions skipped because they were not of a posted receive.
#[cfg(test)]
static SKIPPED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
pub(super) fn skipped_completions() -> usize {
    SKIPPED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Queue a completion for `overlapped` on the pool's port, as a packet this
/// module did not queue (one Winsock may queue for its own calls) would be.
#[cfg(test)]
pub(super) fn post_foreign_completion(overlapped: &'static OVERLAPPED) -> io::Result<()> {
    let port = pool()?.port;
    // SAFETY: `PostQueuedCompletionStatus` only queues the pointer value, on
    // the open pool port. `overlapped` is leaked, so it stays live and shares
    // no address with a registered slot: `take_completed` skips its packet.
    let posted = unsafe { PostQueuedCompletionStatus(port.0, 0, 0, ptr::from_ref(overlapped)) };
    if posted == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// How many panics to raise on completion threads: when starting to
/// complete, after handling a batch, and after retiring.
#[cfg(test)]
static PANIC_ON_START: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static PANIC_AFTER_BATCH: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static PANIC_ON_STOP: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
pub(super) fn inject_panics(on_start: usize, after_batch: usize, on_stop: usize) {
    PANIC_ON_START.store(on_start, Ordering::Release);
    PANIC_AFTER_BATCH.store(after_batch, Ordering::Release);
    PANIC_ON_STOP.store(on_stop, Ordering::Release);
}

#[cfg(test)]
fn injected_panic(armed: &AtomicUsize) {
    if armed
        .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
        .is_ok()
    {
        panic!("injected completion thread panic");
    }
}

/// Panics injected and not raised yet.
#[cfg(test)]
pub(super) fn pending_panics() -> usize {
    [&PANIC_ON_START, &PANIC_AFTER_BATCH, &PANIC_ON_STOP]
        .iter()
        .map(|armed| armed.load(Ordering::Acquire))
        .sum()
}

/// Completion threads alive, counted apart from the pool's own count.
#[cfg(test)]
static LIVE_THREADS: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
pub(super) fn live_threads() -> usize {
    LIVE_THREADS.load(Ordering::Acquire)
}

/// Counts its thread in [`LIVE_THREADS`] until the thread ends, by unwinding too.
#[cfg(test)]
struct LiveThread;

#[cfg(test)]
impl LiveThread {
    fn new() -> Self {
        LIVE_THREADS.fetch_add(1, Ordering::AcqRel);
        Self
    }
}

#[cfg(test)]
impl Drop for LiveThread {
    fn drop(&mut self) {
        LIVE_THREADS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// How often completions were requeued, and waited for a reader.
#[cfg(test)]
pub(super) fn contention() -> (usize, usize) {
    (
        REQUEUED.load(std::sync::atomic::Ordering::Relaxed),
        WAITED_FOR_READER.load(std::sync::atomic::Ordering::Relaxed),
    )
}

#[derive(Clone, Copy)]
struct Port(HANDLE);

// SAFETY: a completion port is a kernel object that any thread of the
// process may post to and wait on concurrently (I/O Completion Ports docs);
// the handle is a plain value that this module never closes.
unsafe impl Send for Port {}
// SAFETY: as above.
unsafe impl Sync for Port {}

/// Shards of [`IN_PORT`], to keep completion threads off one lock.
const IN_PORT_SHARDS: usize = 16;

/// Slots handed to the system or queued on the port, by address.
///
/// Packets of anything but a posted receive or a requeue (whatever
/// undocumented packets Winsock's own calls on the socket may queue; other
/// overlapped I/O is ruled out by [`Reader::new`]) are skipped instead of
/// taken as a slot.
// Safety invariant: an entry maps the address of a slot to the pointer
// `Box::into_raw` returned for it. While the entry exists the box is owned
// by the system or the port, not by any code of this module, and the slot
// was handed to one request that queues at most one completion packet with
// its address.
static IN_PORT: [Mutex<BTreeMap<usize, SlotPtr>>; IN_PORT_SHARDS] =
    [const { Mutex::new(BTreeMap::new()) }; IN_PORT_SHARDS];

/// A slot pointer kept with the provenance `Box::into_raw` gave it.
struct SlotPtr(*mut Slot);

// SAFETY: an entry stands for a boxed `Slot`, which is `Send`; removing it
// under its shard lock hands the box to exactly one thread.
unsafe impl Send for SlotPtr {}

fn in_port_shard(addr: usize) -> &'static Mutex<BTreeMap<usize, SlotPtr>> {
    &IN_PORT[(addr / mem::size_of::<Slot>()) % IN_PORT_SHARDS]
}

/// Register `slot` in [`IN_PORT`] and leak it, to hand it to the system or
/// the port. It comes back through [`take_completed`] or [`take_back`].
///
/// # Safety
///
/// The caller must hand the returned pointer to exactly one request that
/// queues at most one completion packet with it: an overlapped receive, or
/// a post to the pool port. If that request queues none, the caller takes
/// the slot back with [`take_back`].
unsafe fn hand_over(slot: Box<Slot>) -> *mut Slot {
    let raw = Box::into_raw(slot);
    // Safety invariant of `IN_PORT`: the box is leaked here and only the
    // registry hands it back; the request is as this function's contract says.
    let prev = in_port_shard(raw.addr())
        .lock()
        .insert(raw.addr(), SlotPtr(raw));
    // a live box has a unique address, and an entry leaves before its box is freed
    debug_assert!(prev.is_none(), "slot address registered twice");
    raw
}

/// Take back a handed-over slot for which no completion was queued.
///
/// Returns `None` if its entry is gone already.
///
/// # Safety
///
/// The caller must ensure that `raw` was returned by [`hand_over`], and that
/// the request it was handed over for queued no completion packet: it failed
/// synchronously, or was a post to the port that failed.
unsafe fn take_back(raw: *mut Slot) -> Option<Box<Slot>> {
    let entry = in_port_shard(raw.addr()).lock().remove(&raw.addr())?;
    // SAFETY: `Box::from_raw`: the entry holds the pointer `Box::into_raw`
    // returned for this slot (the `IN_PORT` invariant). Removing it under the
    // shard lock makes this the only owner, and with no packet queued
    // (this function's contract) the system no longer uses the slot.
    Some(unsafe { Box::from_raw(entry.0) })
}

/// Take the slot a completion packet refers to, if it is one of ours.
///
/// # Safety
///
/// The caller must ensure that `overlapped` is the `lpOverlapped` of a
/// completion packet it just removed from the pool port.
///
/// Returns `Some` only with the box of a registered slot whose request this
/// packet completed, removing its entry.
unsafe fn take_completed(overlapped: *mut OVERLAPPED) -> Option<Box<Slot>> {
    let entry = in_port_shard(overlapped.addr())
        .lock()
        .remove(&overlapped.addr())?;
    // SAFETY: `Box::from_raw`: the entry holds the pointer `Box::into_raw`
    // returned (the `IN_PORT` invariant), and removing it under the lock
    // makes this the only owner. The packet is the one of the slot's
    // request: an issuer must keep its OVERLAPPED valid for the duration of
    // the operation (WSARecv docs), and on a handle associated with a port
    // the status block "will not be updated until the packet is removed from
    // the completion port"
    // (<https://learn.microsoft.com/en-us/windows/win32/fileio/i-o-completion-ports>),
    // so that lasts until its packet is removed. A packet this module did
    // not queue thus names a live OVERLAPPED, which cannot share an address
    // with this live slot; the pool port's handle never leaves this module.
    // Once its packet is removed the system no longer touches the slot or
    // its buffer.
    Some(unsafe { Box::from_raw(entry.0) })
}

/// Completions a thread takes from the port at once. Getting a full batch
/// back means more are waiting.
const BATCH: usize = 64;
/// At most one thread is added per this interval, so a burst does not start
/// them all at once.
const GROW_INTERVAL: Duration = Duration::from_millis(10);
/// How often a completion goes back to the port because a reader holds its
/// flow, before the completion thread waits for that reader instead.
const MAX_REQUEUES: u8 = 8;

/// The process-wide completion port and the threads completing on it.
///
/// Created on first use and never torn down: the port lives as long as the
/// process, and the threads scale with the load, see
/// [`CompletionThreads`](super::CompletionThreads).
struct Pool {
    port: Port,
    /// Threads running or about to start.
    threads: AtomicUsize,
    /// Threads waiting on the port right now.
    waiting: AtomicUsize,
    /// When a thread was last added, as milliseconds since `created`.
    last_grown_ms: AtomicU64,
    created: Instant,
}

static POOL: OnceLock<Pool> = OnceLock::new();
static STARTING: Mutex<()> = Mutex::new(());

/// The pool, with at least its minimum of threads running. A failure is not
/// remembered: the next wrap retries.
fn pool() -> io::Result<&'static Pool> {
    let pool = if let Some(pool) = POOL.get() {
        pool
    } else {
        create_pool()?
    };
    pool.ensure_minimum(ThreadStartReason::FirstUse)?;
    Ok(pool)
}

fn create_pool() -> io::Result<&'static Pool> {
    let _starting = STARTING.lock();
    if let Some(pool) = POOL.get() {
        return Ok(pool);
    }
    // Concurrency 0 lets as many threads run as there are CPUs; the pool
    // itself decides how many exist.
    // SAFETY: with `INVALID_HANDLE_VALUE` and no existing port,
    // `CreateIoCompletionPort` creates a new port and borrows no handle
    // (CreateIoCompletionPort docs).
    let handle = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, ptr::null_mut(), 0, 0) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(POOL.get_or_init(|| Pool {
        port: Port(handle),
        threads: AtomicUsize::new(0),
        waiting: AtomicUsize::new(0),
        last_grown_ms: AtomicU64::new(0),
        created: Instant::now(),
    }))
}

pub(super) fn running_threads() -> usize {
    POOL.get()
        .map_or(0, |pool| pool.threads.load(Ordering::Relaxed))
}

pub(super) fn completion_threads_changed() {
    let Some(pool) = POOL.get() else {
        return;
    };
    if let Err(err) = pool.ensure_minimum(ThreadStartReason::Minimum) {
        tracing::debug!(
            error = %err,
            "posted recv: starting completion threads for the new minimum failed",
        );
    }
    // Waiting threads would only see a lower maximum or idle timeout when
    // their current wait ends: wake each one up to have it look again.
    for _ in 0..pool.threads.load(Ordering::Acquire) {
        // SAFETY: `PostQueuedCompletionStatus` queues a packet on the open
        // pool port; its OVERLAPPED is null, which the threads skip.
        if unsafe { PostQueuedCompletionStatus(pool.port.0, 0, 0, ptr::null()) } == 0 {
            break;
        }
    }
}

impl Pool {
    fn ensure_minimum(&'static self, reason: ThreadStartReason) -> io::Result<()> {
        let min = completion_threads().min_threads();
        if self.threads.load(Ordering::Acquire) >= min {
            return Ok(());
        }
        let _starting = STARTING.lock();
        let running = self.threads.load(Ordering::Acquire);
        let reason = if running == 0 {
            ThreadStartReason::FirstUse
        } else {
            reason
        };
        for _ in running..min {
            self.threads.fetch_add(1, Ordering::AcqRel);
            if let Err(err) = self.start_thread(reason) {
                // One thread is enough to complete receives.
                if self.threads.load(Ordering::Acquire) == 0 {
                    return Err(err);
                }
                break;
            }
        }
        Ok(())
    }

    /// Start a thread whose place in `threads` is already taken.
    fn start_thread(&'static self, reason: ThreadStartReason) -> io::Result<()> {
        #[cfg(feature = "dial9")]
        let telemetry = ::dial9::Dial9Handle::try_current_thread();
        let spawned = std::thread::Builder::new()
            .name("rama-posted-recv".to_owned())
            .spawn(move || {
                #[cfg(test)]
                let _live = LiveThread::new();
                self.run(move || {
                    #[cfg(feature = "dial9")]
                    if let Some(telemetry) = telemetry {
                        ::dial9::core::set_tl_handle(telemetry);
                    }
                });
            });
        match spawned {
            Ok(_) => {
                let threads = self.threads.load(Ordering::Relaxed);
                tracing::debug!(
                    threads,
                    reason = ?reason,
                    "posted recv: completion thread started",
                );
                #[cfg(feature = "dial9")]
                super::dial9::record_thread_started(threads, reason);
                Ok(())
            }
            Err(err) => {
                self.threads.fetch_sub(1, Ordering::AcqRel);
                tracing::debug!(
                    error = %err,
                    reason = ?reason,
                    "posted recv: starting a completion thread failed",
                );
                Err(err)
            }
        }
    }

    /// Add a thread if every running one is busy and there is room left.
    fn grow(&'static self) {
        if self.waiting.load(Ordering::Acquire) > 0 {
            // An idle thread takes the backlog as soon as the port offers it.
            return;
        }
        let now = u64::try_from(self.created.elapsed().as_millis()).unwrap_or(u64::MAX);
        let last = self.last_grown_ms.load(Ordering::Relaxed);
        if now.saturating_sub(last) < GROW_INTERVAL.as_millis() as u64
            || self
                .last_grown_ms
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        let max = completion_threads().max_threads();
        let reserved = self
            .threads
            .try_update(Ordering::AcqRel, Ordering::Acquire, |threads| {
                (threads < max).then_some(threads + 1)
            })
            .is_ok();
        if reserved {
            // A failure is logged, and the running threads carry on.
            _ = self.start_thread(ThreadStartReason::Backlog);
        }
    }

    /// Give up this thread's place if more than `keep` threads run.
    fn retire(&self, keep: usize, reason: ThreadStopReason) -> Option<Retired> {
        let before = self
            .threads
            .try_update(Ordering::AcqRel, Ordering::Acquire, |threads| {
                (threads > keep).then(|| threads - 1)
            })
            .ok()?;
        // A minimum raised meanwhile may not have counted this thread out
        // yet: stay rather than leave too few. The setter stores the new
        // minimum before topping up, so one of the two always sees it.
        if before - 1 < completion_threads().min_threads() {
            self.threads.fetch_add(1, Ordering::AcqRel);
            return None;
        }
        Some(Retired {
            threads: before - 1,
            reason,
        })
    }

    /// Complete receives until this thread retires. `start` runs first, on
    /// this thread.
    fn run(&'static self, start: impl FnOnce()) {
        let mut start = Some(start);
        // A panic outside the guard around each completion, say in logging,
        // must not end the thread while it still counts as running: carry on.
        let retired = loop {
            let attempt = catch_unwind(AssertUnwindSafe(|| {
                if let Some(start) = start.take() {
                    start();
                    raise_priority();
                }
                #[cfg(test)]
                injected_panic(&PANIC_ON_START);
                self.complete_until_retired()
            }));
            match attempt {
                Ok(retired) => break retired,
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        };
        // No longer counted, so a panic from here on may end the thread.
        tracing::debug!(
            threads = retired.threads,
            reason = ?retired.reason,
            "posted recv: completion thread stopped",
        );
        #[cfg(feature = "dial9")]
        super::dial9::record_thread_stopped(retired.threads, retired.reason);
        #[cfg(test)]
        injected_panic(&PANIC_ON_STOP);
    }

    fn complete_until_retired(&'static self) -> Retired {
        // SAFETY: `mem::zeroed` needs all-zero bytes to be a valid value:
        // OVERLAPPED_ENTRY holds only integers and a raw pointer.
        let mut entries: [OVERLAPPED_ENTRY; BATCH] = unsafe { mem::zeroed() };
        let mut failures: u32 = 0;
        loop {
            let config = completion_threads();
            if let Some(retired) = self.retire(config.max_threads(), ThreadStopReason::OverMaximum)
            {
                return retired;
            }
            let timeout = u32::try_from(config.idle_timeout().as_millis())
                .unwrap_or(INFINITE - 1)
                .min(INFINITE - 1);
            let mut removed = 0;
            self.waiting.fetch_add(1, Ordering::AcqRel);
            // SAFETY: `GetQueuedCompletionStatusEx` writes up to the given count
            // of entries and the number removed: `entries` holds `BATCH`
            // entries, `removed` is a local, and the pool port is never
            // closed. It is not alertable, so no APC runs here.
            let ok = unsafe {
                GetQueuedCompletionStatusEx(
                    self.port.0,
                    entries.as_mut_ptr(),
                    BATCH as u32,
                    &raw mut removed,
                    timeout,
                    0,
                )
            };
            self.waiting.fetch_sub(1, Ordering::AcqRel);
            if ok == 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(WAIT_TIMEOUT as i32) {
                    // The configuration may have changed during the wait.
                    let min = completion_threads().min_threads();
                    if let Some(retired) = self.retire(min, ThreadStopReason::Idle) {
                        return retired;
                    }
                    continue;
                }
                // Only a closed port fails this otherwise, which never happens.
                if failures == 0 {
                    tracing::error!(
                        error = %err,
                        "posted recv: waiting for completions failed",
                    );
                }
                failures = failures.saturating_add(1);
                std::thread::sleep(Duration::from_millis(10 << failures.min(7)));
                continue;
            }
            failures = 0;
            let mut requeued = false;
            let mut panicked = false;
            for entry in &entries[..removed as usize] {
                if entry.lpOverlapped.is_null() {
                    continue;
                }
                let complete = || {
                    // SAFETY: the `take_completed` contract: this packet was
                    // just removed from the pool port.
                    let Some(slot) = (unsafe { take_completed(entry.lpOverlapped) }) else {
                        #[cfg(test)]
                        SKIPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        tracing::trace!(
                            "posted recv: skipped a completion that is not a posted receive"
                        );
                        return true;
                    };
                    Slot::complete(slot, entry.dwNumberOfBytesTransferred, self.port)
                };
                // A panic, say in a waker or a log subscriber, must not drop
                // the other dequeued entries.
                match catch_unwind(AssertUnwindSafe(complete)) {
                    Ok(handled) => requeued |= !handled,
                    Err(_) => panicked = true,
                }
            }
            // Only after every dequeued entry was handled, as these may panic.
            if panicked {
                tracing::error!("posted recv: handling a completion panicked");
            }
            #[cfg(test)]
            injected_panic(&PANIC_AFTER_BATCH);
            if removed as usize == BATCH {
                self.grow();
            }
            if requeued {
                std::thread::yield_now();
            }
        }
    }
}

/// A completion thread that gave up its place in [`Pool::threads`].
struct Retired {
    /// Threads left running.
    threads: usize,
    reason: ThreadStopReason,
}

/// Raise the calling thread's priority, logging a failure.
fn raise_priority() {
    // Bytes that arrive while no receive is posted stay exposed to a reset
    // until a completion thread posts the next one, so these should not wait
    // behind busy workers. Their work per completion is small and bounded.
    // SAFETY: `GetCurrentThread` has no preconditions; it returns a pseudo
    // handle for the calling thread.
    let thread = unsafe { GetCurrentThread() };
    // SAFETY: `SetThreadPriority` needs a thread handle with
    // THREAD_SET_INFORMATION access: the current-thread pseudo handle has
    // full access (GetCurrentThread docs) and is used on this thread.
    if unsafe { SetThreadPriority(thread, THREAD_PRIORITY_ABOVE_NORMAL) } == 0 {
        tracing::debug!(
            error = %io::Error::last_os_error(),
            "posted recv: raising the completion thread priority failed",
        );
    }
}

/// One receive buffer with its OVERLAPPED.
///
/// Owned by whoever holds its box, or by the system and the port while it is
/// registered in [`IN_PORT`].
#[repr(C)]
struct Slot {
    // Must stay first: completions are looked up by its address.
    // Safety invariant: the system accesses this and the heap buffer of
    // `buf` only while the slot is registered in `IN_PORT`, so never while a
    // `Box<Slot>` owns it.
    overlapped: OVERLAPPED,
    buf: Box<[u8]>,
    seq: u64,
    /// How often its current completion went back to the port.
    requeues: u8,
    flow: Arc<Flow>,
}

const _: () = assert!(mem::offset_of!(Slot, overlapped) == 0);

// SAFETY: the fields that are not `Send` are the `hEvent` and `Pointer` raw
// pointers of the OVERLAPPED, which this module keeps 0 and never
// dereferences; the system completes the request from any thread by design.
// A slot has one owner at a time: its box, or `IN_PORT`.
unsafe impl Send for Slot {}

impl Slot {
    fn new(flow: Arc<Flow>, size: usize) -> Box<Self> {
        Box::new(Self {
            // SAFETY: `mem::zeroed` needs all-zero bytes to be a valid value:
            // OVERLAPPED holds only integers and raw pointers, and zero is
            // its initial state.
            overlapped: unsafe { mem::zeroed() },
            buf: vec![0; size].into_boxed_slice(),
            seq: 0,
            requeues: 0,
            flow,
        })
    }

    /// Called on the completion thread for each completed receive. Returns
    /// false if the completion was queued again to be handled later.
    fn complete(mut slot: Box<Self>, bytes: u32, port: Port) -> bool {
        #[cfg(test)]
        slot.flow.lag();
        // Keeps the flow alive until the lock is released; dropping it last
        // may close the socket of a reader that is gone.
        let flow = slot.flow.clone();
        if let Some(state) = flow.state.try_lock() {
            Self::complete_locked(slot, &flow, state);
            return true;
        }
        if slot.requeues >= MAX_REQUEUES {
            // The reader keeps the lock longer than a few rounds through the
            // port: wait for it rather than spin.
            #[cfg(test)]
            WAITED_FOR_READER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Self::complete_locked(slot, &flow, flow.state.lock());
            return true;
        }
        // A reader holds the lock. Come back to this one later rather than
        // hold up the completions of every other flow behind it.
        slot.requeues += 1;
        #[cfg(test)]
        REQUEUED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // SAFETY: the `hand_over` contract: `raw` goes to the one post
        // below, and is taken back if that post fails.
        let raw = unsafe { hand_over(slot) };
        // SAFETY: `PostQueuedCompletionStatus` only queues the pointer value
        // on the open pool port; the slot is registered, so the completion
        // thread that dequeues it takes it back with `take_completed`.
        if unsafe { PostQueuedCompletionStatus(port.0, bytes, 0, raw.cast::<OVERLAPPED>()) } != 0 {
            return false;
        }
        // SAFETY: the `take_back` contract: `raw` came from `hand_over` and
        // the failed post queued no packet.
        let Some(slot) = (unsafe { take_back(raw) }) else {
            // Not reached: only the slot's own packet removes its entry.
            return false;
        };
        Self::complete_locked(slot, &flow, flow.state.lock());
        true
    }

    fn complete_locked(slot: Box<Self>, flow: &Flow, mut state: MutexGuard<'_, State>) {
        #[cfg(test)]
        OUTSTANDING.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        state.in_flight -= 1;
        if state.closing {
            drop(state);
            drop(slot);
            return;
        }
        // SAFETY: the `outcome` contract: the flow is not closing, so by the
        // `Flow::socket` invariant its socket is open, and every receive of
        // this flow is posted on it. The slot is owned by its box, so by the
        // `Slot::overlapped` invariant the system is done with its receive.
        let outcome = unsafe { slot.outcome(flow.socket) };
        let seq = slot.seq;
        let mut news = flow.completed(&mut state, seq, slot, outcome);
        if let Some(code) = outcome.blocked {
            Flow::mark_blocked(&mut state, code);
        }
        news |= flow.refill(&mut state);
        let waker = if news { state.waker.take() } else { None };
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// # Safety
    ///
    /// The caller must ensure that `socket` is the open socket the slot's
    /// receive was posted on, and that the system completed that receive.
    unsafe fn outcome(&self, socket: SOCKET) -> Outcome {
        let mut transferred = 0;
        let mut flags = 0;
        // Asking Winsock rather than decoding `Internal` ourselves also holds
        // for providers that do not complete with an NTSTATUS.
        // SAFETY: `WSAGetOverlappedResult` with `fWait` false reads the
        // OVERLAPPED of an overlapped request on `socket` and writes the two
        // locals: by this function's contract `socket` is open and is the
        // one the request used, which completed, so the system no longer
        // writes the OVERLAPPED that `&self` borrows.
        let ok = unsafe {
            WSAGetOverlappedResult(
                socket,
                &raw const self.overlapped,
                &raw mut transferred,
                0,
                &raw mut flags,
            )
        };
        if ok == 0 {
            // SAFETY: `WSAGetLastError` has no preconditions.
            return Outcome::failed(unsafe { WSAGetLastError() });
        }
        let data = transferred as usize;
        Outcome {
            data,
            end: (data == 0).then_some(End::Eof),
            blocked: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Outcome {
    data: usize,
    end: Option<End>,
    /// The receive failed for lack of resources, with this error, and is
    /// worth retrying.
    blocked: Option<i32>,
}

impl Outcome {
    fn failed(code: i32) -> Self {
        let (end, blocked) = match code {
            WSA_OPERATION_ABORTED => (Some(End::Cancelled), None),
            code if is_resource_error(code) => (None, Some(code)),
            code => (Some(End::Os(code)), None),
        };
        Self {
            data: 0,
            end,
            blocked,
        }
    }
}

/// Errors of a receive that failed for lack of buffers or locked pages,
/// rather than because of the connection.
fn is_resource_error(code: i32) -> bool {
    code == WSAENOBUFS
        || code == WSA_NOT_ENOUGH_MEMORY
        || u32::try_from(code).is_ok_and(|code| {
            matches!(
                code,
                ERROR_NO_SYSTEM_RESOURCES
                    | ERROR_NONPAGED_SYSTEM_RESOURCES
                    | ERROR_PAGED_SYSTEM_RESOURCES
                    | ERROR_WORKING_SET_QUOTA
                    | ERROR_NOT_ENOUGH_QUOTA
            )
        })
}

/// How the stream ended.
#[derive(Debug, Clone, Copy)]
enum End {
    Eof,
    Os(i32),
    Kind(io::ErrorKind),
    Cancelled,
}

impl End {
    fn result(self) -> io::Result<()> {
        match self {
            Self::Eof => Ok(()),
            Self::Os(code) => Err(io::Error::from_raw_os_error(code)),
            Self::Kind(kind) => Err(kind.into()),
            Self::Cancelled => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "posted receive was cancelled",
            )),
        }
    }
}

enum Posted {
    Pending,
    /// Failed for lack of resources with this error; the slot is idle again.
    Blocked(i32),
    /// The receive ended the stream.
    Ended,
}

struct Flow {
    // Safety invariant: an open socket attached to the pool's port while
    // `state.closing` is false, and while `state.socket` holds it. It does
    // not have FILE_SKIP_COMPLETION_PORT_ON_SUCCESS set, and no other code
    // issues overlapped I/O on it.
    socket: SOCKET,
    slot_size: usize,
    max_buffered: usize,
    state: Mutex<State>,
    #[cfg(test)]
    fail_posts: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    completion_delay_ms: std::sync::atomic::AtomicU64,
}

/// A received buffer, handed over from a slot without copying.
struct Chunk {
    buf: Box<[u8]>,
    len: usize,
    read: usize,
}

struct State {
    /// Received chunks not fully read yet, in stream order.
    ready: VecDeque<Chunk>,
    /// Unread bytes in `ready`.
    buffered: usize,
    /// A read-out buffer kept for the next completed slot while more chunks
    /// wait, which saves an allocation per chunk for a lagging reader.
    spare: Option<Box<[u8]>>,
    /// Slots that are not posted.
    #[expect(
        clippy::vec_box,
        reason = "a slot keeps its address while the kernel holds it, outside this list"
    )]
    idle: Vec<Box<Slot>>,
    /// Completions that arrived ahead of an earlier receive.
    early: Vec<(u64, Box<Slot>, Outcome)>,
    in_flight: usize,
    next_post: u64,
    next_append: u64,
    /// Set once any receive ended the stream.
    stop_posting: bool,
    /// Set while receives fail for lack of resources.
    blocked: bool,
    /// Set once the end is next in stream order.
    end: Option<End>,
    waker: Option<Waker>,
    /// Set when the reader is dropped; nothing is posted from then on.
    closing: bool,
    /// Owns the socket handle after the reader is dropped, so that it is
    /// closed only once the cancelled receives completed.
    socket: Option<std::net::TcpStream>,
}

#[cfg(test)]
impl Drop for Flow {
    fn drop(&mut self) {
        LIVE_FLOWS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Flow {
    /// # Safety
    ///
    /// The caller must ensure the `Flow::socket` invariant for `socket`: it
    /// is open and attached to the pool's port, and stays open until
    /// `state.closing` is set; it has no FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
    /// mode, and no other code issues overlapped I/O on it.
    unsafe fn new(socket: SOCKET, config: &PostedRecvConfig) -> Self {
        #[cfg(test)]
        LIVE_FLOWS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self {
            socket,
            slot_size: config.slot_size,
            max_buffered: config.max_buffered,
            state: Mutex::new(State {
                ready: VecDeque::new(),
                buffered: 0,
                spare: None,
                idle: Vec::with_capacity(config.slots),
                early: Vec::new(),
                in_flight: 0,
                next_post: 0,
                next_append: 0,
                stop_posting: false,
                blocked: false,
                end: None,
                waker: None,
                closing: false,
                socket: None,
            }),
            #[cfg(test)]
            fail_posts: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            completion_delay_ms: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Post idle slots while the reader is not too far behind. Returns
    /// whether the reader has something new.
    ///
    /// Posts nothing unless `state` is the guard of this flow's lock.
    fn refill(&self, state: &mut MutexGuard<'_, State>) -> bool {
        let own = ptr::eq(MutexGuard::mutex(state), &raw const self.state);
        debug_assert!(own, "refill needs the state of its own flow");
        if !own {
            return false;
        }
        let state = &mut **state;
        let mut news = false;
        while !state.closing && !state.stop_posting && state.buffered <= self.max_buffered {
            let Some(slot) = state.idle.pop() else {
                break;
            };
            // SAFETY: the `post` contract: `state` is this flow's locked state
            // (checked above) and the loop condition checked `!state.closing`.
            match unsafe { self.post(state, slot) } {
                Posted::Pending => state.blocked = false,
                Posted::Ended => news = true,
                Posted::Blocked(code) => {
                    Self::mark_blocked(state, code);
                    // With nothing in flight no completion comes to retry,
                    // so the reader has to read on its own meanwhile.
                    news |= state.in_flight == 0;
                    break;
                }
            }
        }
        news
    }

    /// Receives fail for lack of resources: reads pass through until one can
    /// be posted again. Reported once per episode.
    fn mark_blocked(state: &mut State, code: i32) {
        if !state.blocked {
            tracing::debug!(
                error = %io::Error::from_raw_os_error(code),
                "posted recv: out of buffers, reads pass through until receives can be posted",
            );
            #[cfg(feature = "dial9")]
            super::dial9::record_blocked(code);
        }
        state.blocked = true;
    }

    /// Post a receive into `slot`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `state` is the state of `self`, borrowed
    /// from its locked mutex, and that `state.closing` is false.
    unsafe fn post(&self, state: &mut State, mut slot: Box<Slot>) -> Posted {
        // Posting under the lock keeps post order equal to sequence order,
        // which is the order the kernel fills the receives in.
        let seq = state.next_post;
        state.next_post += 1;
        slot.seq = seq;
        slot.requeues = 0;
        // SAFETY: as in `Slot::new`. The box owns the slot, so the system no
        // longer uses it (the `Slot::overlapped` invariant).
        slot.overlapped = unsafe { mem::zeroed() };
        let err = if let Some(err) = self.injected_failure() {
            err
        } else {
            let buf = WSABUF {
                len: u32::try_from(slot.buf.len()).unwrap_or(u32::MAX),
                buf: slot.buf.as_mut_ptr(),
            };
            // SAFETY: the `hand_over` contract: `raw` goes to the one
            // receive below, and is taken back if it fails synchronously.
            let raw = unsafe { hand_over(slot) };
            let mut flags = 0;
            // Receives may be posted from tokio workers that exit later;
            // I/O on a handle attached to a completion port is not
            // cancelled when the thread that issued it exits.
            // SAFETY: an overlapped `WSARecv` needs an open socket, one
            // `WSABUF` valid for the call, and a buffer and OVERLAPPED that
            // stay valid and untouched until the request completes (WSARecv
            // docs). This flow's `state.closing` is false (this function's
            // contract), so the socket is open (the `Flow::socket`
            // invariant); `buf` is a local covering at most the slot's
            // buffer; the registered slot keeps both alive and unaccessed
            // until `take_completed` returns it after completion (the
            // `IN_PORT` invariant). The byte count pointer is null, as
            // overlapped requests allow, and the flags are a local.
            let rc = unsafe {
                WSARecv(
                    self.socket,
                    &raw const buf,
                    1,
                    ptr::null_mut(),
                    &raw mut flags,
                    raw.cast::<OVERLAPPED>(),
                    None,
                )
            };
            let err = if rc == SOCKET_ERROR {
                // SAFETY: `WSAGetLastError` has no preconditions.
                unsafe { WSAGetLastError() }
            } else {
                0
            };
            // An immediate success still queues a completion: the socket has
            // no FILE_SKIP_COMPLETION_PORT_ON_SUCCESS mode (the `Flow::socket`
            // invariant).
            if rc == 0 || err == WSA_IO_PENDING {
                state.in_flight += 1;
                #[cfg(test)]
                OUTSTANDING.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Posted::Pending;
            }
            // SAFETY: the `take_back` contract: `raw` came from `hand_over`,
            // and a `WSARecv` failing with another error queues no
            // completion (WSARecv docs).
            let Some(back) = (unsafe { take_back(raw) }) else {
                // Not reached: only the slot's own packet removes its entry.
                state.in_flight += 1;
                #[cfg(test)]
                OUTSTANDING.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Posted::Pending;
            };
            slot = back;
            err
        };
        let outcome = Outcome::failed(err);
        self.completed(state, seq, slot, outcome);
        match outcome.blocked {
            Some(code) => Posted::Blocked(code),
            None => Posted::Ended,
        }
    }

    #[cfg(test)]
    fn injected_failure(&self) -> Option<i32> {
        use std::sync::atomic::Ordering;
        self.fail_posts
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
            .ok()
            .map(|_| WSAENOBUFS)
    }

    #[cfg(not(test))]
    #[expect(clippy::unused_self, reason = "the test build injects failures here")]
    fn injected_failure(&self) -> Option<i32> {
        None
    }

    /// Hold up the completion thread, as a busy one would be.
    #[cfg(test)]
    fn lag(&self) {
        let ms = self
            .completion_delay_ms
            .load(std::sync::atomic::Ordering::Relaxed);
        if ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }

    /// Record the outcome of receive `seq` in stream order. Returns whether
    /// the reader has something new.
    fn completed(&self, state: &mut State, seq: u64, slot: Box<Slot>, outcome: Outcome) -> bool {
        if outcome.end.is_some() {
            state.stop_posting = true;
        }
        if seq != state.next_append {
            state.early.push((seq, slot, outcome));
            return false;
        }
        let mut news = self.append(state, slot, outcome);
        while let Some(i) = state
            .early
            .iter()
            .position(|(seq, ..)| *seq == state.next_append)
        {
            let (_, slot, outcome) = state.early.swap_remove(i);
            news |= self.append(state, slot, outcome);
        }
        news
    }

    fn append(&self, state: &mut State, mut slot: Box<Slot>, outcome: Outcome) -> bool {
        state.next_append += 1;
        let news = state.end.is_none() && (outcome.data > 0 || outcome.end.is_some());
        if state.end.is_none() && outcome.data > 0 {
            let len = outcome.data.min(slot.buf.len());
            // Small receives are copied onto the last chunk, so that every
            // chunk but the last holds at least a quarter of a slot and the
            // chunks of a trickling stream do not pin a buffer each.
            match state.ready.back_mut() {
                Some(tail) if len <= self.slot_size / 4 && tail.buf.len() - tail.len >= len => {
                    tail.buf[tail.len..tail.len + len].copy_from_slice(&slot.buf[..len]);
                    tail.len += len;
                }
                _ => {
                    let fresh = state
                        .spare
                        .take()
                        .unwrap_or_else(|| vec![0; self.slot_size].into_boxed_slice());
                    let buf = mem::replace(&mut slot.buf, fresh);
                    state.ready.push_back(Chunk { buf, len, read: 0 });
                }
            }
            state.buffered += len;
        }
        if state.end.is_none() {
            state.end = outcome.end;
        }
        state.idle.push(slot);
        news
    }
}

/// What [`Reader::poll_read`] wants the caller to do.
pub(super) enum ReadStep {
    Ready(io::Result<()>),
    Pending,
    /// No receive can be posted right now: read through the inner stream,
    /// then report back with [`Reader::direct_read`].
    Direct,
}

/// The reading side of a [`PostedRecv`](super::PostedRecv).
pub(super) struct Reader {
    flow: Arc<Flow>,
}

impl Reader {
    /// Attach `socket` to the pool's port and post its first receives.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    ///
    /// - `socket` is an open socket handle that stays open until
    ///   [`Reader::stop`] returned on the returned reader, and is never closed
    ///   if `stop` is never called;
    /// - no other code issues overlapped I/O on `socket` while the reader
    ///   lives: its packets would reach the pool's port, which skips them, so
    ///   its issuer would never see them complete;
    /// - `socket` does not have `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS` set
    ///   (a completion mode cannot be removed once set), so a receive that
    ///   succeeds at once still queues its packet.
    ///
    /// On error the socket was not attached and nothing was posted on it.
    pub(super) unsafe fn new(socket: RawSocket, config: &PostedRecvConfig) -> io::Result<Self> {
        let port = pool()?.port;
        // `RawSocket` widens a `SOCKET`.
        let socket = SOCKET::try_from(socket)
            .map_err(|_err| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `CreateIoCompletionPort` with an existing port associates
        // an open handle with it, or fails without effect (CreateIoCompletionPort
        // docs). `socket` is open (this function's contract) and the pool
        // port is never closed.
        let attached =
            unsafe { CreateIoCompletionPort(ptr::without_provenance_mut(socket), port.0, 0, 0) };
        if attached.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the `Flow::new` contract: `socket` is open, attached just
        // above, and stays open until `stop` set `closing`; it has no skip
        // mode and no other overlapped I/O (this function's contract).
        let flow = Arc::new(unsafe { Flow::new(socket, config) });
        let mut state = flow.state.lock();
        state.idle = (0..config.slots)
            .map(|_| Slot::new(flow.clone(), config.slot_size))
            .collect();
        flow.refill(&mut state);
        drop(state);
        Ok(Self { flow })
    }

    pub(super) fn poll_read(&self, cx: &Context<'_>, buf: &mut ReadBuf<'_>) -> ReadStep {
        if buf.remaining() == 0 {
            return ReadStep::Ready(Ok(()));
        }
        let mut guard = self.flow.state.lock();
        if guard.blocked && guard.buffered == 0 {
            self.flow.refill(&mut guard);
            // Nothing posted and nothing queued: reading directly cannot
            // take bytes out of order.
            if guard.in_flight == 0 && guard.early.is_empty() && guard.end.is_none() {
                return ReadStep::Direct;
            }
        }
        let state = &mut *guard;
        if state.buffered > 0 {
            while buf.remaining() > 0
                && let Some(chunk) = state.ready.front_mut()
            {
                let n = buf.remaining().min(chunk.len - chunk.read);
                buf.put_slice(&chunk.buf[chunk.read..chunk.read + n]);
                chunk.read += n;
                state.buffered -= n;
                if chunk.read == chunk.len
                    && let Some(chunk) = state.ready.pop_front()
                    && state.spare.is_none()
                {
                    state.spare = Some(chunk.buf);
                }
            }
            if state.ready.is_empty() {
                // An idle flow then only holds its posted buffers.
                state.spare = None;
            }
            self.flow.refill(&mut guard);
            return ReadStep::Ready(Ok(()));
        }
        if let Some(end) = state.end {
            return ReadStep::Ready(end.result());
        }
        if !state
            .waker
            .as_ref()
            .is_some_and(|waker| waker.will_wake(cx.waker()))
        {
            state.waker = Some(cx.waker().clone());
        }
        ReadStep::Pending
    }

    /// Record the end of the stream seen by a direct read.
    pub(super) fn direct_read(&self, result: &Poll<io::Result<()>>, filled: usize) {
        let end = match result {
            Poll::Ready(Ok(())) if filled == 0 => End::Eof,
            Poll::Ready(Err(err)) => err.raw_os_error().map_or(End::Kind(err.kind()), End::Os),
            _ => return,
        };
        let mut state = self.flow.state.lock();
        state.end = Some(end);
        state.stop_posting = true;
    }

    /// Stop posting receives. Must run before the socket leaves tokio, since
    /// a receive posted on a closed socket handle could land on whatever
    /// reuses the handle.
    pub(super) fn stop(&self) {
        // `Flow::socket` invariant: from here on the socket may close.
        self.flow.state.lock().closing = true;
    }

    /// Cancel the pending receives and close the socket once they completed.
    pub(super) fn close(&self, stream: io::Result<std::net::TcpStream>) {
        let mut state = self.flow.state.lock();
        debug_assert!(state.closing, "stop must run first");
        // `Flow::socket` invariant: set before `stream` can close below.
        state.closing = true;
        let idle = mem::take(&mut state.idle);
        let early = mem::take(&mut state.early);
        let waker = state.waker.take();
        // If tokio failed to hand the socket back it closed its handle
        // already, so there is none left to cancel through: the slots come
        // back as their receives complete.
        let close_now = match stream {
            Ok(stream) if state.in_flight > 0 => {
                state.socket = Some(stream);
                None
            }
            stream => stream.ok(),
        };
        let cancel = state.socket.is_some();
        drop(state);
        if cancel {
            // SAFETY: `CancelIoEx` with a null OVERLAPPED cancels the pending
            // I/O on an open handle (CancelIoEx docs): `state.socket` holds
            // the handle, so it is open (the `Flow::socket` invariant), and
            // it is closed only when the last slot drops the flow.
            unsafe { CancelIoEx(ptr::without_provenance_mut(self.flow.socket), ptr::null()) };
        }
        drop(close_now);
        drop((idle, early, waker));
    }

    #[cfg(test)]
    pub(super) fn watch(&self) -> FlowWatch {
        FlowWatch(Arc::downgrade(&self.flow))
    }

    /// Make the next `n` posts fail as if the system ran out of buffers.
    #[cfg(test)]
    pub(super) fn fail_next_posts(&self, n: usize) {
        self.flow
            .fail_posts
            .store(n, std::sync::atomic::Ordering::Relaxed);
    }

    /// Delay the handling of each completion of this flow by `delay`.
    #[cfg(test)]
    pub(super) fn delay_completions(&self, delay: std::time::Duration) {
        self.flow.completion_delay_ms.store(
            u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// A handle to hold the flow with, see [`FlowHandle::hold`].
    #[cfg(test)]
    pub(super) fn flow(&self) -> FlowHandle {
        FlowHandle(self.flow.clone())
    }
}

/// Lets a test hold a flow.
#[cfg(test)]
pub(super) struct FlowHandle(Arc<Flow>);

#[cfg(test)]
impl FlowHandle {
    /// Hold the flow, as a reader in the middle of a read does.
    pub(super) fn hold(&self) -> HeldFlow<'_> {
        HeldFlow {
            _state: self.0.state.lock(),
        }
    }
}

/// A flow held by a test, see [`FlowHandle::hold`].
#[cfg(test)]
pub(super) struct HeldFlow<'a> {
    _state: MutexGuard<'a, State>,
}

/// Tells whether a flow, and with it its socket, is gone.
#[cfg(test)]
pub(super) struct FlowWatch(std::sync::Weak<Flow>);

#[cfg(test)]
impl FlowWatch {
    pub(super) fn is_closed(&self) -> bool {
        self.0.strong_count() == 0
    }
}
