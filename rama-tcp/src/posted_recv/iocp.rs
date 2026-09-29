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
    collections::VecDeque,
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

#[derive(Clone, Copy)]
struct Port(HANDLE);

// SAFETY: a completion port handle may be used from any thread.
unsafe impl Send for Port {}
// SAFETY: as above.
unsafe impl Sync for Port {}

/// Completions a thread takes from the port at once. Getting a full batch
/// back means more are waiting.
const BATCH: usize = 64;
/// At most one thread is added per this interval, so a burst does not start
/// them all at once.
const GROW_INTERVAL: Duration = Duration::from_millis(10);

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
static STARTING: Mutex<()> = parking_lot::const_mutex(());

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
    // SAFETY: creates a new port without borrowing any handle.
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
    if let Some(pool) = POOL.get()
        && let Err(err) = pool.ensure_minimum(ThreadStartReason::Minimum)
    {
        tracing::debug!(
            error = %err,
            "posted recv: starting completion threads for the new minimum failed",
        );
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
                #[cfg(feature = "dial9")]
                if let Some(telemetry) = telemetry {
                    ::dial9::core::set_tl_handle(telemetry);
                }
                self.run();
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
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |threads| {
                (threads < max).then_some(threads + 1)
            })
            .is_ok();
        if reserved {
            // A failure is logged, and the running threads carry on.
            _ = self.start_thread(ThreadStartReason::Backlog);
        }
    }

    /// Give up this thread's place if more than `keep` threads run.
    fn retire(&self, keep: usize, reason: ThreadStopReason) -> bool {
        let retired = self
            .threads
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |threads| {
                (threads > keep).then(|| threads - 1)
            });
        let Ok(before) = retired else {
            return false;
        };
        // A minimum raised meanwhile may not have counted this thread out
        // yet: stay rather than leave too few. The setter stores the new
        // minimum before topping up, so one of the two always sees it.
        if before - 1 < completion_threads().min_threads() {
            self.threads.fetch_add(1, Ordering::AcqRel);
            return false;
        }
        tracing::debug!(
            threads = before - 1,
            reason = ?reason,
            "posted recv: completion thread stopped",
        );
        #[cfg(feature = "dial9")]
        super::dial9::record_thread_stopped(before - 1, reason);
        true
    }

    fn run(&'static self) {
        // Bytes that arrive while no receive is posted stay exposed to a
        // reset until a completion thread posts the next one, so these
        // should not wait behind busy workers. Their work per completion is
        // small and bounded.
        // SAFETY: no preconditions; the pseudo handle refers to this thread.
        let thread = unsafe { GetCurrentThread() };
        // SAFETY: `thread` is valid for the life of this thread.
        if unsafe { SetThreadPriority(thread, THREAD_PRIORITY_ABOVE_NORMAL) } == 0 {
            tracing::debug!(
                error = %io::Error::last_os_error(),
                "posted recv: raising the completion thread priority failed",
            );
        }
        // SAFETY: OVERLAPPED_ENTRY is plain data.
        let mut entries: [OVERLAPPED_ENTRY; BATCH] = unsafe { mem::zeroed() };
        let mut failures: u32 = 0;
        loop {
            let config = completion_threads();
            if self.retire(config.max_threads(), ThreadStopReason::OverMaximum) {
                return;
            }
            let timeout = u32::try_from(config.idle_timeout().as_millis())
                .unwrap_or(INFINITE - 1)
                .min(INFINITE - 1);
            let mut removed = 0;
            self.waiting.fetch_add(1, Ordering::AcqRel);
            // SAFETY: `entries` has room for BATCH entries and the port is
            // never closed.
            let ok = unsafe {
                GetQueuedCompletionStatusEx(
                    self.port.0,
                    entries.as_mut_ptr(),
                    BATCH as u32,
                    &mut removed,
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
                    if self.retire(min, ThreadStopReason::Idle) {
                        return;
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
            if removed as usize == BATCH {
                self.grow();
            }
            let mut requeued = false;
            for entry in &entries[..removed as usize] {
                if entry.lpOverlapped.is_null() {
                    continue;
                }
                // SAFETY: only slots post receives on sockets attached to
                // this port, each passing the `Box::into_raw` pointer of the
                // slot, whose first field is the OVERLAPPED.
                let slot = unsafe { Box::from_raw(entry.lpOverlapped.cast::<Slot>()) };
                let bytes = entry.dwNumberOfBytesTransferred;
                // A panic, say in a waker, must not stop the completions of
                // every other flow.
                if let Ok(handled) =
                    catch_unwind(AssertUnwindSafe(|| Slot::complete(slot, bytes, self.port)))
                {
                    requeued |= !handled;
                } else {
                    tracing::error!("posted recv: handling a completion panicked");
                }
            }
            if requeued {
                std::thread::yield_now();
            }
        }
    }
}

/// One receive buffer with its OVERLAPPED.
///
/// Owned by whoever holds its box, or by the kernel while its receive is
/// pending.
#[repr(C)]
struct Slot {
    // Must stay first: the kernel hands back a pointer to it.
    overlapped: OVERLAPPED,
    buf: Box<[u8]>,
    seq: u64,
    flow: Arc<Flow>,
}

// SAFETY: a slot has a single owner at a time, and the raw pointer in its
// OVERLAPPED is plain data to us.
unsafe impl Send for Slot {}

impl Slot {
    fn new(flow: Arc<Flow>, size: usize) -> Box<Self> {
        Box::new(Self {
            // SAFETY: OVERLAPPED is plain data and zero is its initial state.
            overlapped: unsafe { mem::zeroed() },
            buf: vec![0; size].into_boxed_slice(),
            seq: 0,
            flow,
        })
    }

    /// Called on the completion thread for each completed receive. Returns
    /// false if the completion was queued again to be handled later.
    fn complete(slot: Box<Self>, bytes: u32, port: Port) -> bool {
        // Keeps the flow alive until the lock is released; dropping it last
        // may close the socket of a reader that is gone.
        let flow = slot.flow.clone();
        if let Some(state) = flow.state.try_lock() {
            Self::complete_locked(slot, &flow, state);
            return true;
        }
        // A reader holds the lock. Come back to this one later rather than
        // hold up the completions of every other flow behind it.
        let raw = Box::into_raw(slot);
        // SAFETY: the packet hands the slot back to this thread, as the
        // kernel's completion did.
        if unsafe { PostQueuedCompletionStatus(port.0, bytes, 0, raw.cast::<OVERLAPPED>()) } != 0 {
            return false;
        }
        // SAFETY: nothing was queued, so the slot is still ours.
        let slot = unsafe { Box::from_raw(raw) };
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
        let outcome = slot.outcome(flow.socket);
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

    fn outcome(&self, socket: SOCKET) -> Outcome {
        let mut transferred = 0;
        let mut flags = 0;
        // Asking Winsock rather than decoding `Internal` ourselves also holds
        // for providers that do not complete with an NTSTATUS.
        // SAFETY: the receive completed and the flow is not closing, so its
        // reader still owns the socket.
        let ok = unsafe {
            WSAGetOverlappedResult(socket, &self.overlapped, &mut transferred, 0, &mut flags)
        };
        if ok == 0 {
            // SAFETY: no preconditions.
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
    socket: SOCKET,
    slot_size: usize,
    max_buffered: usize,
    state: Mutex<State>,
    #[cfg(test)]
    fail_posts: std::sync::atomic::AtomicUsize,
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
    /// Owns the socket after the reader is dropped, so that it is closed
    /// only once the cancelled receives completed.
    socket: Option<std::net::TcpStream>,
}

#[cfg(test)]
impl Drop for Flow {
    fn drop(&mut self) {
        LIVE_FLOWS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Flow {
    fn new(socket: SOCKET, config: &PostedRecvConfig) -> Self {
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
        }
    }

    /// Post idle slots while the reader is not too far behind. Returns
    /// whether the reader has something new.
    fn refill(&self, state: &mut State) -> bool {
        let mut news = false;
        while !state.closing && !state.stop_posting && state.buffered <= self.max_buffered {
            let Some(slot) = state.idle.pop() else {
                break;
            };
            match self.post(state, slot) {
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

    fn post(&self, state: &mut State, mut slot: Box<Slot>) -> Posted {
        // Posting under the lock keeps post order equal to sequence order,
        // which is the order the kernel fills the receives in.
        let seq = state.next_post;
        state.next_post += 1;
        slot.seq = seq;
        // SAFETY: OVERLAPPED is plain data and zero is its initial state.
        slot.overlapped = unsafe { mem::zeroed() };
        let err = if let Some(err) = self.injected_failure() {
            err
        } else {
            let buf = WSABUF {
                len: u32::try_from(slot.buf.len()).unwrap_or(u32::MAX),
                buf: slot.buf.as_mut_ptr(),
            };
            let raw = Box::into_raw(slot);
            let mut flags = 0;
            // Receives may be posted from tokio workers that exit later;
            // I/O on a handle attached to a completion port is not
            // cancelled when the thread that issued it exits.
            // SAFETY: the socket is open while the flow is not closing,
            // and `raw` keeps the OVERLAPPED and the buffer alive until
            // the completion thread takes the slot back.
            let rc = unsafe {
                WSARecv(
                    self.socket,
                    &buf,
                    1,
                    ptr::null_mut(),
                    &mut flags,
                    raw.cast::<OVERLAPPED>(),
                    None,
                )
            };
            let err = if rc == SOCKET_ERROR {
                // SAFETY: no preconditions.
                unsafe { WSAGetLastError() }
            } else {
                0
            };
            // An immediate success still queues a completion, since
            // FILE_SKIP_COMPLETION_PORT_ON_SUCCESS is never set on the
            // socket.
            if rc == 0 || err == WSA_IO_PENDING {
                state.in_flight += 1;
                #[cfg(test)]
                OUTSTANDING.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Posted::Pending;
            }
            // SAFETY: nothing is queued for a receive that failed
            // synchronously, so the slot is still ours.
            slot = unsafe { Box::from_raw(raw) };
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
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
            .ok()
            .map(|_| WSAENOBUFS)
    }

    #[cfg(not(test))]
    #[expect(clippy::unused_self, reason = "the test build injects failures here")]
    fn injected_failure(&self) -> Option<i32> {
        None
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
    pub(super) fn new(socket: RawSocket, config: &PostedRecvConfig) -> io::Result<Self> {
        let port = pool()?.port;
        let socket = socket as SOCKET;
        // SAFETY: the socket is open and owned by the stream being wrapped.
        let attached = unsafe { CreateIoCompletionPort(socket as HANDLE, port.0, 0, 0) };
        if attached.is_null() {
            return Err(io::Error::last_os_error());
        }
        let flow = Arc::new(Flow::new(socket, config));
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
        let mut state = self.flow.state.lock();
        let state = &mut *state;
        if state.blocked && state.buffered == 0 {
            self.flow.refill(state);
            // Nothing posted and nothing queued: reading directly cannot
            // take bytes out of order.
            if state.in_flight == 0 && state.early.is_empty() && state.end.is_none() {
                return ReadStep::Direct;
            }
        }
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
            self.flow.refill(state);
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
        self.flow.state.lock().closing = true;
    }

    /// Cancel the pending receives and close the socket once they completed.
    pub(super) fn close(&self, stream: io::Result<std::net::TcpStream>) {
        let mut state = self.flow.state.lock();
        debug_assert!(state.closing, "stop must run first");
        let idle = mem::take(&mut state.idle);
        let early = mem::take(&mut state.early);
        let waker = state.waker.take();
        // If tokio failed to hand the socket back it already closed it,
        // which also cancelled the receives.
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
            // SAFETY: the flow owns the open socket until the cancelled
            // receives completed. Only our receives are overlapped I/O on it.
            unsafe { CancelIoEx(self.flow.socket as HANDLE, ptr::null()) };
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
