//! Overlapped receives kept posted on the socket, completed by a single
//! process-wide completion thread.
//!
//! mio attaches only its AFD helper handle to its own completion port, never
//! the socket, so the socket is free to be attached to ours. Tokio keeps
//! doing the writes; its read readiness goes stale, which is harmless since
//! nothing reads through it.

use std::{
    cell::UnsafeCell,
    collections::VecDeque,
    io, mem,
    os::windows::io::RawSocket,
    ptr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use parking_lot::Mutex;
use rama_core::telemetry::tracing;
use tokio::io::ReadBuf;
use windows_sys::Win32::{
    Foundation::{
        HANDLE, INVALID_HANDLE_VALUE, NTSTATUS, STATUS_CANCELLED, STATUS_CONNECTION_ABORTED,
        STATUS_CONNECTION_RESET, STATUS_LOCAL_DISCONNECT, STATUS_REMOTE_DISCONNECT,
    },
    Networking::WinSock::{
        SOCKET, SOCKET_ERROR, WSA_IO_PENDING, WSABUF, WSAECONNABORTED, WSAECONNRESET,
        WSAGetLastError, WSAGetOverlappedResult, WSARecv,
    },
    System::{
        IO::{
            CancelIoEx, CreateIoCompletionPort, GetQueuedCompletionStatusEx, OVERLAPPED,
            OVERLAPPED_ENTRY,
        },
        Threading::{GetCurrentThread, INFINITE, SetThreadPriority, THREAD_PRIORITY_ABOVE_NORMAL},
    },
};

use super::PostedRecvConfig;

/// Receives posted and not completed yet, across all flows.
static OUTSTANDING: AtomicUsize = AtomicUsize::new(0);
/// Flows whose socket is not closed yet, across all flows.
static LIVE_FLOWS: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
pub(super) fn outstanding_receives() -> usize {
    OUTSTANDING.load(Ordering::Relaxed)
}

#[cfg(test)]
pub(super) fn live_flows() -> usize {
    LIVE_FLOWS.load(Ordering::Relaxed)
}

#[derive(Clone, Copy)]
struct Port(HANDLE);

// SAFETY: a completion port handle may be used from any thread.
unsafe impl Send for Port {}
// SAFETY: as above.
unsafe impl Sync for Port {}

/// The process-wide completion port, created with its thread on first use
/// and never closed.
fn port() -> io::Result<HANDLE> {
    static PORT: OnceLock<Result<Port, io::Error>> = OnceLock::new();
    match PORT.get_or_init(start_port) {
        Ok(port) => Ok(port.0),
        Err(err) => Err(io::Error::new(err.kind(), err.to_string())),
    }
}

fn start_port() -> io::Result<Port> {
    // SAFETY: creates a new port without borrowing any handle.
    let handle = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, ptr::null_mut(), 0, 1) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    let port = Port(handle);
    // A dedicated thread rather than the thread pool: completions are
    // handled in the order they were queued, and keep being handled while
    // tokio workers are busy.
    std::thread::Builder::new()
        .name("rama-posted-recv".to_owned())
        .spawn(move || run_completions(port))?;
    Ok(port)
}

fn run_completions(port: Port) {
    const BATCH: usize = 64;
    // Bytes beyond the posted buffers stay exposed to a reset until this
    // thread posts the next receive, so it should not wait behind busy
    // workers. Its work per completion is small and bounded.
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
    loop {
        let mut removed = 0;
        // SAFETY: `entries` has room for BATCH entries and the port is never closed.
        let ok = unsafe {
            GetQueuedCompletionStatusEx(
                port.0,
                entries.as_mut_ptr(),
                BATCH as u32,
                &mut removed,
                INFINITE,
                0,
            )
        };
        if ok == 0 {
            // Only a timeout or a closed port fail this, and neither happens.
            tracing::error!(
                error = %io::Error::last_os_error(),
                "posted recv: waiting for completions failed",
            );
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        for entry in &entries[..removed as usize] {
            if entry.lpOverlapped.is_null() {
                continue;
            }
            // SAFETY: only slots post receives on sockets attached to this
            // port, each passing the `Arc::into_raw` pointer of the slot,
            // whose first field is the OVERLAPPED.
            let slot = unsafe { Arc::from_raw(entry.lpOverlapped.cast_const().cast::<Slot>()) };
            Slot::complete(slot, entry.dwNumberOfBytesTransferred);
        }
    }
}

/// One receive buffer with its OVERLAPPED.
///
/// Whoever posted it owns it: the kernel while the receive is pending,
/// otherwise the holder of the flow lock.
#[repr(C)]
struct Slot {
    // Must stay first: the kernel hands back a pointer to it.
    overlapped: UnsafeCell<OVERLAPPED>,
    buf: UnsafeCell<Box<[u8]>>,
    seq: AtomicU64,
    flow: Arc<Flow>,
}

// SAFETY: the cells are only accessed by the slot's single owner at a time,
// see the type docs.
unsafe impl Send for Slot {}
// SAFETY: as above.
unsafe impl Sync for Slot {}

impl Slot {
    fn new(flow: Arc<Flow>, size: usize) -> Self {
        Self {
            // SAFETY: OVERLAPPED is plain data and zero is its initial state.
            overlapped: UnsafeCell::new(unsafe { mem::zeroed() }),
            buf: UnsafeCell::new(vec![0; size].into_boxed_slice()),
            seq: AtomicU64::new(0),
            flow,
        }
    }

    /// Reset the OVERLAPPED and describe the buffer for a new receive.
    ///
    /// # Safety
    ///
    /// The slot must not be posted, and the flow lock must be held.
    unsafe fn prepare(&self) -> WSABUF {
        // SAFETY: OVERLAPPED is plain data and zero is its initial state.
        let zeroed = unsafe { mem::zeroed() };
        // SAFETY: nobody else uses the slot, per the caller.
        unsafe { *self.overlapped.get() = zeroed };
        // SAFETY: as above.
        let buf = unsafe { &mut *self.buf.get() };
        WSABUF {
            len: u32::try_from(buf.len()).unwrap_or(u32::MAX),
            buf: buf.as_mut_ptr(),
        }
    }

    /// The buffer of a completed receive.
    ///
    /// # Safety
    ///
    /// The receive must have completed, and the flow lock must be held.
    #[expect(
        clippy::mut_from_ref,
        reason = "the slot is exclusively ours, see the type docs"
    )]
    unsafe fn completed_buf(&self) -> &mut Box<[u8]> {
        // SAFETY: the kernel is done with the buffer, per the caller.
        unsafe { &mut *self.buf.get() }
    }

    /// Called on the completion thread for each completed receive.
    fn complete(slot: Arc<Self>, bytes: u32) {
        OUTSTANDING.fetch_sub(1, Ordering::Relaxed);
        // Keeps the flow alive until the lock is released; dropping it last
        // may close the socket of a reader that is gone.
        let flow = slot.flow.clone();
        let mut state = flow.state.lock();
        state.in_flight -= 1;
        if state.closing {
            drop(state);
            drop(slot);
            return;
        }
        let outcome = slot.outcome(bytes, flow.socket);
        let seq = slot.seq.load(Ordering::Relaxed);
        let news = flow.completed(&mut state, seq, slot, outcome) | flow.refill(&mut state);
        let waker = if news { state.waker.take() } else { None };
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn outcome(&self, bytes: u32, socket: SOCKET) -> Outcome {
        // SAFETY: the receive completed, so the kernel no longer writes it.
        let status = unsafe { (*self.overlapped.get()).Internal } as NTSTATUS;
        let data = bytes as usize;
        let end = match status {
            // NT_SUCCESS; zero bytes on success is the peer's FIN.
            0.. => (data == 0).then_some(End::Eof),
            STATUS_CONNECTION_RESET | STATUS_REMOTE_DISCONNECT => Some(End::Os(WSAECONNRESET)),
            STATUS_CONNECTION_ABORTED | STATUS_LOCAL_DISCONNECT => Some(End::Os(WSAECONNABORTED)),
            STATUS_CANCELLED => Some(End::Cancelled),
            status => Some(overlapped_error(socket, self.overlapped.get(), status)),
        };
        Outcome { data, end }
    }
}

/// Map any other status the way Winsock does, since std decodes WSA codes but
/// not the Win32 codes `GetOverlappedResult` would give.
fn overlapped_error(socket: SOCKET, overlapped: *const OVERLAPPED, status: NTSTATUS) -> End {
    let mut transferred = 0;
    let mut flags = 0;
    // SAFETY: the receive completed and the flow is not closing, so its
    // reader still owns the socket.
    let ok = unsafe { WSAGetOverlappedResult(socket, overlapped, &mut transferred, 0, &mut flags) };
    let code = if ok == 0 {
        // SAFETY: no preconditions.
        unsafe { WSAGetLastError() }
    } else {
        0
    };
    if code == 0 {
        End::Status(status)
    } else {
        End::Os(code)
    }
}

#[derive(Debug, Clone, Copy)]
struct Outcome {
    data: usize,
    end: Option<End>,
}

/// How the stream ended.
#[derive(Debug, Clone, Copy)]
enum End {
    Eof,
    Os(i32),
    Cancelled,
    Status(NTSTATUS),
}

impl End {
    fn result(self) -> io::Result<()> {
        match self {
            Self::Eof => Ok(()),
            Self::Os(code) => Err(io::Error::from_raw_os_error(code)),
            Self::Cancelled => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "posted receive was cancelled",
            )),
            Self::Status(status) => Err(io::Error::other(format!(
                "posted receive failed with status {status:#x}"
            ))),
        }
    }
}

struct Flow {
    socket: SOCKET,
    slot_size: usize,
    max_buffered: usize,
    state: Mutex<State>,
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
    /// A read-out buffer kept for the next completed slot, which saves an
    /// allocation per chunk in a busy flow.
    spare: Option<Box<[u8]>>,
    /// Slots that are not posted.
    idle: Vec<Arc<Slot>>,
    /// Completions that arrived ahead of an earlier receive.
    early: Vec<(u64, Arc<Slot>, Outcome)>,
    in_flight: usize,
    next_post: u64,
    next_append: u64,
    /// Set once any receive ended the stream.
    stop_posting: bool,
    /// Set once the end is next in stream order.
    end: Option<End>,
    waker: Option<Waker>,
    /// Set when the reader is dropped; nothing is posted from then on.
    closing: bool,
    /// Owns the socket after the reader is dropped, so that it is closed
    /// only once the cancelled receives completed.
    socket: Option<std::net::TcpStream>,
}

impl Drop for Flow {
    fn drop(&mut self) {
        LIVE_FLOWS.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Flow {
    fn new(socket: SOCKET, config: &PostedRecvConfig) -> Self {
        LIVE_FLOWS.fetch_add(1, Ordering::Relaxed);
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
                end: None,
                waker: None,
                closing: false,
                socket: None,
            }),
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
            news |= self.post(state, slot);
        }
        news
    }

    fn post(&self, state: &mut State, slot: Arc<Slot>) -> bool {
        // Posting under the lock keeps post order equal to sequence order,
        // which is the order the kernel fills the receives in.
        let seq = state.next_post;
        state.next_post += 1;
        slot.seq.store(seq, Ordering::Relaxed);
        // SAFETY: the slot was idle and the lock is held.
        let buf = unsafe { slot.prepare() };
        let raw = Arc::into_raw(slot);
        OUTSTANDING.fetch_add(1, Ordering::Relaxed);
        let mut flags = 0;
        // SAFETY: the socket is open while the flow is not closing, and `raw`
        // keeps the OVERLAPPED and the buffer alive until the completion
        // thread takes the slot back.
        let rc = unsafe {
            WSARecv(
                self.socket,
                &buf,
                1,
                ptr::null_mut(),
                &mut flags,
                raw.cast::<OVERLAPPED>().cast_mut(),
                None,
            )
        };
        let err = if rc == SOCKET_ERROR {
            // SAFETY: no preconditions.
            unsafe { WSAGetLastError() }
        } else {
            0
        };
        // An immediate success still queues a completion.
        if rc == 0 || err == WSA_IO_PENDING {
            state.in_flight += 1;
            return false;
        }
        OUTSTANDING.fetch_sub(1, Ordering::Relaxed);
        // SAFETY: nothing is queued for a receive that failed synchronously,
        // so the reference is still ours.
        let slot = unsafe { Arc::from_raw(raw) };
        let end = Outcome {
            data: 0,
            end: Some(End::Os(err)),
        };
        self.completed(state, seq, slot, end)
    }

    /// Record the outcome of receive `seq` in stream order. Returns whether
    /// the reader has something new.
    fn completed(&self, state: &mut State, seq: u64, slot: Arc<Slot>, outcome: Outcome) -> bool {
        if outcome.end.is_some() {
            state.stop_posting = true;
        }
        if seq != state.next_append {
            state.early.push((seq, slot, outcome));
            return false;
        }
        let mut news = self.append(state, &slot, outcome);
        state.idle.push(slot);
        while let Some(i) = state
            .early
            .iter()
            .position(|(seq, ..)| *seq == state.next_append)
        {
            let (_, slot, outcome) = state.early.swap_remove(i);
            news |= self.append(state, &slot, outcome);
            state.idle.push(slot);
        }
        news
    }

    fn append(&self, state: &mut State, slot: &Slot, outcome: Outcome) -> bool {
        state.next_append += 1;
        if state.end.is_some() {
            return false;
        }
        if outcome.data > 0 {
            // SAFETY: the receive completed and the lock is held.
            let buf = unsafe { slot.completed_buf() };
            let len = outcome.data.min(buf.len());
            // Small receives are copied onto the last chunk, so that every
            // chunk but the last holds at least a quarter of a slot and the
            // chunks of a trickling stream do not pin a buffer each.
            match state.ready.back_mut() {
                Some(tail) if len <= self.slot_size / 4 && tail.buf.len() - tail.len >= len => {
                    tail.buf[tail.len..tail.len + len].copy_from_slice(&buf[..len]);
                    tail.len += len;
                }
                _ => {
                    let fresh = state
                        .spare
                        .take()
                        .unwrap_or_else(|| vec![0; self.slot_size].into_boxed_slice());
                    let buf = mem::replace(buf, fresh);
                    state.ready.push_back(Chunk { buf, len, read: 0 });
                }
            }
            state.buffered += len;
        }
        state.end = outcome.end;
        true
    }
}

/// The reading side of a [`PostedRecv`](super::PostedRecv).
pub(super) struct Reader {
    flow: Arc<Flow>,
}

impl Reader {
    pub(super) fn new(socket: RawSocket, config: &PostedRecvConfig) -> io::Result<Self> {
        let port = port()?;
        let socket = socket as SOCKET;
        // SAFETY: the socket is open and owned by the stream being wrapped.
        let attached = unsafe { CreateIoCompletionPort(socket as HANDLE, port, 0, 0) };
        if attached.is_null() {
            return Err(io::Error::last_os_error());
        }
        let flow = Arc::new(Flow::new(socket, config));
        let mut state = flow.state.lock();
        state.idle = (0..config.slots)
            .map(|_| Arc::new(Slot::new(flow.clone(), config.slot_size)))
            .collect();
        flow.refill(&mut state);
        drop(state);
        Ok(Self { flow })
    }

    pub(super) fn poll_read(
        &self,
        cx: &Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut state = self.flow.state.lock();
        if state.buffered > 0 {
            let state = &mut *state;
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
            self.flow.refill(state);
            return Poll::Ready(Ok(()));
        }
        if let Some(end) = state.end {
            return Poll::Ready(end.result());
        }
        if !state
            .waker
            .as_ref()
            .is_some_and(|waker| waker.will_wake(cx.waker()))
        {
            state.waker = Some(cx.waker().clone());
        }
        Poll::Pending
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
