//! Raw overlapped `WSARecv` on a socket attached to a completion port of our
//! own, with no abstractions in between. The assertions pin the OS behaviour
//! [`PostedRecv`](crate::posted_recv::PostedRecv) relies on; everything else
//! is printed as evidence.

use std::{
    io::{Read, Write},
    mem,
    net::{SocketAddr, TcpListener, TcpStream},
    os::windows::io::AsRawSocket,
    ptr,
    thread::{self, JoinHandle},
    time::Duration,
};

use rama_net::socket::core::SockRef;
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_NETNAME_DELETED, GetLastError, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS,
        STATUS_CANCELLED, STATUS_CONNECTION_RESET,
    },
    Networking::WinSock::{
        SOCKET, SOCKET_ERROR, WSA_IO_PENDING, WSABUF, WSAECONNABORTED, WSAECONNRESET,
        WSAGetLastError, WSAGetOverlappedResult, WSARecv,
    },
    System::IO::{
        CancelIoEx, CreateIoCompletionPort, GetOverlappedResult, GetQueuedCompletionStatusEx,
        OVERLAPPED, OVERLAPPED_ENTRY,
    },
};

use super::harness::{REQUEST, reply};

const WAIT: Duration = Duration::from_millis(100);

struct Port(HANDLE);

// SAFETY: a completion port handle can be used from any thread.
unsafe impl Send for Port {}

impl Port {
    fn new() -> Self {
        // SAFETY: creating a fresh port, no handles borrowed.
        let port = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, ptr::null_mut(), 0, 1) };
        assert!(!port.is_null(), "CreateIoCompletionPort failed");
        Self(port)
    }

    fn attach(&self, socket: SOCKET) {
        // SAFETY: `socket` is a live socket owned by the caller.
        let port = unsafe { CreateIoCompletionPort(socket as HANDLE, self.0, 0, 0) };
        assert_eq!(port, self.0, "attaching the socket failed");
    }

    /// Collect completions until `timeout` passes without a new one.
    fn drain(&self, timeout: Duration) -> Vec<Done> {
        let mut done = Vec::new();
        loop {
            // SAFETY: OVERLAPPED_ENTRY is plain data.
            let mut entries: [OVERLAPPED_ENTRY; 16] = unsafe { mem::zeroed() };
            let mut n = 0;
            // SAFETY: `entries` has room for 16 entries.
            let ok = unsafe {
                GetQueuedCompletionStatusEx(
                    self.0,
                    entries.as_mut_ptr(),
                    16,
                    &mut n,
                    timeout.as_millis() as u32,
                    0,
                )
            };
            if ok == 0 {
                return done;
            }
            for entry in &entries[..n as usize] {
                let op = entry.lpOverlapped.cast::<Op>();
                // SAFETY: every posted OVERLAPPED is the first field of an `Op`
                // that the test keeps alive until its completion is collected.
                let status = unsafe { (*op).ov.Internal } as NTSTATUS;
                done.push(Done {
                    op,
                    bytes: entry.dwNumberOfBytesTransferred,
                    status,
                });
            }
        }
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        // SAFETY: the port is owned by us.
        unsafe { CloseHandle(self.0) };
    }
}

#[repr(C)]
struct Op {
    ov: OVERLAPPED,
    buf: Vec<u8>,
    id: usize,
}

impl Op {
    fn new(id: usize, len: usize) -> Box<Self> {
        Box::new(Self {
            // SAFETY: OVERLAPPED is plain data and all zeroes is its initial state.
            ov: unsafe { mem::zeroed() },
            buf: vec![0; len],
            id,
        })
    }
}

#[derive(Debug)]
struct Done {
    op: *mut Op,
    bytes: u32,
    status: NTSTATUS,
}

impl Done {
    fn op(&self) -> &Op {
        // SAFETY: the op outlives the test step that collected it and the
        // kernel no longer touches it once completed.
        unsafe { &*self.op }
    }

    fn data(&self) -> &[u8] {
        &self.op().buf[..self.bytes as usize]
    }
}

/// Post an overlapped receive; returns 0 on immediate success or the WSA error.
fn post(socket: SOCKET, op: &mut Op) -> i32 {
    let buf = WSABUF {
        len: op.buf.len() as u32,
        buf: op.buf.as_mut_ptr(),
    };
    let mut flags = 0;
    // SAFETY: `op` stays alive and unmoved until its completion is collected.
    let rc = unsafe {
        WSARecv(
            socket,
            &buf,
            1,
            ptr::null_mut(),
            &mut flags,
            &mut op.ov,
            None,
        )
    };
    if rc == SOCKET_ERROR {
        // SAFETY: no preconditions.
        unsafe { WSAGetLastError() }
    } else {
        0
    }
}

/// What `WSAGetOverlappedResult` and `GetOverlappedResult` report for a
/// completed op, as raw error codes (0 for success).
fn overlapped_results(socket: SOCKET, op: &Op) -> (i32, u32) {
    let mut bytes = 0;
    let mut flags = 0;
    // SAFETY: `op` is completed, so the call only reads it.
    let wsa = if unsafe { WSAGetOverlappedResult(socket, &op.ov, &mut bytes, 0, &mut flags) } == 0 {
        // SAFETY: no preconditions.
        unsafe { WSAGetLastError() }
    } else {
        0
    };
    // SAFETY: as above; with `bWait = FALSE` the handle is not waited on.
    let win = if unsafe { GetOverlappedResult(socket as HANDLE, &op.ov, &mut bytes, 0) } == 0 {
        // SAFETY: no preconditions.
        unsafe { GetLastError() }
    } else {
        0
    };
    (wsa, win)
}

fn raw(stream: &TcpStream) -> SOCKET {
    stream.as_raw_socket() as SOCKET
}

/// A connected client plus the origin thread serving its peer.
fn pair<R, F>(serve: F) -> (TcpStream, JoinHandle<R>)
where
    F: FnOnce(TcpStream) -> R + Send + 'static,
    R: Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let origin = thread::spawn(move || serve(listener.accept().unwrap().0));
    let client = TcpStream::connect(addr).unwrap();
    client.set_nonblocking(true).unwrap();
    (client, origin)
}

/// Read the request, reply with `len` bytes, then reset.
fn reply_then_reset(len: usize) -> impl FnOnce(TcpStream) + Send + 'static {
    move |mut peer| {
        let mut req = vec![0; REQUEST.len()];
        peer.read_exact(&mut req).unwrap();
        peer.write_all(&reply(len)).unwrap();
        thread::sleep(Duration::from_millis(5));
        SockRef::from(&peer)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
    }
}

fn send_request(client: &TcpStream) {
    let mut client = client;
    client.write_all(REQUEST).unwrap();
}

/// Q1, Q2 and the reset status of Q4: a posted read keeps the reply that
/// arrives before the reset, and the next read reports the reset.
#[test]
fn posted_read_keeps_data_that_arrives_before_reset() {
    for len in [234, 1843, 6554] {
        let port = Port::new();
        let (client, origin) = pair(reply_then_reset(len));
        port.attach(raw(&client));

        let mut first = Op::new(1, 16 * 1024);
        let mut second = Op::new(2, 16 * 1024);
        let rc = post(raw(&client), &mut first);
        eprintln!("ws1/q1 N={len}: overlapped WSARecv on FIONBIO socket -> {rc}");
        assert_eq!(
            rc, WSA_IO_PENDING,
            "Q1: expected WSA_IO_PENDING, not WSAEWOULDBLOCK"
        );
        assert_eq!(post(raw(&client), &mut second), WSA_IO_PENDING);

        send_request(&client);
        origin.join().unwrap();
        thread::sleep(WAIT);

        let done = port.drain(WAIT);
        assert_eq!(done.len(), 2);
        eprintln!(
            "ws1/q2 N={len}: first completion bytes={} status={:#x}",
            done[0].bytes, done[0].status
        );
        assert_eq!(done[0].status, 0);
        assert_eq!(done[0].data(), reply(len), "Q2: the posted read lost data");

        let results = overlapped_results(raw(&client), done[1].op());
        eprintln!(
            "ws1/q4 reset N={len}: second completion bytes={} status={:#x} (WSAGetOverlappedResult, GetOverlappedResult)={results:?}",
            done[1].bytes, done[1].status
        );
        assert_eq!(done[1].status, STATUS_CONNECTION_RESET);
        assert_eq!(
            results,
            (WSAECONNRESET, ERROR_NETNAME_DELETED),
            "Q4: reset maps to WSAECONNRESET / ERROR_NETNAME_DELETED"
        );

        let mut third = Op::new(3, 16 * 1024);
        let rc = post(raw(&client), &mut third);
        eprintln!("ws1/q4 reset N={len}: read posted after the reset -> {rc}");
        assert_eq!(rc, WSAECONNRESET);
    }
}

/// Q3: several posted reads fill in the order they were posted.
#[test]
fn posted_reads_fill_in_post_order() {
    let len = 6554;
    let port = Port::new();
    let (client, origin) = pair(reply_then_reset(len));
    port.attach(raw(&client));

    let mut ops: Vec<_> = (0..5).map(|id| Op::new(id, 1500)).collect();
    for op in &mut ops {
        assert_eq!(post(raw(&client), op), WSA_IO_PENDING);
    }
    send_request(&client);
    origin.join().unwrap();
    thread::sleep(WAIT);

    let done = port.drain(WAIT);
    let order: Vec<_> = done
        .iter()
        .map(|d| (d.op().id, d.bytes, d.status))
        .collect();
    eprintln!("ws1/q3 completions in dequeue order (id, bytes, status): {order:x?}");

    let mut by_post_order: Vec<&Done> = done.iter().collect();
    by_post_order.sort_by_key(|d| d.op().id);
    let data: Vec<u8> = by_post_order
        .iter()
        .filter(|d| d.status == 0)
        .flat_map(|d| d.data().iter().copied())
        .collect();
    assert_eq!(
        data,
        reply(len),
        "Q3: data in post order must equal the reply"
    );
    assert!(
        done.windows(2).all(|w| w[0].op().id < w[1].op().id),
        "Q3: completions were dequeued out of post order"
    );
}

/// Q4: the status of a cancelled read and of a graceful end of stream.
#[test]
fn completion_status_for_cancel_and_eof() {
    let port = Port::new();
    let (client, origin) = pair(|mut peer: TcpStream| {
        let mut req = vec![0; REQUEST.len()];
        peer.read_exact(&mut req).unwrap();
        thread::sleep(Duration::from_millis(50));
        peer.write_all(&reply(100)).unwrap();
    });
    port.attach(raw(&client));

    let mut cancelled = Op::new(0, 1024);
    assert_eq!(post(raw(&client), &mut cancelled), WSA_IO_PENDING);
    // SAFETY: the socket is live and the op is still owned by the kernel.
    let ok = unsafe { CancelIoEx(raw(&client) as HANDLE, &cancelled.ov) };
    assert_ne!(ok, 0);
    let done = port.drain(WAIT);
    let results = overlapped_results(raw(&client), done[0].op());
    eprintln!(
        "ws1/q4 cancel: status={:#x} bytes={} (WSAGetOverlappedResult, GetOverlappedResult)={results:?}",
        done[0].status, done[0].bytes
    );
    assert_eq!(done[0].status, STATUS_CANCELLED);

    let mut data = Op::new(1, 1024);
    let mut eof = Op::new(2, 1024);
    assert_eq!(post(raw(&client), &mut data), WSA_IO_PENDING);
    assert_eq!(post(raw(&client), &mut eof), WSA_IO_PENDING);
    send_request(&client);
    origin.join().unwrap();
    thread::sleep(WAIT);
    let done = port.drain(WAIT);
    let summary: Vec<_> = done
        .iter()
        .map(|d| (d.op().id, d.bytes, d.status))
        .collect();
    let results = overlapped_results(raw(&client), done[1].op());
    eprintln!("ws1/q4 graceful eof: (id, bytes, status)={summary:x?} results={results:?}");
    assert_eq!(done[0].data(), reply(100));
    assert_eq!((done[1].bytes, done[1].status), (0, 0));
}

/// Q4: the status of an abort after we wrote to a peer that already closed.
#[test]
fn completion_status_for_send_after_peer_close() {
    let port = Port::new();
    let (client, origin) = pair(|mut peer: TcpStream| {
        let mut req = vec![0; REQUEST.len()];
        peer.read_exact(&mut req).unwrap();
        peer.write_all(&reply(100)).unwrap();
    });
    port.attach(raw(&client));
    let mut kept = Op::new(0, 1024);
    assert_eq!(post(raw(&client), &mut kept), WSA_IO_PENDING);
    send_request(&client);
    origin.join().unwrap();
    thread::sleep(Duration::from_millis(30));
    let write = (&client)
        .write_all(b"late")
        .map_err(|err| err.raw_os_error());
    thread::sleep(Duration::from_millis(30));

    let mut op = Op::new(1, 1024);
    let rc = post(raw(&client), &mut op);
    let done = port.drain(WAIT);
    let summary: Vec<_> = done
        .iter()
        .map(|d| (d.op().id, d.bytes, d.status))
        .collect();
    eprintln!(
        "ws1/q4 send after peer close: write={write:?} post after write rc={rc} completions (id, bytes, status)={summary:x?}"
    );
    assert_eq!(done[0].data(), reply(100), "the posted read kept the reply");
    assert_eq!(rc, WSAECONNABORTED);
}

/// Q4: what a pending read completes with when we close our own socket.
#[test]
fn completion_status_for_local_close() {
    let port = Port::new();
    let (client, origin) = pair(|mut peer: TcpStream| {
        let mut buf = [0; 16];
        _ = peer.read(&mut buf);
    });
    port.attach(raw(&client));
    let mut op = Op::new(0, 1024);
    assert_eq!(post(raw(&client), &mut op), WSA_IO_PENDING);
    let socket = raw(&client);
    drop(client);
    let done = port.drain(WAIT);
    let (_, win) = overlapped_results(socket, done[0].op());
    eprintln!(
        "ws1/q4 local close: status={:#x} bytes={} GetOverlappedResult={win}",
        done[0].status, done[0].bytes
    );
    origin.join().unwrap();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerSaw {
    Fin,
    Reset,
    Other,
}

/// Q5: does closing with a read still posted reset the peer, and does
/// cancelling and waiting for the cancellation first avoid that?
#[test]
fn close_with_posted_read() {
    fn run(cancel_first: bool, post_read: bool) -> PeerSaw {
        let port = Port::new();
        let (client, origin) = pair(|mut peer: TcpStream| {
            let mut buf = [0; 16];
            match peer.read(&mut buf) {
                Ok(0) => PeerSaw::Fin,
                Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => PeerSaw::Reset,
                _ => PeerSaw::Other,
            }
        });
        port.attach(raw(&client));
        let mut op = Op::new(0, 1024);
        if post_read {
            assert_eq!(post(raw(&client), &mut op), WSA_IO_PENDING);
        }
        if post_read && cancel_first {
            // SAFETY: the socket is live.
            unsafe { CancelIoEx(raw(&client) as HANDLE, ptr::null()) };
            let done = port.drain(WAIT);
            assert_eq!(done[0].status, STATUS_CANCELLED);
        }
        drop(client);
        // The op must outlive a pending completion caused by the close.
        _ = port.drain(WAIT);
        origin.join().unwrap()
    }

    for (label, cancel_first, post_read) in [
        ("no posted read", false, false),
        ("close with posted read", false, true),
        ("cancel, wait, then close", true, true),
    ] {
        let seen: Vec<_> = (0..20).map(|_| run(cancel_first, post_read)).collect();
        let fin = seen.iter().filter(|s| **s == PeerSaw::Fin).count();
        let reset = seen.iter().filter(|s| **s == PeerSaw::Reset).count();
        eprintln!(
            "ws1/q5 {label}: peer saw fin={fin} reset={reset} of {}",
            seen.len()
        );
    }
}

/// With the socket attached to a port, a read posted from a thread that has
/// exited since is not cancelled (thread-agnostic I/O).
#[test]
fn read_posted_from_exited_thread_survives() {
    let port = Port::new();
    let (client, origin) = pair(reply_then_reset(234));
    port.attach(raw(&client));
    let socket = raw(&client);
    let mut op = Op::new(0, 16 * 1024);
    let op_addr = &raw mut *op as usize;
    let rc = thread::spawn(move || {
        // SAFETY: the op is kept alive by the test until it completes.
        post(socket, unsafe { &mut *(op_addr as *mut Op) })
    })
    .join()
    .unwrap();
    assert_eq!(rc, WSA_IO_PENDING);
    thread::sleep(Duration::from_millis(20));
    send_request(&client);
    origin.join().unwrap();
    thread::sleep(WAIT);
    let done = port.drain(WAIT);
    eprintln!(
        "ws1/extra exited thread: status={:#x} bytes={}",
        done[0].status, done[0].bytes
    );
    assert_eq!(done[0].status, 0);
    assert_eq!(done[0].data(), reply(234));
}

/// A read posted while data is already queued may succeed right away; the
/// completion packet is still queued since we never skip it on success.
#[test]
fn immediate_success_still_queues_a_completion() {
    let port = Port::new();
    let (client, origin) = pair(|mut peer: TcpStream| {
        let mut req = vec![0; REQUEST.len()];
        peer.read_exact(&mut req).unwrap();
        peer.write_all(&reply(234)).unwrap();
        let mut buf = [0; 1];
        _ = peer.read(&mut buf);
    });
    port.attach(raw(&client));
    send_request(&client);
    thread::sleep(Duration::from_millis(30));
    let mut op = Op::new(0, 16 * 1024);
    let rc = post(raw(&client), &mut op);
    let done = port.drain(WAIT);
    eprintln!(
        "ws1/extra data already queued: post rc={rc} completions={}",
        done.len()
    );
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].data(), reply(234));
    drop(client);
    origin.join().unwrap();
}
