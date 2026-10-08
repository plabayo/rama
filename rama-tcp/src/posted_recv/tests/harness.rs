//! Loopback peers that reply and then close in a chosen way, plus a client
//! helper that reads everything up to the end of the stream.

use std::{io, net::SocketAddr, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    task::JoinHandle,
};

pub(super) const REQUEST: &[u8] = b"PING\r\n";

/// How long a single flow may take before a test gives up on it.
const FLOW_TIMEOUT: Duration = Duration::from_secs(30);

/// A loopback listener with a backlog deep enough for a thousand clients
/// connecting at once, which a default backlog would silently drop.
pub(super) fn listen() -> TcpListener {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(([127, 0, 0, 1], 0).into()).unwrap();
    socket.listen(4096).unwrap()
}

/// How the origin ends a connection after writing its reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Close {
    /// Read the request, reply, then close with zero linger (RST).
    Reset,
    /// Read the request, reply, then close gracefully (FIN).
    Fin,
    /// Wait for the request without reading it, reply and close. Closing with
    /// unread input turns the close into a reset (rama#1156).
    UnreadInput,
}

/// Replies are a counting pattern so that loss, truncation and reordering all
/// show up as a mismatch.
pub(super) fn reply(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

pub(super) struct Origin {
    pub(super) addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Spawn an origin that answers every connection with `reply(len)` and then
/// closes as `close` says, right after the reply was acknowledged.
pub(super) async fn spawn_origin(len: usize, close: Close) -> Origin {
    let body = reply(len);
    spawn_origin_fn(move |stream| {
        let body = body.clone();
        async move {
            _ = serve_one(stream, &body, close).await;
        }
    })
    .await
}

async fn serve_one(mut stream: TcpStream, body: &[u8], close: Close) -> io::Result<()> {
    if close == Close::UnreadInput {
        stream.readable().await?;
    } else {
        let mut req = vec![0; REQUEST.len()];
        stream.read_exact(&mut req).await?;
    }
    stream.write_all(body).await?;
    if close == Close::Reset {
        stream.set_zero_linger()?;
    }
    if close != Close::Fin {
        // An abortive close discards what this side has not sent yet.
        wait_until_acked(&stream, body.len()).await?;
    }
    drop(stream);
    Ok(())
}

/// Wait until the `sent` bytes written to `stream` went out and were
/// acknowledged, so that a reset right after cannot discard any of them.
pub(super) async fn wait_until_acked(stream: &TcpStream, sent: usize) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + FLOW_TIMEOUT;
    while !acked(stream, sent)? {
        if tokio::time::Instant::now() > deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn acked(stream: &TcpStream, sent: usize) -> io::Result<bool> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        SIO_TCP_INFO, SOCKET, SOCKET_ERROR, TCP_INFO_v0, WSAIoctl,
    };

    let version: u32 = 0;
    let mut info = TCP_INFO_v0::default();
    let mut returned = 0;
    // SAFETY: the socket is open, and the buffers match the v0 layout.
    let rc = unsafe {
        WSAIoctl(
            stream.as_raw_socket() as SOCKET,
            SIO_TCP_INFO,
            (&raw const version).cast(),
            size_of::<u32>() as u32,
            (&raw mut info).cast(),
            size_of::<TCP_INFO_v0>() as u32,
            &mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if rc == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }
    Ok(info.BytesOut >= sent as u64 && info.BytesInFlight == 0)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn acked(stream: &TcpStream, _sent: usize) -> io::Result<bool> {
    use std::os::fd::AsRawFd;

    let mut queued: libc::c_int = 0;
    // SAFETY: the socket is open and TIOCOUTQ writes one int.
    let rc = unsafe { libc::ioctl(stream.as_raw_fd(), libc::TIOCOUTQ as _, &mut queued) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(queued == 0)
}

#[cfg(target_vendor = "apple")]
fn acked(stream: &TcpStream, _sent: usize) -> io::Result<bool> {
    use std::os::fd::AsRawFd;

    let mut queued: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: the socket is open and SO_NWRITE writes one int.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NWRITE,
            (&raw mut queued).cast(),
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(queued == 0)
}

#[cfg(not(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple"
)))]
fn acked(_: &TcpStream, _: usize) -> io::Result<bool> {
    Ok(true)
}

/// Everything a reader saw up to the end of the stream.
#[derive(Debug)]
pub(super) struct Received {
    pub(super) bytes: Vec<u8>,
    /// `Ok` for a clean end of stream.
    pub(super) end: io::Result<()>,
}

impl Received {
    pub(super) fn is_complete(&self, len: usize) -> bool {
        self.bytes.len() == len && self.bytes == reply(len)
    }

    pub(super) fn end_kind(&self) -> Option<io::ErrorKind> {
        self.end.as_ref().err().map(io::Error::kind)
    }

    pub(super) fn raw_os_error(&self) -> Option<i32> {
        self.end.as_ref().err().and_then(io::Error::raw_os_error)
    }
}

pub(super) async fn read_until_end<R: AsyncRead + Unpin>(reader: &mut R) -> Received {
    let mut bytes = Vec::new();
    let mut buf = vec![0; 64 * 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => return Received { bytes, end: Ok(()) },
            Ok(n) => bytes.extend_from_slice(&buf[..n]),
            Err(err) => {
                return Received {
                    bytes,
                    end: Err(err),
                };
            }
        }
    }
}

/// Send the request, wait `delay` before the first read, then read to the end.
pub(super) async fn exchange<S>(stream: &mut S, delay: Duration) -> Received
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Err(err) = stream.write_all(REQUEST).await {
        return Received {
            bytes: Vec::new(),
            end: Err(err),
        };
    }
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    read_until_end(stream).await
}

/// Tally of many exchanges against the same origin.
#[derive(Debug, Default)]
pub(super) struct Tally {
    pub(super) runs: usize,
    pub(super) complete: usize,
    pub(super) empty: usize,
    pub(super) partial: usize,
    pub(super) ends: Vec<(Option<i32>, Option<io::ErrorKind>)>,
}

impl Tally {
    pub(super) fn add(&mut self, received: &Received, len: usize) {
        self.runs += 1;
        if received.is_complete(len) {
            self.complete += 1;
        } else if received.bytes.is_empty() {
            self.empty += 1;
        } else {
            self.partial += 1;
        }
        let end = (received.raw_os_error(), received.end_kind());
        if !self.ends.contains(&end) {
            self.ends.push(end);
        }
    }

    pub(super) fn lost(&self) -> usize {
        self.runs - self.complete
    }

    pub(super) fn loss_rate(&self) -> f64 {
        if self.runs == 0 {
            return 0.0;
        }
        self.lost() as f64 / self.runs as f64
    }
}

impl std::fmt::Display for Tally {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "runs={} complete={} empty={} partial={} loss={:.1}% ends={:?}",
            self.runs,
            self.complete,
            self.empty,
            self.partial,
            self.loss_rate() * 100.0,
            self.ends,
        )
    }
}

/// Tasks that burn CPU in short bursts, so that I/O tasks on the same runtime
/// wait longer between being woken and running.
pub(super) struct Filler {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    tasks: Vec<JoinHandle<()>>,
}

pub(super) fn spawn_filler(tasks: usize) -> Filler {
    use std::sync::atomic::{AtomicBool, Ordering};

    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let tasks = (0..tasks)
        .map(|_| {
            let stop = stop.clone();
            tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    let until = std::time::Instant::now() + Duration::from_micros(200);
                    while std::time::Instant::now() < until {
                        std::hint::spin_loop();
                    }
                    tokio::task::yield_now().await;
                }
            })
        })
        .collect();
    Filler { stop, tasks }
}

impl Filler {
    pub(super) async fn stop(self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for task in self.tasks {
            _ = task.await;
        }
    }
}

pub(super) const SIZES: [usize; 3] = [234, 1843, 6554];
/// How long a client waits before its first read, so that the reply and the
/// reset both arrived before it reads.
pub(super) const FORCED_DELAY: Duration = Duration::from_millis(50);

/// Run `runs` exchanges, `concurrency` at a time, and tally the outcomes.
pub(super) async fn tally<F, Fut>(runs: usize, concurrency: usize, len: usize, run: F) -> Tally
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Received> + Send + 'static,
{
    let mut tally = Tally::default();
    let mut set = tokio::task::JoinSet::new();
    let run = || {
        let flow = run();
        async move {
            tokio::time::timeout(FLOW_TIMEOUT, flow)
                .await
                .expect("a flow hung")
        }
    };
    for _ in 0..runs {
        if set.len() >= concurrency
            && let Some(received) = set.join_next().await
        {
            tally.add(&received.unwrap(), len);
        }
        set.spawn(run());
    }
    while let Some(received) = set.join_next().await {
        tally.add(&received.unwrap(), len);
    }
    tally
}

/// Spawn an origin that hands every accepted connection to `serve`.
pub(super) async fn spawn_origin_fn<F, Fut>(serve: F) -> Origin
where
    F: Fn(TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = listen();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(serve(stream));
        }
    });
    Origin { addr, task }
}

/// Characterization and benchmark tests only run when asked to, through
/// `just characterize-posted-recv`, rather than with every ignored test.
#[cfg(target_os = "windows")]
pub(super) fn characterizing() -> bool {
    let enabled = std::env::var_os("RAMA_POSTED_RECV_CHARACTERIZE").is_some();
    if !enabled {
        eprintln!("skipped: run `just characterize-posted-recv`");
    }
    enabled
}
