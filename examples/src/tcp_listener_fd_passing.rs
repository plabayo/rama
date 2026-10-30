//! TCP listener FD passing ("teleport") - real zero-downtime restart via SCM_RIGHTS
//!
//! Demonstrates actual file descriptor transfer between parent and child processes
//! using Unix domain sockets and SCM_RIGHTS. This technique, sometimes called "teleporting"
//! a socket, allows the parent process to create a listener, spawn a child, transfer the FD,
//! and have the child take over serving without dropping connections.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin tcp_listener_fd_passing --features=http-full
//! ```
//!
//! # Expected output
//!
//! - Parent binds to 127.0.0.1:62046
//! - Parent spawns child process
//! - Parent sends listener FD via Unix socket
//! - Child receives FD and starts serving
//! - Parent gracefully exits
//! - Test with: `curl http://127.0.0.1:62046`
//!
//! This only works on Unix systems (Linux, macOS, BSDs).

#![cfg_attr(
    target_family = "unix",
    expect(
        clippy::unwrap_used,
        reason = "example: panic-on-error is the standard pattern for demos"
    )
)]

#[cfg(target_family = "unix")]
mod unix_example {
    use std::{
        convert::Infallible,
        env, io, mem,
        os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
        process::{Command, Stdio},
        time::Duration,
    };

    use rama::{
        error::BoxError,
        graceful::Shutdown,
        http::Request,
        http::server::HttpServer,
        http::service::web::response::Json,
        rt::Executor,
        service::service_fn,
        tcp::server::TcpListener,
        telemetry::tracing::{
            self,
            level_filters::LevelFilter,
            subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
        },
    };
    use serde_json::json;

    const SOCKET_PATH: &str = "/tmp/rama_fd_passing.sock";
    const ROLE_ENV: &str = "RAMA_FD_ROLE";

    pub(crate) fn run() {
        // Check if we're parent or child
        match env::var(ROLE_ENV).as_deref() {
            Ok("child") => {
                // Child process: receive FD and serve
                tokio::runtime::Runtime::new()
                    .unwrap()
                    .block_on(child_process())
                    .unwrap();
            }
            _ => {
                // Parent process: create listener, spawn child, transfer FD
                tokio::runtime::Runtime::new()
                    .unwrap()
                    .block_on(parent_process())
                    .unwrap();
            }
        }
    }

    async fn parent_process() -> Result<(), BoxError> {
        tracing::subscriber::registry()
            .with(fmt::layer())
            .with(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            )
            .init();

        tracing::info!("=== Parent Process ===");
        tracing::info!("Creating TCP listener...");

        // Create listener
        let listener = TcpListener::bind_address("127.0.0.1:62046", Executor::default()).await?;
        let addr = listener.local_addr()?;
        tracing::info!("✓ Listening on {addr}");

        // Clean up old socket file
        _ = std::fs::remove_file(SOCKET_PATH);

        // Create Unix socket for FD passing (std blocking socket required for libc sendmsg)
        let unix_listener = std::os::unix::net::UnixListener::bind(SOCKET_PATH)?;
        tracing::info!("✓ Created control socket at {SOCKET_PATH}");

        // Convert to std listener for FD passing
        let std_listener = listener.into_std()?;
        tracing::info!("✓ Converted to std::net::TcpListener");

        // Spawn child process
        tracing::info!("\nSpawning child process...");
        let exe = env::current_exe()?;
        let mut child = Command::new(exe)
            .env(ROLE_ENV, "child")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;

        tracing::info!("✓ Child spawned (PID: {})", child.id());

        // Wait for child to connect (blocking)
        tracing::info!("\nWaiting for child to connect...");
        let (stream, _) = unix_listener.accept()?;
        tracing::info!("✓ Child connected");

        // Send the FD via SCM_RIGHTS (libc required - no stable Rust API for ancillary data)
        tracing::info!("\nTransferring listener FD...");
        send_fd(stream.as_fd(), std_listener.as_fd())?;
        tracing::info!("✓ FD transferred");

        // Close our copy of the listener
        drop(std_listener);

        // Wait a bit for child to start serving
        tokio::time::sleep(Duration::from_secs(1)).await;

        tracing::info!("\n=== Parent exiting - child now serving ===");
        tracing::info!("Test with: curl http://127.0.0.1:62046\n");

        // Wait for child to finish (it will run for 10 seconds)
        _ = child.wait();

        // Cleanup
        _ = std::fs::remove_file(SOCKET_PATH);

        Ok(())
    }

    async fn child_process() -> Result<(), BoxError> {
        tracing::subscriber::registry()
            .with(fmt::layer())
            .with(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            )
            .init();

        // Give parent time to set up
        tokio::time::sleep(Duration::from_millis(100)).await;

        let shutdown = Shutdown::default();
        let guard = shutdown.guard();

        tracing::info!("\n=== Child Process ===");
        tracing::info!("Connecting to parent...");

        // Connect to parent's Unix socket (std blocking socket required for libc recvmsg)
        let stream = std::os::unix::net::UnixStream::connect(SOCKET_PATH)?;
        tracing::info!("✓ Connected to parent");

        // Receive the FD via SCM_RIGHTS (libc required - no stable Rust API for ancillary data)
        tracing::info!("Receiving listener FD...");
        let fd = recv_fd(stream.as_fd())?;
        tracing::info!("✓ Received FD: {}", fd.as_raw_fd());

        // Reconstruct std listener from the owned FD
        let std_listener = std::net::TcpListener::from(fd);
        let addr = std_listener.local_addr()?;
        tracing::info!("✓ Reconstructed listener on {addr}");

        // Convert to rama listener
        let listener = TcpListener::try_from_std_tcp_listener(
            std_listener,
            Executor::graceful(guard.clone()),
        )?;
        tracing::info!("✓ Converted to rama::tcp::TcpListener");

        // Start serving
        tracing::info!("\n=== Child now serving ===");
        tracing::info!("Will serve for 10 seconds, then exit\n");

        let http_service = HttpServer::auto(Executor::graceful(guard.clone())).service(service_fn(
            |_req: Request| async move {
                Ok::<_, Infallible>(Json(json!({
                    "message": "Hello from child process!",
                    "pid": std::process::id(),
                    "zero_downtime": true
                })))
            },
        ));

        // Shutdown after 10 seconds
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            tracing::info!("\n=== Child shutting down ===");
            shutdown.shutdown().await;
        });

        listener.serve(http_service).await;
        tracing::info!("✓ Child shutdown complete\n");

        Ok(())
    }

    /// Payload length of a control message carrying one file descriptor.
    const FD_LEN: libc::c_uint = mem::size_of::<RawFd>() as libc::c_uint;
    /// Control buffer size for one file descriptor.
    const CMSG_SPACE: usize = {
        // SAFETY: `CMSG_SPACE` is the cmsg(3) size macro: it only computes on
        // its argument and touches no memory.
        unsafe { libc::CMSG_SPACE(FD_LEN) as usize }
    };
    /// `cmsg_len` of a control message carrying one file descriptor.
    const CMSG_LEN: usize = {
        // SAFETY: `CMSG_LEN` is the cmsg(3) size macro: it only computes on
        // its argument and touches no memory.
        unsafe { libc::CMSG_LEN(FD_LEN) as usize }
    };

    /// Control buffer for one SCM_RIGHTS message, aligned for `cmsghdr` as
    /// cmsg(3) requires of `msg_control`.
    #[repr(C)]
    union CmsgBuffer {
        _align: libc::cmsghdr,
        bytes: [u8; CMSG_SPACE],
    }

    /// Send a file descriptor via Unix domain socket using SCM_RIGHTS.
    ///
    /// Uses libc directly because stable Rust lacks SCM_RIGHTS support:
    /// - std::os::unix::net::SocketAncillary is nightly-only
    /// - socket2 tracking: <https://github.com/rust-lang/socket2/issues/614>
    /// - rama tracking: <https://github.com/plabayo/rama/issues/781>
    fn send_fd(sock: BorrowedFd<'_>, fd: BorrowedFd<'_>) -> io::Result<()> {
        // Prepare iovec with dummy byte
        let dummy = *b"F";
        let mut iov = libc::iovec {
            iov_base: dummy.as_ptr().cast_mut().cast(),
            iov_len: 1,
        };

        // Prepare control message buffer
        let mut control = CmsgBuffer {
            bytes: [0; CMSG_SPACE],
        };

        // Prepare msghdr
        // SAFETY: `msghdr` has only integer and raw-pointer fields (libc), for
        // which all-zero is valid (`mem::zeroed` docs).
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = (&raw mut control).cast();
        msg.msg_controllen = CMSG_SPACE as _;

        // Fill control message
        // SAFETY: `CMSG_FIRSTHDR` only reads `msg_control` and
        // `msg_controllen` of the live `msg`.
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        if cmsg.is_null() {
            return Err(io::Error::other("Failed to get CMSG_FIRSTHDR"));
        }

        // SAFETY: `cmsghdr` has only integer fields (libc), for which all-zero
        // is valid (`mem::zeroed` docs).
        let mut header: libc::cmsghdr = unsafe { mem::zeroed() };
        header.cmsg_level = libc::SOL_SOCKET;
        header.cmsg_type = libc::SCM_RIGHTS;
        header.cmsg_len = CMSG_LEN as _;
        // SAFETY: `write` needs `cmsg` writable and aligned for a `cmsghdr`.
        // Per cmsg(3) a non-null `CMSG_FIRSTHDR` is the start of `msg_control`,
        // i.e. `control`: aligned for `cmsghdr` (union member) and
        // `CMSG_SPACE >= size_of::<cmsghdr>()` bytes long.
        unsafe { cmsg.write(header) };
        // SAFETY: `CMSG_DATA` only offsets `cmsg` by `CMSG_LEN(0)`, which stays
        // inside `control` (`CMSG_LEN(0) <= CMSG_SPACE`).
        let data = unsafe { libc::CMSG_DATA(cmsg) };
        // SAFETY: `write_unaligned` needs `data` writable for a `RawFd`, with
        // no alignment: `data..data + FD_LEN` ends at `CMSG_LEN <= CMSG_SPACE`,
        // inside `control`.
        unsafe { data.cast::<RawFd>().write_unaligned(fd.as_raw_fd()) };

        // Send
        // SAFETY: sendmsg(2) reads `msg` and what it points to: `iov` (1
        // readable byte in `dummy`) and `control` (`msg_controllen`
        // initialized bytes), all live locals; `msg_name` is null. `sock` is
        // borrowed, so it stays open, and the kernel duplicates the open `fd`
        // into the message.
        let result = unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, 0) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Receive a file descriptor via Unix domain socket using SCM_RIGHTS
    fn recv_fd(sock: BorrowedFd<'_>) -> io::Result<OwnedFd> {
        // Prepare control message buffer
        let mut control = CmsgBuffer {
            bytes: [0; CMSG_SPACE],
        };

        // Prepare iovec for dummy byte
        let mut dummy = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: dummy.as_mut_ptr().cast(),
            iov_len: 1,
        };

        // Prepare msghdr
        // SAFETY: as in `send_fd`.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = (&raw mut control).cast();
        msg.msg_controllen = CMSG_SPACE as _;

        // Receive
        // SAFETY: recvmsg(2) writes at most `iov_len` (1) bytes to `dummy`, at
        // most `msg_controllen` bytes to `control`, and updates `msg`; all are
        // live, writable locals and `msg_name` is null. `sock` is borrowed, so
        // it stays open.
        let result = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, 0) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(io::Error::other("Control message truncated"));
        }

        // Extract FD from control message
        // SAFETY: as in `send_fd`.
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        if cmsg.is_null() {
            return Err(io::Error::other("No control message received"));
        }
        // SAFETY: `read` needs `cmsg` readable, aligned and initialized for a
        // `cmsghdr`: per cmsg(3) it is the start of `control` (aligned,
        // `CMSG_SPACE >= size_of::<cmsghdr>()` bytes), whose bytes were zeroed
        // and then written by the kernel.
        let header = unsafe { cmsg.read() };
        if header.cmsg_level != libc::SOL_SOCKET
            || header.cmsg_type != libc::SCM_RIGHTS
            || header.cmsg_len as usize != CMSG_LEN
        {
            return Err(io::Error::other("No FD in control message"));
        }

        // SAFETY: as in `send_fd`.
        let data = unsafe { libc::CMSG_DATA(cmsg) };
        // SAFETY: `read_unaligned` needs `data` readable and initialized for a
        // `RawFd`, without alignment: it lies inside `control` (as in
        // `send_fd`), whose bytes are all initialized.
        let fd = unsafe { data.cast::<RawFd>().read_unaligned() };
        if fd < 0 {
            return Err(io::Error::other("Invalid FD in control message"));
        }

        // SAFETY: `from_raw_fd` needs an open fd that we may own and that
        // needs only `close`. `cmsg_len == CMSG_LEN(sizeof(int))` without
        // MSG_CTRUNC means the kernel installed exactly this one SCM_RIGHTS fd
        // into our process for this message (unix(7)); nothing else refers
        // to it.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

#[cfg(target_family = "unix")]
use unix_example::run;

#[cfg(not(target_family = "unix"))]
fn run() {
    rama::telemetry::tracing::info!(
        "tcp_listener_fd_passing example is Unix-only (requires SCM_RIGHTS)"
    );
}

fn main() {
    run()
}
