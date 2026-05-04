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
//! cargo run --example tcp_listener_fd_passing --features=http-full
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

#![expect(clippy::unwrap_used, reason = "example: panic-on-error is the standard pattern for demos")]

#[cfg(target_family = "unix")]
mod unix_example {
    use std::{
        convert::Infallible,
        env, io,
        os::unix::io::{AsRawFd, FromRawFd, RawFd},
        process::{Command, Stdio},
        time::Duration,
    };

    use rama::{
        error::BoxError, graceful::Shutdown, http::Request, http::server::HttpServer,
        http::service::web::response::Json, rt::Executor, service::service_fn,
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
        send_fd(stream.as_raw_fd(), std_listener.as_raw_fd())?;
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
        let fd = recv_fd(stream.as_raw_fd())?;
        tracing::info!("✓ Received FD: {fd}");

        // Reconstruct std listener from FD
        let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
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

    /// Send a file descriptor via Unix domain socket using SCM_RIGHTS.
    ///
    /// Uses libc directly because stable Rust lacks SCM_RIGHTS support:
    /// - std::os::unix::net::SocketAncillary is nightly-only
    /// - socket2 tracking: <https://github.com/rust-lang/socket2/issues/614>
    /// - rama tracking: <https://github.com/plabayo/rama/issues/781>
    fn send_fd(sock_fd: RawFd, fd: RawFd) -> io::Result<()> {
        // Prepare iovec with dummy byte
        let dummy = [b'F'];
        let mut iov = libc::iovec {
            iov_base: dummy.as_ptr() as *mut libc::c_void,
            iov_len: 1,
        };

        // Prepare control message buffer
        let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as libc::c_uint) };
        let mut cmsg_buf = vec![0u8; cmsg_space as usize];

        // Prepare msghdr
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_space as _;

        // Fill control message
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        if cmsg.is_null() {
            return Err(io::Error::other("Failed to get CMSG_FIRSTHDR"));
        }

        #[expect(clippy::multiple_unsafe_ops_per_block, reason = "single CMSG header initialization sequence: level/type/len + copy_nonoverlapping is one logical write")]
        unsafe {
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as libc::c_uint) as _;

            std::ptr::copy_nonoverlapping(
                &fd as *const RawFd,
                libc::CMSG_DATA(cmsg) as *mut RawFd,
                1,
            );
        }

        // Send
        let result = unsafe { libc::sendmsg(sock_fd, &msg, 0) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Receive a file descriptor via Unix domain socket using SCM_RIGHTS
    fn recv_fd(sock_fd: RawFd) -> io::Result<RawFd> {
        // Prepare control message buffer
        let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as libc::c_uint) };
        let mut cmsg_buf = vec![0u8; cmsg_space as usize];

        // Prepare iovec for dummy byte
        let mut dummy = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: dummy.as_mut_ptr() as *mut libc::c_void,
            iov_len: 1,
        };

        // Prepare msghdr
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_space as _;

        // Receive
        let result = unsafe { libc::recvmsg(sock_fd, &mut msg, 0) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        // Extract FD from control message
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        if cmsg.is_null() {
            return Err(io::Error::other("No control message received"));
        }

        #[expect(clippy::multiple_unsafe_ops_per_block, reason = "single CMSG header read sequence: deref + CMSG_DATA + ptr deref is one logical read")]
        unsafe {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let fd_ptr = libc::CMSG_DATA(cmsg) as *const RawFd;
                return Ok(*fd_ptr);
            }
        }

        Err(io::Error::other("No FD in control message"))
    }
}

#[cfg(target_family = "unix")]
use unix_example::run;

#[cfg(not(target_family = "unix"))]
fn run() {
    tracing::info!("tcp_listener_fd_passing example is Unix-only (requires SCM_RIGHTS)");
}

fn main() {
    run()
}
