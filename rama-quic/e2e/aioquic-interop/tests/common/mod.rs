//! What the aioquic interoperability tests need: identities on disk for a peer that reads PEM
//! files, the two stacks' configurations, and a child process driven over a line protocol.
//!
//! The peer is a separate interpreter with its own pinned environment, so nothing but the wire
//! is shared with Rama. Building that environment is separate from running a scenario: a test
//! calls [`prepare`] first, under its own bound, and only then starts the scenario deadline
//! that covers the protocol work.
//!
//! Prerequisite: `uv` on PATH. `uv sync --frozen` in this directory builds `.venv` from
//! `uv.lock`; [`prepare`] runs the same command if the interpreter is missing. uv keeps its
//! download cache and its managed interpreters outside this directory, so what is project-local
//! is the environment and the resolution, not everything uv touches.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use parking_lot::Mutex;
use rama::{
    crypto::{dep::rcgen, pki_types::PrivatePkcs8KeyDer},
    net::tls::ApplicationProtocol,
    quic::{ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig, tls::TlsOptions},
    tls::{
        client::TlsClientConfig,
        server::{ServerAuthData, TlsServerConfig},
    },
    utils::{fmt, octets},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdout, Command},
    sync::OnceCell,
    time::Instant,
};

pub const ALPN: &str = "rama-aioquic-interop";
/// The interpreter this project pins, matching `.python-version` and `requires-python`.
pub const PYTHON: &str = "3.12";
/// The peer library this project pins, matching `pyproject.toml` and `uv.lock`.
pub const AIOQUIC: &str = "1.2.0";
/// How long a scenario's protocol work may take. Every await inside one shares this deadline,
/// so a stall anywhere fails the test instead of extending it. Building the peer's environment
/// is not part of it; see [`prepare`].
pub const LIMIT: Duration = Duration::from_secs(30);
/// How long building the peer's environment may take, which on a cold checkout includes
/// resolving an interpreter and downloading wheels.
pub const SETUP_LIMIT: Duration = Duration::from_secs(300);
/// What a stream may carry in these tests, matching the peer's own cap.
pub const STREAM_LIMIT: usize = octets::mib(1);
/// What one line of the peer's output may carry. Its events are small; a larger line is a
/// fault rather than a bigger message.
pub const LINE_LIMIT: usize = octets::kib(64);
/// How much of the peer's error output is kept for a failure message, in total, including the
/// marker that says more was dropped.
pub const COMPLAINT_LIMIT: usize = octets::kib(16);
/// How much of a setup command's own output is kept, per stream.
pub const OUTPUT_LIMIT: usize = octets::kib(64);

/// The TLS alerts a certificate check can end on, as QUIC error codes: RFC 9001 section 4.8
/// maps an alert to 0x100 plus its description. Which one appears depends on how the chain
/// fails; an anchor that is not found gives unknown_ca, and an anchor found by subject whose
/// signature does not verify gives decrypt_error.
pub const CERTIFICATE_ALERTS: [u64; 7] = [
    0x12a, // bad_certificate (42)
    0x12b, // unsupported_certificate (43)
    0x12c, // certificate_revoked (44)
    0x12d, // certificate_expired (45)
    0x12e, // certificate_unknown (46)
    0x130, // unknown_ca (48)
    0x133, // decrypt_error (51)
];

/// The moment a scenario must be finished by. Passed to every operation that waits.
#[derive(Clone, Copy)]
pub struct Deadline(Instant);

impl Deadline {
    pub fn new() -> Self {
        Self(Instant::now() + LIMIT)
    }

    /// A deadline of the caller's own length, for a scenario that is about waiting.
    pub fn of(limit: Duration) -> Self {
        Self(Instant::now() + limit)
    }

    /// Wait for one future, or fail saying what was being waited for.
    pub async fn wait<F: Future>(&self, what: &str, future: F) -> F::Output {
        match tokio::time::timeout_at(self.0, future).await {
            Ok(value) => value,
            Err(_) => panic!("{what}: the scenario's deadline ran out"),
        }
    }

    /// Wait for one future, answering `None` rather than failing when the deadline passes.
    pub async fn try_wait<F: Future>(&self, future: F) -> Option<F::Output> {
        tokio::time::timeout_at(self.0, future).await.ok()
    }

    /// The instant this deadline ends, for a wait that needs it directly.
    pub fn at(&self) -> Instant {
        self.0
    }
}

impl Default for Deadline {
    fn default() -> Self {
        Self::new()
    }
}

/// A spawned Rama-side task. The guard owns its handle for as long as it exists, including
/// while a wait on it is in progress, so a wait that is itself cancelled leaves the task with
/// the guard. Dropping the guard aborts the task.
pub struct Task(Option<tokio::task::JoinHandle<()>>);

impl Task {
    pub fn spawn(task: impl Future<Output = ()> + Send + 'static) -> Self {
        Self(Some(tokio::spawn(task)))
    }

    /// Whether the guard still owns the task, which is what keeps a cancelled wait from
    /// leaving it detached.
    pub fn owns_it(&self) -> bool {
        self.0.is_some()
    }

    pub async fn join(mut self, what: &str, deadline: Deadline) {
        if let Err(reason) = self.try_join(deadline).await {
            panic!("{what}: {reason}");
        }
    }

    /// Wait for the task, with the handle staying in the guard throughout. Awaiting it by value
    /// would drop it on a timeout, leaving the task detached.
    pub async fn try_join(&mut self, deadline: Deadline) -> Result<(), String> {
        let handle = self.0.as_mut().expect("waited on once");
        let outcome = match tokio::time::timeout_at(deadline.0, handle).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) if error.is_panic() => Err(format!("panicked: {error}")),
            Ok(Err(error)) => Err(format!("ended: {error}")),
            Err(_) => {
                let handle = self.0.as_mut().expect("still here");
                handle.abort();
                let _ = handle.await;
                Err("the deadline ran out".to_owned())
            }
        };
        self.0 = None;
        outcome
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

pub fn localhost() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)
}

pub fn digest(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

pub fn hex(payload: &[u8]) -> String {
    format!("{:x}", fmt::hex(payload))
}

/// The payload shape the peer builds from the same seed and length.
pub fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|index| ((index % 251) as u8) ^ seed).collect()
}

/// A self-signed identity, as PEM files for the peer and as Rama's own types. The directory is
/// owned before anything is written into it, so every path out removes it.
pub struct Identity {
    /// Held so the files live as long as the identity does.
    #[expect(dead_code)]
    directory: TempDir,
    certificate: PathBuf,
    key: PathBuf,
    auth: ServerAuthData,
}

impl Identity {
    pub fn generate(name: &str) -> Self {
        let directory = tempfile::Builder::new()
            .prefix("rama-aioquic-interop-")
            .tempdir()
            .expect("a directory of our own");
        let generated = rcgen::generate_simple_self_signed(vec![name.to_owned()])
            .expect("an identity is generated");
        let certificate = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        std::fs::write(&certificate, generated.cert.pem()).expect("the certificate is written");
        std::fs::write(&key, generated.signing_key.serialize_pem()).expect("the key is written");
        // rcgen serialises the key as PKCS#8, so it is named as such rather than guessed at.
        let auth = ServerAuthData::new(
            vec![generated.cert.der().clone()],
            PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der()).into(),
        );
        Self {
            directory,
            certificate,
            key,
            auth,
        }
    }

    pub fn certificate(&self) -> &str {
        Self::path(&self.certificate)
    }

    pub fn key(&self) -> &str {
        Self::path(&self.key)
    }

    fn path(path: &Path) -> &str {
        path.to_str().expect("a printable path")
    }
}

pub fn alpn() -> impl IntoIterator<Item = ApplicationProtocol> {
    [ApplicationProtocol::from(ALPN)]
}

pub fn rama_server_config(identity: &Identity) -> ServerConfig {
    let tls = TlsServerConfig::new()
        .with_alpn(alpn().into_iter().collect())
        .with_server_auth(identity.auth.clone());
    ServerConfig::try_from_rama_tls(&tls, TlsOptions::default())
        .expect("the server config is built")
}

/// A client that trusts `identity` and holds at most `buffer` bytes of outgoing datagrams, so
/// a test can fill that buffer deliberately rather than by volume.
pub fn rama_client_config_with_datagram_buffer(identity: &Identity, buffer: usize) -> ClientConfig {
    let transport = TransportConfig::default().with_datagram_send_buffer_size(buffer);
    rama_client_config(identity).with_transport_config(Arc::new(transport))
}

pub fn rama_client_config(identity: &Identity) -> ClientConfig {
    let anchor = identity.auth.cert_chain.last().expect("a chain").clone();
    let tls = TlsClientConfig::new()
        .with_alpn(alpn().into_iter().collect())
        .try_with_server_trust_anchors([anchor])
        .expect("the trust anchor is accepted");
    ClientConfig::try_from_rama_tls(&tls, TlsOptions::default())
        .expect("the client config is built")
}

/// The interpreter of this project's own environment, resolved once per test binary.
static INTERPRETER: OnceCell<PathBuf> = OnceCell::const_new();

fn project() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// What a bounded command left behind, with its output already capped.
#[derive(Debug)]
pub struct Finished {
    pub status: std::process::ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

/// Run a command to completion within a bound, reaping the child either way.
///
/// The pipes are read alongside the wait and inside the same bound, so a child that fills one
/// is not deadlocked against a parent that is only waiting, and a descendant holding a pipe
/// open cannot extend the call past the bound. On the bound the child is killed and waited for.
pub async fn bounded_command(mut command: Command, limit: Duration) -> Result<Finished, String> {
    command.stdin(Stdio::null()).kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|reason| format!("it does not start: {reason}"))?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let running = async {
        let (status, stdout, stderr) = tokio::join!(
            child.wait(),
            capped_read(stdout, OUTPUT_LIMIT),
            capped_read(stderr, OUTPUT_LIMIT),
        );
        (status, stdout, stderr)
    };
    match tokio::time::timeout(limit, running).await {
        Ok((status, stdout, stderr)) => Ok(Finished {
            status: status.map_err(|reason| format!("its status is unreadable: {reason}"))?,
            stdout: stdout.map_err(|reason| format!("its output is unreadable: {reason}"))?,
            stderr: stderr.map_err(|reason| format!("its output is unreadable: {reason}"))?,
        }),
        Err(_) => {
            // `kill` is start_kill followed by a wait, so the child is reaped before this
            // returns rather than merely asked to stop.
            child
                .kill()
                .await
                .map_err(|reason| format!("it could not be stopped: {reason}"))?;
            Err(format!("it did not finish within {limit:?}"))
        }
    }
}

/// Read a pipe to its end, keeping at most `cap` bytes. Reading continues past the cap without
/// keeping anything, so the child is never blocked on a pipe nobody is draining.
async fn capped_read(stream: Option<impl AsyncRead + Unpin>, cap: usize) -> io::Result<String> {
    let Some(mut stream) = stream else {
        return Ok(String::new());
    };
    let mut kept = Vec::new();
    let mut scratch = [0u8; 8192];
    loop {
        let read = stream.read(&mut scratch).await?;
        if read == 0 {
            return Ok(String::from_utf8_lossy(&kept).into_owned());
        }
        if kept.len() < cap {
            let room = cap - kept.len();
            kept.extend_from_slice(&scratch[..read.min(room)]);
        }
    }
}

/// Build the peer's environment and check it is the one this project pins, within
/// [`SETUP_LIMIT`]. Call this before starting a scenario deadline, so a cold checkout's
/// downloads are not counted against the protocol work. It runs once per test binary.
///
/// The frozen sync runs every time rather than only when `.venv` is missing: an environment
/// left over from an older `uv.lock` would otherwise be used against the current one. The
/// versions are then read back from the interpreter itself, so a wrong or broken environment
/// fails here with what it actually is.
pub async fn prepare() {
    INTERPRETER
        .get_or_init(|| async {
            let mut command = Command::new("uv");
            command
                .args(["sync", "--frozen"])
                .current_dir(project())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let built = bounded_command(command, SETUP_LIMIT)
                .await
                .unwrap_or_else(|reason| {
                    panic!(
                        "uv sync --frozen {reason}. uv must be on PATH; run it in {} to see why",
                        project().display()
                    )
                });
            assert!(built.status.success(), "uv sync --frozen: {}", built.stderr);

            let interpreter = project().join(".venv/bin/python");
            assert!(
                interpreter.is_file(),
                "the environment at {} has an interpreter",
                interpreter.display()
            );
            let mut command = Command::new(&interpreter);
            command
                .args([
                    "-c",
                    "import sys, aioquic; \
                     print(f'{sys.version_info[0]}.{sys.version_info[1]} {aioquic.__version__}')",
                ])
                .current_dir(project())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let asked = bounded_command(command, SETUP_LIMIT)
                .await
                .unwrap_or_else(|reason| panic!("asking the interpreter what it is {reason}"));
            assert!(
                asked.status.success(),
                "the environment cannot import aioquic: {}",
                asked.stderr
            );
            assert_eq!(
                asked.stdout.trim(),
                format!("{PYTHON} {AIOQUIC}"),
                "the environment is the one this project pins"
            );
            interpreter
        })
        .await;
}

/// The pinned interpreter, for a test that needs a controlled child of its own. [`prepare`]
/// must have run first.
pub fn python() -> &'static Path {
    interpreter()
}

fn interpreter() -> &'static Path {
    INTERPRETER
        .get()
        .expect("prepare() was called before the peer was started")
        .as_path()
}

/// One line the peer wrote, as it named it.
#[derive(Debug)]
pub struct Event(Value);

impl Event {
    pub fn name(&self) -> &str {
        self.0["event"]
            .as_str()
            .expect("every line names its event")
    }

    pub fn id(&self) -> u64 {
        self.0["id"].as_u64().expect("a stream id")
    }

    pub fn port(&self) -> u16 {
        u16::try_from(self.0["port"].as_u64().expect("a port")).expect("a port that fits")
    }

    pub fn len(&self) -> usize {
        usize::try_from(self.0["len"].as_u64().expect("a length")).expect("a length that fits")
    }

    pub fn sha256(&self) -> &str {
        self.0["sha256"].as_str().expect("a digest")
    }

    pub fn code(&self) -> u64 {
        self.0["code"].as_u64().expect("an error code")
    }

    pub fn reason(&self) -> &str {
        self.0["reason"].as_str().unwrap_or_default()
    }

    pub fn order(&self) -> &str {
        self.0["order"].as_str().expect("an order")
    }

    pub fn alpn(&self) -> &str {
        self.0["alpn"].as_str().expect("a negotiated protocol")
    }
}

/// The aioquic peer as a child process, with everything it says and everything it owns.
pub struct AioQuic {
    child: Child,
    orders: Option<tokio::process::ChildStdin>,
    output: BufReader<ChildStdout>,
    complaints: Arc<Mutex<String>>,
    draining: Option<tokio::task::JoinHandle<()>>,
}

impl AioQuic {
    /// Start the peer in one of its roles. The arguments are the peer's own, less the role.
    /// [`prepare`] must have run first.
    pub async fn spawn(role: &str, arguments: &[&str]) -> Self {
        let mut command = Command::new(interpreter());
        command
            .arg(project().join("peer/interop_peer.py"))
            .arg(role)
            .args(["--alpn", ALPN])
            .args(arguments)
            .current_dir(project())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().expect("the peer starts");
        let orders = child.stdin.take();
        let output = BufReader::new(child.stdout.take().expect("its output"));
        let complaints = Arc::new(Mutex::new(String::new()));
        let draining = tokio::spawn(drain(
            child.stderr.take().expect("its complaints"),
            Arc::clone(&complaints),
        ));
        Self {
            child,
            orders,
            output,
            complaints,
            draining: Some(draining),
        }
    }

    /// Give the peer a one-word order and wait for it to say the order took effect. The peer
    /// must have been started with `--orders`.
    pub async fn tell(&mut self, order: &str, deadline: Deadline) {
        let orders = self.orders.as_mut().expect("the peer takes orders");
        deadline
            .wait(
                &format!("telling the peer to {order}"),
                orders.write_all(format!("{order}\n").as_bytes()),
            )
            .await
            .expect("the order is written");
        deadline
            .wait("flushing the order", orders.flush())
            .await
            .expect("it is flushed");
        let seen = self.expect("ack", deadline).await;
        assert_eq!(seen.order(), order, "the peer acknowledged this order");
    }

    /// The next line the peer wrote, or a failure naming what was being waited for.
    pub async fn event(&mut self, what: &str, deadline: Deadline) -> Event {
        let line = deadline
            .wait(what, capped_line(&mut self.output, LINE_LIMIT))
            .await
            .unwrap_or_else(|reason| panic!("{what}: the peer's output: {reason}"))
            .unwrap_or_else(|| panic!("{what}: the peer stopped without saying so{}", self.said()));
        Event(serde_json::from_str(&line).unwrap_or_else(|reason| {
            panic!("the peer wrote a line that is not one of its events ({reason}): {line}")
        }))
    }

    /// The next line, required to be the named event.
    pub async fn expect(&mut self, event: &str, deadline: Deadline) -> Event {
        let seen = self.event(event, deadline).await;
        assert_eq!(
            seen.name(),
            event,
            "the peer reported {seen:?} where {event} was due{}",
            self.said()
        );
        seen
    }

    /// The next `count` stream reports, in whatever order the peer completed them.
    pub async fn streams(&mut self, count: usize, deadline: Deadline) -> Vec<Event> {
        let mut seen = Vec::with_capacity(count);
        for _ in 0..count {
            seen.push(self.expect("stream", deadline).await);
        }
        seen
    }

    /// The port the peer bound, from its first line.
    pub async fn listening(&mut self, deadline: Deadline) -> SocketAddr {
        let port = self.expect("listening", deadline).await.port();
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    /// Wait for the peer to finish, requiring a clean exit.
    pub async fn finished(&mut self, deadline: Deadline) {
        let status = self.reap(deadline).await;
        assert!(
            status.success(),
            "the peer exited with {status}{}",
            self.said()
        );
    }

    /// Wait for the peer to finish, requiring the opposite.
    pub async fn failed(&mut self, deadline: Deadline) {
        let status = self.reap(deadline).await;
        assert!(!status.success(), "the peer exited cleanly{}", self.said());
    }

    /// Wait for the process and for the task reading its error output, so a test that ends
    /// normally leaves neither behind. The handle stays in the guard across the wait, so a
    /// cancelled wait does not detach the task, and a drain that failed is reported rather than
    /// counted as clean.
    async fn reap(&mut self, deadline: Deadline) -> std::process::ExitStatus {
        let status = deadline
            .wait("the peer finishes", self.child.wait())
            .await
            .expect("its status is readable");
        if let Some(draining) = self.draining.as_mut() {
            match tokio::time::timeout_at(deadline.at(), &mut *draining).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    self.draining = None;
                    panic!("the task reading the peer's error output {error}");
                }
                Err(_) => {
                    draining.abort();
                    let _ = draining.await;
                    self.draining = None;
                    panic!("the task reading the peer's error output did not finish in time");
                }
            }
        }
        self.draining = None;
        status
    }

    /// Whatever the peer wrote to its error output so far, for a failure message.
    pub fn said(&self) -> String {
        let complaints = self.complaints.lock();
        if complaints.is_empty() {
            String::new()
        } else {
            format!("\n--- the peer's error output ---\n{complaints}")
        }
    }
}

impl Drop for AioQuic {
    fn drop(&mut self) {
        // A drop cannot wait, so this is best effort: the reader is asked to stop and the
        // process is asked to stop. `kill_on_drop` leaves the runtime to reap the process once
        // it has exited, which is not observed here. A test that needs the exit observed calls
        // `finished` or `failed`, and a test that needs the process proved gone looks for it.
        if let Some(draining) = self.draining.take() {
            draining.abort();
        }
        let _ = self.child.start_kill();
    }
}

/// Read one line, failing rather than growing past `cap`, where `cap` counts the bytes of the
/// line itself and not the newline that ends it. A line of exactly `cap` is read; one byte more
/// is an error, whether the newline arrives in the same buffer or a later one. Answers `None`
/// at the end of the stream with nothing buffered, and renders invalid UTF-8 lossily.
pub async fn capped_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    cap: usize,
) -> io::Result<Option<String>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok((!line.is_empty()).then(|| String::from_utf8_lossy(&line).into_owned()));
        }
        let ends_at = available.iter().position(|byte| *byte == b'\n');
        let take = ends_at.unwrap_or(available.len());
        if line.len() + take > cap {
            return Err(io::Error::other(format!("a line ran past {cap} bytes")));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take + usize::from(ends_at.is_some()));
        if ends_at.is_some() {
            return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
        }
    }
}

/// Keep what the peer writes to its error output, for a failure message. What is retained is
/// at most [`COMPLAINT_LIMIT`] bytes in total, the marker included.
async fn drain(stream: impl AsyncRead + Unpin, into: Arc<Mutex<String>>) {
    const MARKER: &str = "... further error output dropped\n";
    let room = COMPLAINT_LIMIT - MARKER.len();
    let mut reader = BufReader::new(stream);
    let mut marked = false;
    loop {
        let line = match capped_line(&mut reader, room).await {
            Ok(Some(line)) => line,
            Ok(None) => return,
            Err(reason) => {
                let mut held = into.lock();
                if held.len() + MARKER.len() <= COMPLAINT_LIMIT {
                    held.push_str(&format!("... error output unreadable: {reason}\n"));
                }
                return;
            }
        };
        let mut held = into.lock();
        if held.len() + line.len() + 1 > room {
            if !marked {
                marked = true;
                held.push_str(MARKER);
            }
            continue;
        }
        held.push_str(&line);
        held.push('\n');
    }
}

/// The process identifier a controlled child wrote, for a test that checks it was reaped.
pub fn read_pid(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|reason| panic!("the child wrote its identifier to {path:?}: {reason}"))
        .trim()
        .to_owned()
}

/// Whether a process is gone, asked of the system rather than assumed from a kill request.
#[cfg(unix)]
pub fn process_is_gone(pid: &str) -> bool {
    !std::process::Command::new("kill")
        .args(["-0", pid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("kill runs")
        .success()
}

/// Wait for a condition to hold, within a bound of its own. Answers whether it did.
pub async fn within(limit: Duration, mut holds: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + limit;
    while Instant::now() < until {
        if holds() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    holds()
}

/// Take one attempt on a Rama server and require it to reach a connection. An attempt that
/// never arrives, is refused by the endpoint, or fails its handshake fails the caller.
pub async fn accept_one(what: &str, server: &Endpoint, deadline: Deadline) -> Connection {
    let incoming = deadline
        .wait(&format!("{what} takes an attempt"), server.accept())
        .await
        .unwrap_or_else(|| panic!("{what}: no attempt arrived before the endpoint closed"));
    deadline
        .wait(
            &format!("{what} completes the handshake"),
            incoming
                .accept()
                .unwrap_or_else(|reason| panic!("{what}: the attempt was refused: {reason}")),
        )
        .await
        .unwrap_or_else(|reason| panic!("{what}: the handshake failed: {reason}"))
}

/// Take one attempt on a Rama server and require its handshake to fail, answering why.
pub async fn refuse_one(what: &str, server: &Endpoint, deadline: Deadline) -> String {
    let incoming = deadline
        .wait(&format!("{what} takes an attempt"), server.accept())
        .await
        .unwrap_or_else(|| panic!("{what}: no attempt arrived before the endpoint closed"));
    let outcome = deadline
        .wait(
            &format!("{what} sees the attempt end"),
            incoming
                .accept()
                .unwrap_or_else(|reason| panic!("{what}: the attempt was refused: {reason}")),
        )
        .await;
    match outcome {
        Ok(_) => panic!("{what}: the handshake completed where it had to fail"),
        Err(reason) => format!("{reason:?}"),
    }
}

/// Whether a UDP port on loopback can be bound, which is how these tests see that a peer's
/// socket is gone rather than merely unreferenced.
pub fn port_is_free(port: u16) -> bool {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
}

/// Sets a flag when it is dropped, so a test can see a task actually unwind rather than
/// assuming an abort took effect.
pub struct Marks(pub Arc<AtomicBool>);

impl Drop for Marks {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Read one line from `bytes`, delivered in buffers of at most `chunk`, with the given cap.
/// The chunk size is what makes a split-buffer case different from a whole-buffer one.
pub async fn read_one_line(bytes: &[u8], cap: usize, chunk: usize) -> io::Result<Option<String>> {
    let mut reader = BufReader::with_capacity(chunk, bytes);
    capped_line(&mut reader, cap).await
}
