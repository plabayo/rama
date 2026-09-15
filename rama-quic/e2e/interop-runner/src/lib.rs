//! HTTP/0.9 file transfer endpoints for the QUIC interop runner, using `hq-interop`.

#[cfg(any(
    all(feature = "rustls-ring", feature = "rustls-aws-lc"),
    all(
        feature = "boring",
        any(feature = "rustls-ring", feature = "rustls-aws-lc")
    ),
))]
compile_error!("select exactly one Rama TLS backend: boring, rustls-ring or rustls-aws-lc");
#[cfg(not(any(feature = "boring", feature = "rustls-ring", feature = "rustls-aws-lc")))]
compile_error!("select a Rama TLS backend: boring, rustls-ring or rustls-aws-lc");

pub mod client;
pub mod server;

use rama::{
    error::{BoxError, ErrorContext as _},
    error_sink::TracingErrorSink,
    net::tls::ApplicationProtocol,
    quic::{Connection, Endpoint, ShutdownOutcome, TransportConfig, qlog::QlogConfig},
    rt::Executor,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    utils::octets,
};
use std::{path::Path, process::ExitCode, sync::Arc};

fn tls_options() -> rama::quic::tls::TlsOptions {
    rama::quic::tls::TlsOptions::default().with_backend(if cfg!(feature = "boring") {
        rama::tls::TlsBackend::Boring
    } else {
        rama::tls::TlsBackend::Rustls
    })
}

const ALPN: &[u8] = b"hq-interop";
const REQUEST_LIMIT: usize = octets::kib(4);
const STREAM_LIMIT: usize = 64;
/// Bytes moved per read on either side. Larger reads mean fewer trips through the connection's
/// lock and the blocking file pool, which is what bounds a client pulling many streams at once.
const BUFFER_SIZE: usize = octets::kib(256);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestCase {
    Handshake,
    Transfer,
    Retry,
    MultiConnect,
}

impl TestCase {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "handshake" => Some(Self::Handshake),
            "transfer" => Some(Self::Transfer),
            "retry" => Some(Self::Retry),
            "multiconnect" => Some(Self::MultiConnect),
            _ => None,
        }
    }
}

/// Reject unsupported cases before opening sockets or reading runner mounts.
pub fn testcase_or_exit(value: &str) -> Result<TestCase, ExitCode> {
    TestCase::parse(value).ok_or_else(|| {
        eprintln!("unsupported TESTCASE: {value}");
        ExitCode::from(127)
    })
}

pub fn init_tracing() {
    tracing::subscriber::registry()
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
}

/// Set to shrink the receive windows to 64 KiB per stream and 256 KiB per connection, so a
/// transfer of any size forces stream- and connection-level window updates. The default windows
/// are Rama's own, which is what a benchmark of this endpoint should see.
pub const SMALL_WINDOWS: &str = "RAMA_INTEROP_SMALL_WINDOWS";

async fn transport(executor: Executor, role: &str) -> Result<Arc<TransportConfig>, BoxError> {
    let mut config =
        TransportConfig::default().with_max_concurrent_bidi_streams((STREAM_LIMIT as u32).into());
    if std::env::var_os(SMALL_WINDOWS).is_some() {
        config = config
            .with_stream_receive_window(octets::kib_u32(64).into())
            .with_receive_window(octets::kib_u32(256).into());
    }
    if let Some(directory) = std::env::var_os("QLOGDIR") {
        let directory = Path::new(&directory);
        tokio::fs::create_dir_all(directory)
            .await
            .context("create qlog directory")?;
        let file = tokio::fs::File::create(directory.join(format!("rama-{role}.sqlog")))
            .await
            .context("create qlog file")?;
        config.set_qlog_recorder(
            QlogConfig::default()
                .with_writer(file)
                .with_executor(executor)
                .with_error_sink(TracingErrorSink::warn())
                .start()?,
        );
    }
    Ok(Arc::new(config))
}

/// Join every transport producer before the shared shutdown drains the qlog recorder.
async fn shutdown_endpoint(
    endpoint: &Endpoint,
    outcome: Result<(), BoxError>,
) -> Result<(), BoxError> {
    match endpoint.shutdown().await {
        ShutdownOutcome::Drained => {}
        ShutdownOutcome::Forced => {
            tracing::debug!("endpoint shutdown reached its transport budget")
        }
        ShutdownOutcome::DriverFailed => {
            if outcome.is_ok() {
                return Err("endpoint driver failed during shutdown".into());
            }
            tracing::warn!("endpoint driver also failed during shutdown");
        }
    }
    outcome
}

fn check_alpn(connection: &Connection) -> Result<(), BoxError> {
    if connection
        .handshake_data()
        .and_then(|data| data.application_layer_protocol)
        != Some(ApplicationProtocol::from(ALPN))
    {
        return Err("peer did not negotiate hq-interop".into());
    }
    Ok(())
}

/// Runner filenames are ASCII. Reject encoded or ambiguous paths instead of decoding them.
fn relative_path(target: &str) -> Result<&Path, BoxError> {
    let relative = target
        .strip_prefix('/')
        .ok_or("request path must be absolute")?;
    if relative.is_empty() || target.len() > REQUEST_LIMIT - 6 {
        return Err("invalid request path length".into());
    }
    for segment in relative.split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || !segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err("request path contains an unsupported segment".into());
        }
    }
    Ok(Path::new(relative))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runner_paths_are_confined() {
        assert_eq!(
            relative_path("/nested/file-1.bin").unwrap(),
            Path::new("nested/file-1.bin")
        );
        for target in [
            "",
            "/",
            "file",
            "//file",
            "/../file",
            "/a/./file",
            "/%2e%2e/file",
            "/a\\file",
            "/file?query",
            "/file\r\n",
        ] {
            assert!(relative_path(target).is_err(), "accepted {target:?}");
        }
        assert!(relative_path(&format!("/{}", "a".repeat(REQUEST_LIMIT))).is_err());
    }

    #[test]
    fn runner_paths_reserve_space_for_request_framing() {
        let framing_length = b"GET \r\n".len();
        let mut target = format!("/{}", "a".repeat(REQUEST_LIMIT - framing_length - 1));
        assert_eq!(format!("GET {target}\r\n").len(), REQUEST_LIMIT);
        assert_eq!(relative_path(&target).unwrap(), Path::new(&target[1..]));

        target.push('a');
        assert!(relative_path(&target).is_err());
    }

    #[test]
    fn unsupported_testcases_do_not_fall_back_to_transfer() {
        for value in [
            "",
            "http3",
            "resumption",
            "zerortt",
            "chacha20",
            "v2",
            "keyupdate",
            "connectionmigration",
            "unknown",
        ] {
            assert_eq!(TestCase::parse(value), None);
        }
        assert_eq!(TestCase::parse("retry"), Some(TestCase::Retry));
    }
}
