//! Unix-socket transport for the FastCGI client.

use std::path::{Path, PathBuf};

use rama_core::{
    Service,
    bytes::Bytes,
    error::{BoxError, ErrorContext as _},
};
use rama_net::client::EstablishedClientConnection;
use rama_unix::{UnixStream, client::default_unix_connect};

use crate::client::FastCgiClientRequest;
use crate::proto::cgi;

use super::tcp::{PhpFpmStager, with_php_fpm};

/// Open a Unix-socket connection to a FastCGI backend (typically php-fpm at
/// e.g. `/run/php/php8.3-fpm.sock`).
///
/// Mirrors [`FastCgiTcpConnector`][super::FastCgiTcpConnector] but talks to
/// a Unix domain socket. Use [`Self::php_fpm`] for the common case (sets
/// `SCRIPT_FILENAME` + `DOCUMENT_ROOT`); use [`Self::with_param`] for any
/// other CGI variable.
///
/// Available only on Unix-family targets.
#[derive(Debug, Clone)]
pub struct FastCgiUnixConnector {
    socket_path: PathBuf,
    extra_params: Vec<(Bytes, Bytes)>,
}

impl FastCgiUnixConnector {
    /// Create a bare Unix-socket connector — no CGI params injected.
    #[must_use]
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            extra_params: Vec::new(),
        }
    }

    /// php-fpm common case: opens a connection to `socket_path` and stages
    /// `SCRIPT_FILENAME = script` + `DOCUMENT_ROOT = <parent dir of script>`.
    #[must_use]
    pub fn php_fpm(socket_path: impl Into<PathBuf>, script: impl AsRef<Path>) -> Self {
        with_php_fpm(Self::new(socket_path), script)
    }

    /// Stage an arbitrary CGI param onto every request.
    #[must_use]
    pub fn with_param(mut self, name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        self.extra_params.push((name.into(), value.into()));
        self
    }

    /// Stage `SCRIPT_FILENAME` for every request.
    #[must_use]
    pub fn with_script_filename(self, path: impl AsRef<Path>) -> Self {
        let bytes = Bytes::copy_from_slice(path.as_ref().as_os_str().as_encoded_bytes());
        self.with_param(cgi::SCRIPT_FILENAME, bytes)
    }

    /// Stage `DOCUMENT_ROOT` for every request.
    #[must_use]
    pub fn with_document_root(self, path: impl AsRef<Path>) -> Self {
        let bytes = Bytes::copy_from_slice(path.as_ref().as_os_str().as_encoded_bytes());
        self.with_param(cgi::DOCUMENT_ROOT, bytes)
    }
}

impl Service<FastCgiClientRequest> for FastCgiUnixConnector {
    type Output = EstablishedClientConnection<UnixStream, FastCgiClientRequest>;
    type Error = BoxError;

    async fn serve(&self, mut input: FastCgiClientRequest) -> Result<Self::Output, Self::Error> {
        for (name, value) in &self.extra_params {
            input.params.push((name.clone(), value.clone()));
        }
        let (conn, _info) = default_unix_connect(&self.socket_path)
            .await
            .with_context(|| {
                format!(
                    "connect to FastCGI backend over Unix socket: {}",
                    self.socket_path.display()
                )
            })?;
        Ok(EstablishedClientConnection { input, conn })
    }
}

impl PhpFpmStager for FastCgiUnixConnector {
    fn stage_script_filename(self, path: &Path) -> Self {
        self.with_script_filename(path)
    }
    fn stage_document_root(self, path: &Path) -> Self {
        self.with_document_root(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::params::decode_params;
    use crate::proto::{BeginRequestBody, RecordHeader, RecordType, Role, params::NvPairRef};
    use rama_core::Service;
    use rama_core::bytes::{Bytes, BytesMut};
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    fn staged(c: &FastCgiUnixConnector, name: &[u8]) -> Option<Bytes> {
        c.extra_params
            .iter()
            .find(|(k, _)| k.as_ref() == name)
            .map(|(_, v)| v.clone())
    }

    #[tokio::test]
    async fn test_php_fpm_preset_stages_params() {
        let c = FastCgiUnixConnector::php_fpm("/tmp/dummy.sock", "/var/www/index.php");
        assert_eq!(
            staged(&c, b"SCRIPT_FILENAME").as_deref(),
            Some(b"/var/www/index.php".as_ref())
        );
        assert_eq!(
            staged(&c, b"DOCUMENT_ROOT").as_deref(),
            Some(b"/var/www".as_ref())
        );
    }

    /// End-to-end via a real Unix socket: connect, write BEGIN+PARAMS, parse
    /// on the server side, verify the staged params landed on the wire.
    #[tokio::test]
    async fn test_connector_writes_staged_params_over_unix_socket() {
        let dir = TempDir::with_prefix("rfcgi-test.").unwrap();
        let socket_path = dir.path().join("test.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        // Server task: accept one conn, decode BEGIN + PARAMS, return them.
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // BEGIN_REQUEST (8 header + 8 body)
            let mut buf = [0u8; 16];
            sock.read_exact(&mut buf).await.unwrap();
            // PARAMS records until empty.
            let mut all = Vec::new();
            loop {
                let mut h = [0u8; 8];
                sock.read_exact(&mut h).await.unwrap();
                let cl = u16::from_be_bytes([h[4], h[5]]) as usize;
                if cl == 0 {
                    break;
                }
                let mut body = vec![0u8; cl];
                sock.read_exact(&mut body).await.unwrap();
                all.extend_from_slice(&body);
            }
            let _shutdown = sock.shutdown().await;
            all
        });

        let connector = FastCgiUnixConnector::php_fpm(&socket_path, "/srv/app.php");
        let request = FastCgiClientRequest::new(vec![(
            Bytes::from_static(b"REQUEST_METHOD"),
            Bytes::from_static(b"GET"),
        )]);
        let conn = connector.serve(request).await.unwrap();

        // Drive a minimal BEGIN + PARAMS over the wire so the test server
        // can decode them.
        let mut io = conn.conn;
        RecordHeader::new(RecordType::BeginRequest, 1, 8)
            .write_to(&mut io)
            .await
            .unwrap();
        BeginRequestBody {
            role: Role::Responder,
            keep_conn: false,
        }
        .write_to(&mut io)
        .await
        .unwrap();
        let mut pbuf = BytesMut::new();
        for (n, v) in &conn.input.params {
            NvPairRef::new(n, v).write_to_buf(&mut pbuf).unwrap();
        }
        RecordHeader::new(RecordType::Params, 1, pbuf.len() as u16)
            .write_to(&mut io)
            .await
            .unwrap();
        io.write_all(&pbuf).await.unwrap();
        RecordHeader::new(RecordType::Params, 1, 0)
            .write_to(&mut io)
            .await
            .unwrap();
        io.shutdown().await.unwrap();

        let bytes = server.await.unwrap();
        let decoded: Vec<(Vec<u8>, Vec<u8>)> = decode_params(&bytes)
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();

        // The staged php_fpm params must have arrived on the wire.
        assert!(
            decoded
                .iter()
                .any(|(k, v)| k == b"SCRIPT_FILENAME" && v == b"/srv/app.php"),
            "SCRIPT_FILENAME missing: {decoded:?}"
        );
        assert!(
            decoded
                .iter()
                .any(|(k, v)| k == b"DOCUMENT_ROOT" && v == b"/srv"),
            "DOCUMENT_ROOT missing: {decoded:?}"
        );
        // Original caller-supplied param also survives.
        assert!(
            decoded
                .iter()
                .any(|(k, v)| k == b"REQUEST_METHOD" && v == b"GET")
        );
    }
}
