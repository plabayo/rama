//! TCP transport for the FastCGI client.

use std::path::Path;

use rama_core::{
    Service,
    bytes::Bytes,
    error::{BoxError, ErrorContext as _},
    rt::Executor,
};
use rama_net::{address::HostWithPort, client::EstablishedClientConnection};
use rama_tcp::{TcpStream, client::default_tcp_connect};

use crate::client::FastCgiClientRequest;
use crate::proto::cgi;

/// Open a TCP connection to a FastCGI backend (typically php-fpm at
/// `127.0.0.1:9000`).
///
/// Stages any [`with_param`][Self::with_param] / [`with_script_filename`][Self::with_script_filename]
/// / [`with_document_root`][Self::with_document_root] values onto the
/// [`FastCgiClientRequest::params`] vec just before forwarding to the inner
/// HTTP-→-FastCGI conversion. The connector itself owns no per-request
/// state, so it is cheap to clone.
///
/// See the module-level docs for usage examples and the [`Self::php_fpm`]
/// preset.
#[derive(Debug, Clone)]
pub struct FastCgiTcpConnector {
    target: HostWithPort,
    exec: Executor,
    extra_params: Vec<(Bytes, Bytes)>,
}

impl FastCgiTcpConnector {
    /// Create a bare TCP connector — no CGI params injected.
    ///
    /// Use [`Self::php_fpm`] if you want `SCRIPT_FILENAME` and
    /// `DOCUMENT_ROOT` set automatically (the 90% case).
    #[must_use]
    pub fn new(target: HostWithPort, exec: Executor) -> Self {
        Self {
            target,
            exec,
            extra_params: Vec::new(),
        }
    }

    /// Convenience constructor for the php-fpm common case: opens a TCP
    /// connection to `target` and injects `SCRIPT_FILENAME = script` plus
    /// `DOCUMENT_ROOT = <parent dir of script>`. Both params are required
    /// for php-fpm to route the request to the right script.
    #[must_use]
    pub fn php_fpm(target: HostWithPort, exec: Executor, script: impl AsRef<Path>) -> Self {
        with_php_fpm(Self::new(target, exec), script)
    }

    /// Push an arbitrary CGI param onto every request handled by this connector.
    ///
    /// Use the [`cgi`] constants for spec-defined names:
    ///
    /// ```ignore
    /// use rama_fastcgi::client::transport::FastCgiTcpConnector;
    /// use rama_fastcgi::proto::cgi;
    /// let c = FastCgiTcpConnector::new(addr, exec)
    ///     .with_param(cgi::SCRIPT_FILENAME, "/srv/app.php")
    ///     .with_param(cgi::REDIRECT_STATUS, "200");
    /// ```
    #[must_use]
    pub fn with_param(mut self, name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        self.extra_params.push((name.into(), value.into()));
        self
    }

    /// Stage `SCRIPT_FILENAME` for every request. See [`cgi::SCRIPT_FILENAME`].
    #[must_use]
    pub fn with_script_filename(self, path: impl AsRef<Path>) -> Self {
        let bytes = Bytes::copy_from_slice(path.as_ref().as_os_str().as_encoded_bytes());
        self.with_param(cgi::SCRIPT_FILENAME, bytes)
    }

    /// Stage `DOCUMENT_ROOT` for every request. See [`cgi::DOCUMENT_ROOT`].
    #[must_use]
    pub fn with_document_root(self, path: impl AsRef<Path>) -> Self {
        let bytes = Bytes::copy_from_slice(path.as_ref().as_os_str().as_encoded_bytes());
        self.with_param(cgi::DOCUMENT_ROOT, bytes)
    }
}

impl Service<FastCgiClientRequest> for FastCgiTcpConnector {
    type Output = EstablishedClientConnection<TcpStream, FastCgiClientRequest>;
    type Error = BoxError;

    async fn serve(&self, mut input: FastCgiClientRequest) -> Result<Self::Output, Self::Error> {
        for (name, value) in &self.extra_params {
            input.params.push((name.clone(), value.clone()));
        }
        let (conn, _peer) =
            default_tcp_connect(&input.extensions, self.target.clone(), self.exec.clone())
                .await
                .with_context(|| format!("connect to FastCGI backend over TCP: {}", self.target))?;
        Ok(EstablishedClientConnection { input, conn })
    }
}

pub(super) fn with_php_fpm<C>(connector: C, script: impl AsRef<Path>) -> C
where
    C: PhpFpmStager,
{
    let script_path = script.as_ref();
    let document_root = script_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| script_path.to_path_buf());
    connector
        .stage_script_filename(script_path)
        .stage_document_root(&document_root)
}

/// Internal: shared `php_fpm` plumbing for both TCP and Unix connectors.
pub(super) trait PhpFpmStager: Sized {
    fn stage_script_filename(self, path: &Path) -> Self;
    fn stage_document_root(self, path: &Path) -> Self;
}

impl PhpFpmStager for FastCgiTcpConnector {
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
    use rama_core::Service;
    use rama_utils::octets::kib;
    use std::sync::Arc;

    /// php_fpm() must populate both SCRIPT_FILENAME and DOCUMENT_ROOT.
    /// The connector hands the staged params to the request, transparently.
    fn staged(c: &FastCgiTcpConnector, name: &[u8]) -> Option<Bytes> {
        c.extra_params
            .iter()
            .find(|(k, _)| k.as_ref() == name)
            .map(|(_, v)| v.clone())
    }

    #[tokio::test]
    async fn test_php_fpm_preset_stages_script_filename_and_document_root() {
        let c = FastCgiTcpConnector::php_fpm(
            "127.0.0.1:9000".parse().unwrap(),
            Executor::new(),
            "/var/www/index.php",
        );
        assert_eq!(
            staged(&c, b"SCRIPT_FILENAME").as_deref(),
            Some(b"/var/www/index.php".as_ref())
        );
        assert_eq!(
            staged(&c, b"DOCUMENT_ROOT").as_deref(),
            Some(b"/var/www".as_ref())
        );
    }

    /// with_param chains cleanly and preserves insertion order.
    #[tokio::test]
    async fn test_with_param_chains() {
        let exec = Executor::new();
        let c = FastCgiTcpConnector::new("127.0.0.1:9000".parse().unwrap(), exec)
            .with_param(cgi::REDIRECT_STATUS, "200")
            .with_param(cgi::SCRIPT_FILENAME, "/app.php");
        assert_eq!(c.extra_params.len(), 2);
        assert_eq!(&c.extra_params[0].0[..], b"REDIRECT_STATUS");
        assert_eq!(&c.extra_params[1].0[..], b"SCRIPT_FILENAME");
    }

    /// End-to-end: spin up a tiny TCP echo server that drains a FastCGI
    /// request, then drive the connector against it and assert that the
    /// staged php_fpm params appear in the wire frame.
    #[tokio::test]
    async fn test_connector_stages_params_onto_request() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let host_with_port: HostWithPort = format!("{addr}").parse().unwrap();

        // Server task: accept one connection, read BEGIN + PARAMS, echo the
        // PARAMS bytes back out for inspection, then close.
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            // BEGIN_REQUEST (8 header + 8 body)
            let mut hdr = [0u8; 16];
            sock.read_exact(&mut hdr).await.unwrap();
            // PARAMS records until empty
            let mut all_params = Vec::new();
            loop {
                let mut h = [0u8; 8];
                sock.read_exact(&mut h).await.unwrap();
                let cl = u16::from_be_bytes([h[4], h[5]]) as usize;
                if cl == 0 {
                    break;
                }
                let mut buf = vec![0u8; cl];
                sock.read_exact(&mut buf).await.unwrap();
                all_params.extend_from_slice(&buf);
            }
            let _shutdown = sock.shutdown().await;
            all_params
        });

        let exec = Executor::new();
        let connector = FastCgiTcpConnector::new(host_with_port, exec)
            .with_param(Bytes::from_static(b"X_CUSTOM"), Bytes::from_static(b"yes"));
        let request = FastCgiClientRequest::new(vec![(
            Bytes::from_static(b"REQUEST_METHOD"),
            Bytes::from_static(b"GET"),
        )]);
        let conn = connector.serve(request).await.unwrap();
        // Write a minimal BEGIN + PARAMS to satisfy the server's reader.
        use crate::proto::{BeginRequestBody, RecordHeader, RecordType, Role, params::NvPairRef};
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
        let mut pbuf = rama_core::bytes::BytesMut::new();
        for (n, v) in &conn.input.params {
            NvPairRef::new(n, v).write_to_buf(&mut pbuf).unwrap();
        }
        let hdr = RecordHeader::new(RecordType::Params, 1, pbuf.len() as u16);
        hdr.write_to(&mut io).await.unwrap();
        use tokio::io::AsyncWriteExt;
        io.write_all(&pbuf).await.unwrap();
        RecordHeader::new(RecordType::Params, 1, 0)
            .write_to(&mut io)
            .await
            .unwrap();
        io.shutdown().await.unwrap();

        let params_bytes = server.await.unwrap();
        let decoded: Vec<(Vec<u8>, Vec<u8>)> = crate::proto::params::decode_params(&params_bytes)
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        assert!(
            decoded.iter().any(|(k, v)| k == b"X_CUSTOM" && v == b"yes"),
            "staged param missing in decoded set: {decoded:?}"
        );
        // Sanity: cap to avoid silent test bloat.
        assert!(params_bytes.len() < kib(64));
        // Reference Arc so the test compiles without an unused-import warning
        // on `Arc` when this file is built standalone.
        let _ = Arc::new(());
    }
}
