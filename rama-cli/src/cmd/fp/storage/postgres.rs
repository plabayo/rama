use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use deadpool_postgres::Config;
use rama::{
    error::{ErrorContext, OpaqueError},
    net::{address::Host, stream::Stream},
    tls::{
        boring::client::{TlsStream, tls_connect},
        boring::dep::boring::{hash::MessageDigest, nid::Nid, ssl::SslRef},
    },
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::tls::{self, ChannelBinding, MakeTlsConnect, TlsConnect};

pub(super) use deadpool_postgres::Pool;

pub(super) async fn new_pool(url: String) -> Result<Pool, OpaqueError> {
    Config {
        url: Some(url),
        dbname: Some("fp".to_owned()),
        ..Default::default()
    }
    .create_pool(None, MakeBoringTlsConnector)
    .context("create postgres deadpool")
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
struct MakeBoringTlsConnector;

#[derive(Debug, Clone)]
struct BoringTlsConnector {
    host: Host,
}

impl<S> MakeTlsConnect<S> for MakeBoringTlsConnector
where
    S: Stream + Unpin,
{
    type Stream = BoringTlsStream<S>;
    type TlsConnect = BoringTlsConnector;
    type Error = OpaqueError;

    fn make_tls_connect(&mut self, domain: &str) -> Result<BoringTlsConnector, OpaqueError> {
        let host: Host = domain.parse().context("parse host from domain")?;
        Ok(BoringTlsConnector { host })
    }
}

impl<S> TlsConnect<S> for BoringTlsConnector
where
    S: Stream + Unpin,
{
    type Stream = BoringTlsStream<S>;
    type Error = OpaqueError;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<BoringTlsStream<S>, Self::Error>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        Box::pin(async move {
            let tls_stream = tls_connect(self.host, stream, None).await?;
            Ok(BoringTlsStream(tls_stream))
        })
    }
}
/// The stream returned by `TlsConnector`.
struct BoringTlsStream<S>(TlsStream<S>);

impl<S> AsyncRead for BoringTlsStream<S>
where
    S: Stream + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for BoringTlsStream<S>
where
    S: Stream + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl<S> tls::TlsStream for BoringTlsStream<S>
where
    S: Stream + Unpin,
{
    fn channel_binding(&self) -> ChannelBinding {
        match tls_server_end_point(self.0.ssl_ref()) {
            Some(buf) => ChannelBinding::tls_server_end_point(buf),
            None => ChannelBinding::none(),
        }
    }
}

fn tls_server_end_point(ssl: &SslRef) -> Option<Vec<u8>> {
    let cert = ssl.peer_certificate()?;
    let algo_nid = cert.signature_algorithm().object().nid();
    let signature_algorithms = algo_nid.signature_algorithms()?;
    let md = match signature_algorithms.digest {
        Nid::MD5 | Nid::SHA1 => MessageDigest::sha256(),
        nid => MessageDigest::from_nid(nid)?,
    };
    cert.digest(md).ok().map(|b| b.to_vec())
}
