//! types and logic for [`HttpPeekRouter`]

use std::fmt;

use rama_core::{
    Context, Service,
    error::{BoxError, ErrorContext},
    service::RejectService,
};
use tokio::io::AsyncReadExt;

use crate::stream::{PeekStream, StackReader};

/// A [`Service`] router that can be used to support
/// http/1x and h2 traffic as well as non-tls traffic.
///
/// By default non-tls traffic is rejected using [`RejectService`].
/// Use [`TlsPeekRouter::with_fallback`] to configure the fallback service.
pub struct HttpPeekRouter<T, F = RejectService<(), NoHttpRejectError>> {
    http_acceptor: T,
    fallback: F,
}

/// Type wrapper used by [`HttpPeekRouter::new_dual`]
/// to serve http/1x and h2 separately.
pub struct HttpDualAcceptor<T, U> {
    http1: T,
    h2: U,
}

impl<T: Clone, U: Clone> Clone for HttpDualAcceptor<T, U> {
    fn clone(&self) -> Self {
        Self {
            http1: self.http1.clone(),
            h2: self.h2.clone(),
        }
    }
}

impl<T: fmt::Debug, U: fmt::Debug> fmt::Debug for HttpDualAcceptor<T, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpDualAcceptor")
            .field("http1", &self.http1)
            .field("h2", &self.h2)
            .finish()
    }
}

/// Type wrapper used by [`HttpPeekRouter::new`]
/// to serve http/1x and h2 with a single service.
pub struct HttpAutoAcceptor<T>(T);

impl<T: Clone> Clone for HttpAutoAcceptor<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: fmt::Debug> fmt::Debug for HttpAutoAcceptor<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HttpAutoAcceptor").field(&self.0).finish()
    }
}

/// Type wrapper used by [`HttpPeekRouter::new_http1`]
/// to only serve http/1x, and send h2 to the fallback.
pub struct Http1Acceptor<T>(T);

impl<T: Clone> Clone for Http1Acceptor<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: fmt::Debug> fmt::Debug for Http1Acceptor<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Http1Acceptor").field(&self.0).finish()
    }
}

/// Type wrapper used by [`HttpPeekRouter::new_h2`]
/// to only serve h2, and send http/1x to the fallback.
pub struct H2Acceptor<T>(T);

impl<T: Clone> Clone for H2Acceptor<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: fmt::Debug> fmt::Debug for H2Acceptor<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("H2Acceptor").field(&self.0).finish()
    }
}
rama_utils::macros::error::static_str_error! {
    #[doc = "non-http connection is rejected"]
    pub struct NoHttpRejectError;
}

impl<T> HttpPeekRouter<HttpAutoAcceptor<T>> {
    /// Create a new [`HttpPeekRouter`] using a service
    /// which can handle h2 and http/1x versions alike.
    pub fn new(auto_acceptor: T) -> Self {
        Self {
            http_acceptor: HttpAutoAcceptor(auto_acceptor),
            fallback: RejectService::new(NoHttpRejectError),
        }
    }
}

impl<T> HttpPeekRouter<Http1Acceptor<T>> {
    /// Create a new [`HttpPeekRouter`] using a service
    /// which handles http/1x traffic but forwards h2 traffic to fallback.
    pub fn new_http1(http1_acceptor: T) -> Self {
        Self {
            http_acceptor: Http1Acceptor(http1_acceptor),
            fallback: RejectService::new(NoHttpRejectError),
        }
    }
}

impl<T> HttpPeekRouter<H2Acceptor<T>> {
    /// Create a new [`HttpPeekRouter`] using a service
    /// which handles h2 traffic but forwards http/1x traffic to fallback.
    pub fn new_h2(h2_acceptor: T) -> Self {
        Self {
            http_acceptor: H2Acceptor(h2_acceptor),
            fallback: RejectService::new(NoHttpRejectError),
        }
    }
}

impl<T> HttpPeekRouter<T> {
    /// Attach a fallback [`Service`] tp this [`HttpPeekRouter`].
    pub fn with_fallback<F>(self, fallback: F) -> HttpPeekRouter<T, F> {
        HttpPeekRouter {
            http_acceptor: self.http_acceptor,
            fallback,
        }
    }
}

impl<T, U> HttpPeekRouter<HttpDualAcceptor<T, U>> {
    /// Create a new [`HttpPeekRouter`] using a service
    /// which handles http/1x and h2 in two separate services.
    pub fn new_dual(http1_acceptor: T, h2_acceptor: U) -> Self {
        Self {
            http_acceptor: HttpDualAcceptor {
                http1: http1_acceptor,
                h2: h2_acceptor,
            },
            fallback: RejectService::new(NoHttpRejectError),
        }
    }
}

impl<T: Clone, F: Clone> Clone for HttpPeekRouter<T, F> {
    fn clone(&self) -> Self {
        Self {
            http_acceptor: self.http_acceptor.clone(),
            fallback: self.fallback.clone(),
        }
    }
}

impl<T: fmt::Debug, F: fmt::Debug> fmt::Debug for HttpPeekRouter<T, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpPeekRouter")
            .field("http_acceptor", &self.http_acceptor)
            .field("fallback", &self.fallback)
            .finish()
    }
}

impl<State, Stream, Response, T, F> Service<State, Stream>
    for HttpPeekRouter<HttpAutoAcceptor<T>, F>
where
    State: Clone + Send + Sync + 'static,
    Stream: crate::stream::Stream + Unpin,
    Response: Send + 'static,
    T: Service<State, HttpPeekStream<Stream>, Response = Response, Error: Into<BoxError>>,
    F: Service<State, HttpPeekStream<Stream>, Response = Response, Error: Into<BoxError>>,
{
    type Response = Response;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        stream: Stream,
    ) -> Result<Self::Response, Self::Error> {
        let (version, stream) = peek_http_stream(stream).await?;
        if version.is_some() {
            tracing::trace!(?version, "http peek: serve[auto]: http acceptor");
            self.http_acceptor
                .0
                .serve(ctx, stream)
                .await
                .map_err(Into::into)
        } else {
            tracing::trace!(?version, "http peek: serve[auto]: fallback");
            self.fallback.serve(ctx, stream).await.map_err(Into::into)
        }
    }
}

impl<State, Stream, Response, T, F> Service<State, Stream> for HttpPeekRouter<Http1Acceptor<T>, F>
where
    State: Clone + Send + Sync + 'static,
    Stream: crate::stream::Stream + Unpin,
    Response: Send + 'static,
    T: Service<State, HttpPeekStream<Stream>, Response = Response, Error: Into<BoxError>>,
    F: Service<State, HttpPeekStream<Stream>, Response = Response, Error: Into<BoxError>>,
{
    type Response = Response;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        stream: Stream,
    ) -> Result<Self::Response, Self::Error> {
        let (version, stream) = peek_http_stream(stream).await?;
        if version == Some(HttpPeekVersion::Http1x) {
            tracing::trace!(?version, "http peek: serve[http1]: http/1x acceptor");
            self.http_acceptor
                .0
                .serve(ctx, stream)
                .await
                .map_err(Into::into)
        } else {
            tracing::trace!(?version, "http peek: serve[http1]: fallback");
            self.fallback.serve(ctx, stream).await.map_err(Into::into)
        }
    }
}

impl<State, Stream, Response, T, F> Service<State, Stream> for HttpPeekRouter<H2Acceptor<T>, F>
where
    State: Clone + Send + Sync + 'static,
    Stream: crate::stream::Stream + Unpin,
    Response: Send + 'static,
    T: Service<State, HttpPeekStream<Stream>, Response = Response, Error: Into<BoxError>>,
    F: Service<State, HttpPeekStream<Stream>, Response = Response, Error: Into<BoxError>>,
{
    type Response = Response;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        stream: Stream,
    ) -> Result<Self::Response, Self::Error> {
        let (version, stream) = peek_http_stream(stream).await?;
        if version == Some(HttpPeekVersion::H2) {
            tracing::trace!(?version, "http peek: serve[h2]: http acceptor");
            self.http_acceptor
                .0
                .serve(ctx, stream)
                .await
                .map_err(Into::into)
        } else {
            tracing::trace!(?version, "http peek: serve[h2]: fallback");
            self.fallback.serve(ctx, stream).await.map_err(Into::into)
        }
    }
}

impl<State, Stream, Response, T, U, F> Service<State, Stream>
    for HttpPeekRouter<HttpDualAcceptor<T, U>, F>
where
    State: Clone + Send + Sync + 'static,
    Stream: crate::stream::Stream + Unpin,
    Response: Send + 'static,
    T: Service<State, HttpPeekStream<Stream>, Response = Response, Error: Into<BoxError>>,
    U: Service<State, HttpPeekStream<Stream>, Response = Response, Error: Into<BoxError>>,
    F: Service<State, HttpPeekStream<Stream>, Response = Response, Error: Into<BoxError>>,
{
    type Response = Response;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        stream: Stream,
    ) -> Result<Self::Response, Self::Error> {
        let (version, stream) = peek_http_stream(stream).await?;
        match version {
            Some(HttpPeekVersion::H2) => {
                tracing::trace!(?version, "http peek: serve[dual]: h2 acceptor");
                self.http_acceptor
                    .h2
                    .serve(ctx, stream)
                    .await
                    .map_err(Into::into)
            }
            Some(HttpPeekVersion::Http1x) => {
                tracing::trace!(?version, "http peek: serve[dual]: http/1x acceptor");
                self.http_acceptor
                    .http1
                    .serve(ctx, stream)
                    .await
                    .map_err(Into::into)
            }
            None => {
                tracing::trace!(?version, "http peek: serve[dual]: fallback");
                self.fallback.serve(ctx, stream).await.map_err(Into::into)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpPeekVersion {
    Http1x,
    H2,
}

async fn peek_http_stream<Stream: crate::stream::Stream + Unpin>(
    mut stream: Stream,
) -> Result<(Option<HttpPeekVersion>, HttpPeekStream<Stream>), BoxError> {
    let mut peek_buf = [0u8; HTTP_HEADER_PEEK_LEN];
    let n = stream
        .read(&mut peek_buf)
        .await
        .context("try to read http prefix")?;

    const HTTP_METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"CONNECT ",
        b"TRACE ",
        b"PATCH ",
    ];

    let http_version = if n == H2_MAGIC_PREFIX.len() && peek_buf.eq(H2_MAGIC_PREFIX) {
        Some(HttpPeekVersion::H2)
    } else if HTTP_METHODS
        .iter()
        .any(|method| peek_buf.starts_with(method))
    {
        Some(HttpPeekVersion::Http1x)
    } else {
        None
    };

    tracing::trace!(?http_version, "http prefix header read");

    let offset = HTTP_HEADER_PEEK_LEN - n;
    if offset > 0 {
        tracing::trace!(
            %n,
            "move http peek buffer cursor due to reading not enough"
        );
        for i in (0..n).rev() {
            peek_buf[i + offset] = peek_buf[i];
        }
    }

    let mut peek = StackReader::new(peek_buf);
    peek.skip(offset);

    let stream = PeekStream::new(peek, stream);

    Ok((http_version, stream))
}

const H2_MAGIC_PREFIX: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HTTP_HEADER_PEEK_LEN: usize = H2_MAGIC_PREFIX.len();

/// [`PeekStream`] alias used by [`HttpPeekRouter`].
pub type HttpPeekStream<S> = PeekStream<StackReader<HTTP_HEADER_PEEK_LEN>, S>;

#[cfg(test)]
mod test {
    use rama_core::service::{RejectError, service_fn};
    use std::convert::Infallible;

    use crate::stream::Stream;

    use super::*;

    #[tokio::test]
    async fn test_peek_router() {
        let http_service = service_fn(async |_, _| Ok::<_, Infallible>("http"));
        let fallback_service = service_fn(async |_, _| Ok::<_, Infallible>("other"));

        let peek_http_svc = HttpPeekRouter::new(http_service).with_fallback(fallback_service);

        let response = peek_http_svc
            .serve(Context::default(), std::io::Cursor::new(b"".to_vec()))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(
                Context::default(),
                std::io::Cursor::new(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec()),
            )
            .await
            .unwrap();
        assert_eq!("http", response);

        let response = peek_http_svc
            .serve(
                Context::default(),
                std::io::Cursor::new(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nfoo".to_vec()),
            )
            .await
            .unwrap();
        assert_eq!("http", response);

        const HTTP_METHODS: &[&str] = &[
            "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE ", "PATCH ",
        ];
        for method in HTTP_METHODS {
            let response = peek_http_svc
                .serve(
                    Context::default(),
                    std::io::Cursor::new(format!("{method} /foobar HTTP/1.1").into_bytes()),
                )
                .await
                .unwrap();
            assert_eq!("http", response);
        }

        let response = peek_http_svc
            .serve(Context::default(), std::io::Cursor::new(b"foo".to_vec()))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(Context::default(), std::io::Cursor::new(b"foobar".to_vec()))
            .await
            .unwrap();
        assert_eq!("other", response);
    }

    #[tokio::test]
    async fn test_peek_http1_router() {
        let http_service = service_fn(async |_, _| Ok::<_, Infallible>("http1"));
        let fallback_service = service_fn(async |_, _| Ok::<_, Infallible>("other"));

        let peek_http_svc = HttpPeekRouter::new_http1(http_service).with_fallback(fallback_service);

        let response = peek_http_svc
            .serve(Context::default(), std::io::Cursor::new(b"".to_vec()))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(
                Context::default(),
                std::io::Cursor::new(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nfoo".to_vec()),
            )
            .await
            .unwrap();
        assert_eq!("other", response);

        const HTTP_METHODS: &[&str] = &[
            "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE ", "PATCH ",
        ];
        for method in HTTP_METHODS {
            let response = peek_http_svc
                .serve(
                    Context::default(),
                    std::io::Cursor::new(format!("{method} /foobar HTTP/1.1").into_bytes()),
                )
                .await
                .unwrap();
            assert_eq!("http1", response);
        }

        let response = peek_http_svc
            .serve(Context::default(), std::io::Cursor::new(b"foo".to_vec()))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(Context::default(), std::io::Cursor::new(b"foobar".to_vec()))
            .await
            .unwrap();
        assert_eq!("other", response);
    }

    #[tokio::test]
    async fn test_peek_h2_router() {
        let http_service = service_fn(async |_, _| Ok::<_, Infallible>("h2"));
        let fallback_service = service_fn(async |_, _| Ok::<_, Infallible>("other"));

        let peek_http_svc = HttpPeekRouter::new_h2(http_service).with_fallback(fallback_service);

        let response = peek_http_svc
            .serve(Context::default(), std::io::Cursor::new(b"".to_vec()))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(
                Context::default(),
                std::io::Cursor::new(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nfoo".to_vec()),
            )
            .await
            .unwrap();
        assert_eq!("h2", response);

        const HTTP_METHODS: &[&str] = &[
            "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE ", "PATCH ",
        ];
        for method in HTTP_METHODS {
            let response = peek_http_svc
                .serve(
                    Context::default(),
                    std::io::Cursor::new(format!("{method} /foobar HTTP/1.1").into_bytes()),
                )
                .await
                .unwrap();
            assert_eq!("other", response);
        }

        let response = peek_http_svc
            .serve(Context::default(), std::io::Cursor::new(b"foo".to_vec()))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(Context::default(), std::io::Cursor::new(b"foobar".to_vec()))
            .await
            .unwrap();
        assert_eq!("other", response);
    }

    #[tokio::test]
    async fn test_peek_dual_router() {
        let http1_service = service_fn(async |_, _| Ok::<_, Infallible>("http1"));
        let h2_service = service_fn(async |_, _| Ok::<_, Infallible>("h2"));
        let fallback_service = service_fn(async |_, _| Ok::<_, Infallible>("other"));

        let peek_http_svc =
            HttpPeekRouter::new_dual(http1_service, h2_service).with_fallback(fallback_service);

        let response = peek_http_svc
            .serve(Context::default(), std::io::Cursor::new(b"".to_vec()))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(
                Context::default(),
                std::io::Cursor::new(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nfoo".to_vec()),
            )
            .await
            .unwrap();
        assert_eq!("h2", response);

        const HTTP_METHODS: &[&str] = &[
            "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE ", "PATCH ",
        ];
        for method in HTTP_METHODS {
            let response = peek_http_svc
                .serve(
                    Context::default(),
                    std::io::Cursor::new(format!("{method} /foobar HTTP/1.1").into_bytes()),
                )
                .await
                .unwrap();
            assert_eq!("http1", response);
        }

        let response = peek_http_svc
            .serve(Context::default(), std::io::Cursor::new(b"foo".to_vec()))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(Context::default(), std::io::Cursor::new(b"foobar".to_vec()))
            .await
            .unwrap();
        assert_eq!("other", response);
    }

    #[tokio::test]
    async fn test_peek_router_read_eof() {
        const CONTENT: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nfoobar";

        async fn http_service_fn(
            mut stream: impl Stream + Unpin,
        ) -> Result<&'static str, BoxError> {
            let mut v = Vec::default();
            let _ = stream.read_to_end(&mut v).await?;
            assert_eq!(CONTENT, v);

            Ok("ok")
        }
        let http_service = service_fn(http_service_fn);

        let peek_http_svc = HttpPeekRouter::new(http_service).with_fallback(RejectService::<
            &'static str,
            RejectError,
        >::new(
            RejectError::default(),
        ));

        let response = peek_http_svc
            .serve(Context::default(), std::io::Cursor::new(CONTENT.to_vec()))
            .await
            .unwrap();
        assert_eq!("ok", response);
    }

    #[tokio::test]
    async fn test_peek_router_read_no_http_eof() {
        let cases = [
            "",
            "foo",
            "abcd",
            "abcde",
            "foobarbazbananas",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nunc vehicula turpis nibh, eget euismod enim elementum et.",
        ];
        for content in cases {
            async fn http_service_fn() -> Result<Vec<u8>, BoxError> {
                Ok("http".as_bytes().to_vec())
            }
            let http_service = service_fn(http_service_fn);

            async fn other_service_fn(
                mut stream: impl Stream + Unpin,
            ) -> Result<Vec<u8>, BoxError> {
                let mut v = Vec::default();
                let _ = stream.read_to_end(&mut v).await?;
                Ok(v)
            }
            let other_service = service_fn(other_service_fn);

            let peek_http_svc = HttpPeekRouter::new(http_service).with_fallback(other_service);

            let response = peek_http_svc
                .serve(
                    Context::default(),
                    std::io::Cursor::new(content.as_bytes().to_vec()),
                )
                .await
                .unwrap();

            assert_eq!(content.as_bytes(), &response[..]);
        }
    }
}
