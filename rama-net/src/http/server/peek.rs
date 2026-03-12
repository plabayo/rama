//! types and logic for [`HttpPeekRouter`]

use rama_core::{
    Service,
    error::{BoxError, ErrorContext},
    io::{PeekIoProvider, PrefixedIo, StackReader},
    service::RejectService,
    telemetry::tracing,
};
use std::time::Duration;
use tokio::{io::AsyncReadExt, time::Instant};

/// A [`Service`] router that can be used to support
/// http/1x and h2 traffic as well as non-tls traffic.
///
/// By default non-http traffic is rejected using [`RejectService`].
/// Use [`HttpPeekRouter::with_fallback`] to configure the fallback service.
#[derive(Debug, Clone)]
pub struct HttpPeekRouter<T, F = RejectService<(), NoHttpRejectError>> {
    http_acceptor: T,
    fallback: F,
    peek_timeout: Option<Duration>,
}

/// Type wrapper used by [`HttpPeekRouter::new_dual`]
/// to serve http/1x and h2 separately.
#[derive(Debug, Clone)]
pub struct HttpDualAcceptor<T, U> {
    http1: T,
    h2: U,
}

/// Type wrapper used by [`HttpPeekRouter::new`]
/// to serve http/1x and h2 with a single service.
#[derive(Debug, Clone)]
pub struct HttpAutoAcceptor<T>(T);

/// Type wrapper used by [`HttpPeekRouter::new_http1`]
/// to only serve http/1x, and send h2 to the fallback.
#[derive(Debug, Clone)]
pub struct Http1Acceptor<T>(T);

/// Type wrapper used by [`HttpPeekRouter::new_h2`]
/// to only serve h2, and send http/1x to the fallback.
#[derive(Debug, Clone)]
pub struct H2Acceptor<T>(T);

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
            peek_timeout: None,
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
            peek_timeout: None,
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
            peek_timeout: None,
        }
    }
}

impl<T> HttpPeekRouter<T> {
    /// Attach a fallback [`Service`] tp this [`HttpPeekRouter`].
    pub fn with_fallback<F>(self, fallback: F) -> HttpPeekRouter<T, F> {
        HttpPeekRouter {
            http_acceptor: self.http_acceptor,
            fallback,
            peek_timeout: self.peek_timeout,
        }
    }
}

impl<T, F> HttpPeekRouter<T, F> {
    rama_utils::macros::generate_set_and_with! {
        /// Set the peek window to timeout on
        pub fn peek_timeout(mut self, peek_timeout: Option<Duration>) -> Self {
            self.peek_timeout = peek_timeout;
            self
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
            peek_timeout: None,
        }
    }
}

impl<PeekableInput, Output, T, F> Service<PeekableInput> for HttpPeekRouter<HttpAutoAcceptor<T>, F>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin>,
    Output: Send + 'static,
    T: Service<
            PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
    F: Service<
            PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
{
    type Output = Output;
    type Error = BoxError;

    async fn serve(&self, input: PeekableInput) -> Result<Self::Output, Self::Error> {
        let (version, peek_input) = peek_http_input(input, self.peek_timeout).await?;
        if version.is_some() {
            tracing::debug!(
                "http peek [auto]: HTTP detect: version = {version:?}; continue with http_acceptor svc"
            );
            self.http_acceptor
                .0
                .serve(peek_input)
                .await
                .into_box_error()
        } else {
            tracing::debug!("http peek [auto]: HTTP not detect: continue with fallback svc");
            self.fallback.serve(peek_input).await.into_box_error()
        }
    }
}

impl<PeekableInput, Output, T, F> Service<PeekableInput> for HttpPeekRouter<Http1Acceptor<T>, F>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin>,
    Output: Send + 'static,
    T: Service<
            PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
    F: Service<
            PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
{
    type Output = Output;
    type Error = BoxError;

    async fn serve(&self, input: PeekableInput) -> Result<Self::Output, Self::Error> {
        let (version, peek_input) = peek_http_input(input, self.peek_timeout).await?;
        if version == Some(HttpPeekVersion::Http1x) {
            tracing::debug!("http peek: serve[http1]: http/1x acceptor; version = {version:?}");
            self.http_acceptor
                .0
                .serve(peek_input)
                .await
                .into_box_error()
        } else {
            tracing::debug!("http peek: serve[http1]: fallback; version = {version:?}");
            self.fallback.serve(peek_input).await.into_box_error()
        }
    }
}

impl<PeekableInput, Output, T, F> Service<PeekableInput> for HttpPeekRouter<H2Acceptor<T>, F>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin>,
    Output: Send + 'static,
    T: Service<
            PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
    F: Service<
            PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
{
    type Output = Output;
    type Error = BoxError;

    async fn serve(&self, input: PeekableInput) -> Result<Self::Output, Self::Error> {
        let (version, peek_input) = peek_http_input(input, self.peek_timeout).await?;
        if version == Some(HttpPeekVersion::H2) {
            tracing::debug!("http peek: serve[h2]: http acceptor; version = {version:?}");
            self.http_acceptor
                .0
                .serve(peek_input)
                .await
                .into_box_error()
        } else {
            tracing::debug!("http peek: serve[h2]: fallback; version = {version:?}");
            self.fallback.serve(peek_input).await.into_box_error()
        }
    }
}

impl<PeekableInput, Output, T, U, F> Service<PeekableInput>
    for HttpPeekRouter<HttpDualAcceptor<T, U>, F>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin>,
    Output: Send + 'static,
    T: Service<
            PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
    U: Service<
            PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
    F: Service<
            PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
{
    type Output = Output;
    type Error = BoxError;

    async fn serve(&self, input: PeekableInput) -> Result<Self::Output, Self::Error> {
        let (version, peek_input) = peek_http_input(input, self.peek_timeout).await?;
        match version {
            Some(HttpPeekVersion::H2) => {
                tracing::trace!("http peek: serve[dual]: h2 acceptor; version = {version:?}");
                self.http_acceptor
                    .h2
                    .serve(peek_input)
                    .await
                    .into_box_error()
            }
            Some(HttpPeekVersion::Http1x) => {
                tracing::trace!("http peek: serve[dual]: http/1x acceptor; version = {version:?}");
                self.http_acceptor
                    .http1
                    .serve(peek_input)
                    .await
                    .into_box_error()
            }
            None => {
                tracing::trace!("http peek: serve[dual]: fallback; version = {version:?}");
                self.fallback.serve(peek_input).await.into_box_error()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpPeekVersion {
    Http1x,
    H2,
}

pub async fn peek_http_input<PeekableInput>(
    mut input: PeekableInput,
    timeout: Option<Duration>,
) -> Result<
    (
        Option<HttpPeekVersion>,
        PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
    ),
    BoxError,
>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin>,
{
    let mut peek_buf = [0u8; HTTP_HEADER_PEEK_LEN];

    let peek_deadline = timeout.map(|d| Instant::now() + d);
    let mut peek_filled = 0;

    let mut maybe_http_version = None;

    for _ in 0..8 {
        let read_fut = input.peek_io_mut().read(&mut peek_buf[peek_filled..]);

        let n = match peek_deadline {
            Some(deadline) => {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }

                let remaining = deadline - now;
                match tokio::time::timeout(remaining, read_fut).await {
                    Err(err) => {
                        tracing::debug!("http peek: time-fenced peek read timeout error: {err}");
                        0
                    }
                    Ok(Err(err)) => {
                        tracing::debug!("http peek: time-fenced peek read error: {err}");
                        0
                    }
                    Ok(Ok(n)) => n,
                }
            }
            None => match read_fut.await {
                Err(err) => {
                    tracing::debug!("http peek: peek read error: {err}");
                    0
                }
                Ok(n) => n,
            },
        };

        if n == 0 {
            tracing::trace!("http peek: break loop: no new data read...");
            break;
        }

        peek_filled = (peek_filled + n).min(peek_buf.len());

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

        if n == H2_MAGIC_PREFIX.len() && peek_buf.eq(H2_MAGIC_PREFIX) {
            maybe_http_version = Some(HttpPeekVersion::H2);
            break;
        } else if HTTP_METHODS
            .iter()
            .any(|method| peek_buf.starts_with(method))
        {
            maybe_http_version = Some(HttpPeekVersion::Http1x);
            break;
        }
    }

    tracing::trace!("http prefix read loop finished: version = {maybe_http_version:?}");

    let offset = HTTP_HEADER_PEEK_LEN - peek_filled;
    if offset > 0 {
        tracing::trace!(
            "move http peek buffer cursor due to reading not enough (read: {peek_filled})"
        );
        peek_buf.copy_within(0..peek_filled, offset);
    }

    let mut peek = StackReader::new(peek_buf);
    peek.skip(offset);

    let peek_input = input.map_peek_io(|io| PrefixedIo::new(peek, io));

    Ok((maybe_http_version, peek_input))
}

const H2_MAGIC_PREFIX: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HTTP_HEADER_PEEK_LEN: usize = H2_MAGIC_PREFIX.len();

/// [`PrefixedIo`] alias used by [`HttpPeekRouter`].
pub type HttpPrefixedIo<S> = PrefixedIo<StackReader<HTTP_HEADER_PEEK_LEN>, S>;

#[cfg(test)]
mod test {
    use rama_core::{
        ServiceInput,
        bytes::Bytes,
        futures::{StreamExt as _, async_stream::stream_fn},
        service::{RejectError, service_fn},
        stream::io::StreamReader,
    };
    use std::convert::Infallible;

    use rama_core::io::Io;

    use super::*;

    #[tokio::test]
    async fn test_peek_router() {
        let http_service = service_fn(async || Ok::<_, Infallible>("http"));
        let fallback_service = service_fn(async || Ok::<_, Infallible>("other"));

        let peek_http_svc = HttpPeekRouter::new(http_service).with_fallback(fallback_service);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!("http", response);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nfoo".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!("http", response);

        const HTTP_METHODS: &[&str] = &[
            "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE ", "PATCH ",
        ];
        for method in HTTP_METHODS {
            let response = peek_http_svc
                .serve(ServiceInput::new(std::io::Cursor::new(
                    format!("{method} /foobar HTTP/1.1").into_bytes(),
                )))
                .await
                .unwrap();
            assert_eq!("http", response);
        }

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foo".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foobar".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);
    }

    #[tokio::test]
    async fn test_peek_http1_connect() {
        for timeout in [Some(Duration::from_millis(500)), None] {
            let reader = StreamReader::new(
                stream_fn(async |mut yielder| {
                    yielder.yield_item(Bytes::from_static(b"CONN")).await;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    yielder.yield_item(Bytes::from_static(b"EC")).await;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    yielder
                        .yield_item(Bytes::from_static(b"T http://foobar.com"))
                        .await;
                })
                .map(Ok::<_, std::io::Error>),
            );
            let writer = tokio::io::sink();

            let io = Box::pin(tokio::io::join(reader, writer));

            let (http_version, _) = peek_http_input(io, timeout).await.unwrap();

            assert_eq!(Some(HttpPeekVersion::Http1x), http_version);
        }
    }

    #[tokio::test]
    async fn test_peek_http1_router() {
        let http_service = service_fn(async || Ok::<_, Infallible>("http1"));
        let fallback_service = service_fn(async || Ok::<_, Infallible>("other"));

        let peek_http_svc = HttpPeekRouter::new_http1(http_service).with_fallback(fallback_service);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nfoo".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!("other", response);

        const HTTP_METHODS: &[&str] = &[
            "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE ", "PATCH ",
        ];
        for method in HTTP_METHODS {
            let response = peek_http_svc
                .serve(ServiceInput::new(std::io::Cursor::new(
                    format!("{method} /foobar HTTP/1.1").into_bytes(),
                )))
                .await
                .unwrap();
            assert_eq!("http1", response);
        }

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foo".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foobar".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);
    }

    #[tokio::test]
    async fn test_peek_h2_router() {
        let http_service = service_fn(async || Ok::<_, Infallible>("h2"));
        let fallback_service = service_fn(async || Ok::<_, Infallible>("other"));

        let peek_http_svc = HttpPeekRouter::new_h2(http_service).with_fallback(fallback_service);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nfoo".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!("h2", response);

        const HTTP_METHODS: &[&str] = &[
            "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE ", "PATCH ",
        ];
        for method in HTTP_METHODS {
            let response = peek_http_svc
                .serve(ServiceInput::new(std::io::Cursor::new(
                    format!("{method} /foobar HTTP/1.1").into_bytes(),
                )))
                .await
                .unwrap();
            assert_eq!("other", response);
        }

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foo".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foobar".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);
    }

    #[tokio::test]
    async fn test_peek_dual_router() {
        let http1_service = service_fn(async || Ok::<_, Infallible>("http1"));
        let h2_service = service_fn(async || Ok::<_, Infallible>("h2"));
        let fallback_service = service_fn(async || Ok::<_, Infallible>("other"));

        let peek_http_svc =
            HttpPeekRouter::new_dual(http1_service, h2_service).with_fallback(fallback_service);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nfoo".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!("h2", response);

        const HTTP_METHODS: &[&str] = &[
            "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE ", "PATCH ",
        ];
        for method in HTTP_METHODS {
            let response = peek_http_svc
                .serve(ServiceInput::new(std::io::Cursor::new(
                    format!("{method} /foobar HTTP/1.1").into_bytes(),
                )))
                .await
                .unwrap();
            assert_eq!("http1", response);
        }

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foo".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foobar".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);
    }

    #[tokio::test]
    async fn test_peek_router_read_eof() {
        const CONTENT: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nfoobar";

        async fn http_service_fn(mut stream: impl Io + Unpin) -> Result<&'static str, BoxError> {
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
            .serve(ServiceInput::new(std::io::Cursor::new(CONTENT.to_vec())))
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

            async fn other_service_fn(mut stream: impl Io + Unpin) -> Result<Vec<u8>, BoxError> {
                let mut v = Vec::default();
                let _ = stream.read_to_end(&mut v).await?;
                Ok(v)
            }
            let other_service = service_fn(other_service_fn);

            let peek_http_svc = HttpPeekRouter::new(http_service).with_fallback(other_service);

            let response = peek_http_svc
                .serve(ServiceInput::new(std::io::Cursor::new(
                    content.as_bytes().to_vec(),
                )))
                .await
                .unwrap();

            assert_eq!(content.as_bytes(), &response[..]);
        }
    }
}
