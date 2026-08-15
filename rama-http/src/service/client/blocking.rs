//! Blocking HTTP client boundary.
//!
//! [`Client::try_new`] creates and owns a dedicated runtime thread. Cloning the
//! client shares both the asynchronous service and that runtime.

use super::ext::{
    BlockingRequestBuilder, RequestBuilder, RequestBuilderState, request_builder_mode,
    request_builder_state,
};
use crate::{Body as HttpBody, Method, Request, Response as HttpResponse, StreamingBody};
use rama_core::{
    BlockingService,
    bytes::Bytes,
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    extensions::Extensions,
    futures::TryStreamExt as _,
    rt::blocking::{Guarded, Io as BlockingIo, Runtime},
    stream::io::StreamReader,
};
use std::{fmt, io, pin::Pin, sync::Arc, time::Duration};
use tokio::io::AsyncRead;

use super::ext::IntoUrl;

/// A cloneable blocking boundary around an asynchronous HTTP service.
pub struct Client<S> {
    service: rama_core::rt::blocking::Service<S>,
}

impl<S> Client<S> {
    /// Create a client with its own dedicated runtime thread.
    pub fn try_new(service: S) -> io::Result<Self> {
        let runtime = Runtime::builder()
            .thread_name("rama-http-blocking-runtime")
            .try_build()?;
        Ok(Self::with_runtime(service, &runtime))
    }

    /// Create a client using an explicitly supplied runtime.
    #[must_use]
    pub fn with_runtime(service: S, runtime: &Runtime) -> Self {
        Self {
            service: runtime.service(service),
        }
    }

    /// Borrow the asynchronous HTTP service.
    #[must_use]
    pub fn get_ref(&self) -> &S {
        self.service.get_ref()
    }

    /// Clone the shared asynchronous HTTP service.
    #[must_use]
    pub fn clone_service(&self) -> Arc<S> {
        self.service.clone_inner()
    }

    /// Borrow the blocking runtime.
    #[must_use]
    pub fn runtime(&self) -> &Runtime {
        self.service.runtime()
    }

    /// Start building a `GET` request.
    pub fn get<B>(&self, url: impl IntoUrl) -> BlockingRequestBuilder<'_, Self, HttpResponse<B>>
    where
        S: rama_core::Service<Request, Output = HttpResponse<B>>,
    {
        self.request(Method::GET, url)
    }

    /// Start building a `POST` request.
    pub fn post<B>(&self, url: impl IntoUrl) -> BlockingRequestBuilder<'_, Self, HttpResponse<B>>
    where
        S: rama_core::Service<Request, Output = HttpResponse<B>>,
    {
        self.request(Method::POST, url)
    }

    /// Start building a `PUT` request.
    pub fn put<B>(&self, url: impl IntoUrl) -> BlockingRequestBuilder<'_, Self, HttpResponse<B>>
    where
        S: rama_core::Service<Request, Output = HttpResponse<B>>,
    {
        self.request(Method::PUT, url)
    }

    /// Start building a `PATCH` request.
    pub fn patch<B>(&self, url: impl IntoUrl) -> BlockingRequestBuilder<'_, Self, HttpResponse<B>>
    where
        S: rama_core::Service<Request, Output = HttpResponse<B>>,
    {
        self.request(Method::PATCH, url)
    }

    /// Start building a `DELETE` request.
    pub fn delete<B>(&self, url: impl IntoUrl) -> BlockingRequestBuilder<'_, Self, HttpResponse<B>>
    where
        S: rama_core::Service<Request, Output = HttpResponse<B>>,
    {
        self.request(Method::DELETE, url)
    }

    /// Start building a `HEAD` request.
    pub fn head<B>(&self, url: impl IntoUrl) -> BlockingRequestBuilder<'_, Self, HttpResponse<B>>
    where
        S: rama_core::Service<Request, Output = HttpResponse<B>>,
    {
        self.request(Method::HEAD, url)
    }

    /// Start building a `CONNECT` request.
    pub fn connect<B>(&self, url: impl IntoUrl) -> BlockingRequestBuilder<'_, Self, HttpResponse<B>>
    where
        S: rama_core::Service<Request, Output = HttpResponse<B>>,
    {
        self.request(Method::CONNECT, url)
    }

    /// Start building a request.
    pub fn request<B>(
        &self,
        method: Method,
        url: impl IntoUrl,
    ) -> BlockingRequestBuilder<'_, Self, HttpResponse<B>>
    where
        S: rama_core::Service<Request, Output = HttpResponse<B>>,
    {
        RequestBuilder::from_state(self, request_builder_state(method, url))
    }

    /// Start with an existing request.
    pub fn build_from_request<B, RequestBody>(
        &self,
        request: Request<RequestBody>,
    ) -> BlockingRequestBuilder<'_, Self, HttpResponse<B>>
    where
        S: rama_core::Service<Request, Output = HttpResponse<B>>,
        RequestBody: Into<HttpBody>,
    {
        RequestBuilder::from_state(self, RequestBuilderState::PostBody(request.map(Into::into)))
    }

    /// Execute a request, blocking until response headers are available.
    pub fn execute<B>(&self, request: Request) -> Result<Response, BoxError>
    where
        S: rama_core::Service<Request, Output = HttpResponse<B>, Error: Into<BoxError>>,
        B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + 'static,
    {
        let uri = request.uri().clone();
        let response = self.service.serve(request).map_err(|err| {
            let err: BoxError = err.into();
            err.context(uri)
        })?;
        Ok(Response::from_guarded(response))
    }

    fn execute_with_timeout<B>(
        &self,
        request: Request,
        timeout: Duration,
    ) -> Result<Response, BoxError>
    where
        S: rama_core::Service<Request, Output = HttpResponse<B>, Error: Into<BoxError>>,
        B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + 'static,
    {
        let uri = request.uri().clone();
        let service = self.service.clone_inner();
        let result = self.service.runtime().block_on_task(async move {
            tokio::time::timeout(timeout, service.serve(request)).await
        });

        let response = match result {
            Ok(Ok(response)) => response,
            Ok(Err(err)) => {
                let err: BoxError = err.into();
                return Err(err.context(uri));
            }
            Err(err) => {
                return Err(err
                    .context("roundtrip timeout reached")
                    .context_debug_field("timeout", timeout));
            }
        };

        Ok(Response::from_guarded(Guarded::new(
            response,
            self.service.runtime().clone(),
        )))
    }
}

impl<S> Clone for Client<S> {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
        }
    }
}

impl<S> fmt::Debug for Client<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("service", self.get_ref())
            .field("runtime", self.runtime())
            .finish()
    }
}

impl<S, B> BlockingService<Request> for Client<S>
where
    S: rama_core::Service<Request, Output = HttpResponse<B>, Error: Into<BoxError>>,
    B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + 'static,
{
    type Output = Response;
    type Error = BoxError;

    fn serve(&self, input: Request) -> Result<Self::Output, Self::Error> {
        self.execute(input)
    }
}

impl<S, B> RequestBuilder<'_, Client<S>, HttpResponse<B>, request_builder_mode::Blocking>
where
    S: rama_core::Service<Request, Output = HttpResponse<B>, Error: Into<BoxError>>,
    B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + 'static,
{
    /// Construct the request without sending it.
    pub fn try_into_request(self) -> Result<Request, BoxError> {
        self.build()
    }

    /// Construct and send the request, blocking until response headers arrive.
    pub fn send(self) -> Result<Response, BoxError> {
        let client = self.http_client_service;
        client.execute(self.build()?)
    }

    /// Construct and send the request with a response-header timeout.
    ///
    /// The timeout does not include reading the response body.
    pub fn send_with_timeout(self, timeout: Duration) -> Result<Response, BoxError> {
        let client = self.http_client_service;
        client.execute_with_timeout(self.build()?, timeout)
    }
}

type AsyncBodyReader = Pin<Box<dyn AsyncRead + Send + 'static>>;

/// A blocking HTTP response body.
pub struct Body {
    inner: BlockingIo<AsyncBodyReader>,
}

impl Body {
    fn new<B>(body: B, runtime: &Runtime) -> Self
    where
        B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + 'static,
    {
        let stream = crate::body::util::BodyDataStream::new(body)
            .map_err(|err| io::Error::other(err.into()));
        let reader: AsyncBodyReader = Box::pin(StreamReader::new(stream));
        Self {
            inner: runtime.io(reader),
        }
    }

    /// Borrow the runtime keeping this body live.
    #[must_use]
    pub fn runtime(&self) -> &Runtime {
        self.inner.runtime()
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Body").finish_non_exhaustive()
    }
}

impl io::Read for Body {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

/// An HTTP response with a blocking body reader and an attached runtime lease.
#[derive(Debug)]
pub struct Response {
    parts: crate::response::Parts,
    body: Body,
}

impl Response {
    fn from_guarded<B>(response: Guarded<HttpResponse<B>>) -> Self
    where
        B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + 'static,
    {
        let (response, runtime) = response.into_parts();
        let (parts, body) = response.into_parts();
        Self {
            parts,
            body: Body::new(body, &runtime),
        }
    }

    /// Return the HTTP status.
    #[must_use]
    pub fn status(&self) -> crate::StatusCode {
        self.parts.status
    }

    /// Return the HTTP version.
    #[must_use]
    pub fn version(&self) -> crate::Version {
        self.parts.version
    }

    /// Borrow the response headers.
    #[must_use]
    pub fn headers(&self) -> &crate::HeaderMap {
        &self.parts.headers
    }

    /// Mutably borrow the response headers.
    pub fn headers_mut(&mut self) -> &mut crate::HeaderMap {
        &mut self.parts.headers
    }

    /// Borrow the response extensions.
    #[must_use]
    pub fn extensions(&self) -> &Extensions {
        &self.parts.extensions
    }

    /// Mutably borrow the response extensions.
    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.parts.extensions
    }

    /// Borrow the blocking response body.
    #[must_use]
    pub fn body(&self) -> &Body {
        &self.body
    }

    /// Mutably borrow the blocking response body.
    pub fn body_mut(&mut self) -> &mut Body {
        &mut self.body
    }

    /// Consume the response and return its body.
    #[must_use]
    pub fn into_body(self) -> Body {
        self.body
    }

    /// Consume the response and return its head and body.
    #[must_use]
    pub fn into_parts(self) -> (crate::response::Parts, Body) {
        (self.parts, self.body)
    }

    /// Read the complete body as bytes.
    pub fn try_into_bytes(mut self) -> Result<Bytes, BoxError> {
        use io::Read as _;

        let mut bytes = Vec::new();
        self.read_to_end(&mut bytes)
            .context("read HTTP response body")?;
        Ok(bytes.into())
    }

    /// Read the complete body as UTF-8 text.
    pub fn try_into_string(mut self) -> Result<String, BoxError> {
        use io::Read as _;

        let mut text = String::new();
        self.read_to_string(&mut text)
            .context("read HTTP response body as UTF-8")?;
        Ok(text)
    }

    /// Buffer and deserialize the complete body as JSON.
    pub fn try_into_json<T>(self) -> Result<T, BoxError>
    where
        T: serde::de::DeserializeOwned,
    {
        let bytes = self.try_into_bytes()?;
        serde_json::from_slice(bytes.as_ref()).context("deserialize HTTP response body as JSON")
    }

    /// Deserialize JSON directly from the streaming body reader.
    pub fn try_into_json_streaming<T>(mut self) -> Result<T, BoxError>
    where
        T: serde::de::DeserializeOwned,
    {
        serde_json::from_reader(&mut self)
            .context("streaming-deserialize HTTP response body as JSON")
    }

    /// Copy the response body into a blocking writer.
    pub fn copy_to<W>(&mut self, writer: &mut W) -> Result<u64, BoxError>
    where
        W: io::Write + ?Sized,
    {
        io::copy(self, writer).context("copy HTTP response body")
    }
}

impl io::Read for Response {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.body.read(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::{error::BoxError, service::service_fn};
    use rama_http_types::BodyExtractExt as _;

    #[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
    struct Message {
        value: String,
    }

    #[test]
    fn client_owns_runtime_is_cloneable_and_reuses_request_builder() {
        let client = Client::try_new(service_fn(|request: Request| async move {
            let payload: Message = request.try_into_json().await?;
            let body = serde_json::to_vec(&payload)?;
            Ok::<_, BoxError>(HttpResponse::new(HttpBody::from(body)))
        }))
        .unwrap();
        let cloned = client.clone();
        drop(client);

        let response = cloned
            .post("https://example.test/messages")
            .header("x-rama", "blocking")
            .json(&Message {
                value: "hello".to_owned(),
            })
            .send()
            .unwrap();

        assert_eq!(response.status(), crate::StatusCode::OK);
        assert_eq!(
            response.try_into_json::<Message>().unwrap(),
            Message {
                value: "hello".to_owned()
            }
        );
    }

    #[test]
    fn response_implements_read() {
        let client = Client::try_new(service_fn(|_: Request| async {
            Ok::<_, BoxError>(HttpResponse::new(HttpBody::from("hello")))
        }))
        .unwrap();

        let mut response = client.get("http://example.test").send().unwrap();
        let mut text = String::new();
        io::Read::read_to_string(&mut response, &mut text).unwrap();
        assert_eq!(text, "hello");
    }

    #[test]
    fn response_body_keeps_runtime_alive_after_client_drop() {
        let client = Client::try_new(service_fn(|_: Request| async {
            let body = HttpBody::from_stream(rama_core::futures::stream::once(async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok::<_, core::convert::Infallible>(Bytes::from_static(b"still alive"))
            }));
            Ok::<_, BoxError>(HttpResponse::new(body))
        }))
        .unwrap();

        let response = client.get("http://example.test").send().unwrap();
        drop(client);
        assert_eq!(response.try_into_string().unwrap(), "still alive");
    }

    #[cfg(feature = "dial9")]
    #[test]
    fn client_request_runs_inside_dial9_session() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = rama_core::telemetry::dial9::Dial9Config::builder()
            .enabled(true)
            .base_path(temp_dir.path().join("blocking-http.bin"))
            .max_file_size(1024 * 1024)
            .max_total_size(4 * 1024 * 1024)
            .build()
            .unwrap();
        let runtime = Runtime::builder()
            .with_dial9_config(config)
            .try_build()
            .unwrap();
        let client = Client::with_runtime(
            service_fn(|_: Request| async {
                assert!(
                    rama_core::telemetry::dial9::telemetry::TelemetryHandle::current().is_enabled()
                );
                Ok::<_, BoxError>(HttpResponse::new(HttpBody::from("tracked")))
            }),
            &runtime,
        );

        assert_eq!(
            client
                .get("https://example.test")
                .send()
                .unwrap()
                .try_into_string()
                .unwrap(),
            "tracked"
        );
        assert_eq!(
            client
                .get("https://example.test/timeout")
                .send_with_timeout(Duration::from_secs(1))
                .unwrap()
                .try_into_string()
                .unwrap(),
            "tracked"
        );
    }
}
