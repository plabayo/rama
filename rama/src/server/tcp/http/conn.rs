use std::error::Error as StdError;

use hyper::server::conn::http1::Builder as Http1Builder;
use hyper::server::conn::http2::Builder as Http2Builder;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as AutoBuilder;

use crate::net::TcpStream;

type H2Executor = hyper_util::rt::TokioExecutor;

use crate::service::{
    http::ServiceBuilderExt,
    hyper::{HyperBody, TowerHyperServiceExt},
    util::Identity,
    BoxError, Layer, Service, ServiceBuilder,
};

pub type ServeResult = Result<(), BoxError>;

pub use crate::net::http::Response;
pub type Request = crate::net::http::Request<HyperBody>;

#[derive(Debug)]
pub struct HttpConnector<B, S, L> {
    builder: B,
    stream: TcpStream<S>,
    service_builder: ServiceBuilder<L>,
}

impl<B, S, L> Clone for HttpConnector<B, S, L>
where
    B: Clone,
    S: Clone,
    L: Clone,
{
    fn clone(&self) -> Self {
        Self {
            builder: self.builder.clone(),
            stream: self.stream.clone(),
            service_builder: self.service_builder.clone(),
        }
    }
}

impl<S> HttpConnector<Http1Builder, S, Identity>
where
    S: crate::stream::Stream + Send + 'static,
{
    pub fn http1(stream: TcpStream<S>) -> Self {
        Self {
            builder: Http1Builder::new(),
            stream,
            service_builder: ServiceBuilder::new(),
        }
    }
}

impl<S> HttpConnector<Http2Builder<H2Executor>, S, Identity>
where
    S: crate::stream::Stream + Send + 'static,
{
    pub fn h2(stream: TcpStream<S>) -> Self {
        Self {
            builder: Http2Builder::new(H2Executor::new()),
            stream,
            service_builder: ServiceBuilder::new(),
        }
    }
}

impl<S> HttpConnector<AutoBuilder<H2Executor>, S, Identity>
where
    S: crate::stream::Stream + Send + 'static,
{
    pub fn auto(stream: TcpStream<S>) -> Self {
        Self {
            builder: AutoBuilder::new(H2Executor::new()),
            stream,
            service_builder: ServiceBuilder::new(),
        }
    }
}

impl<B, S, L> HttpConnector<B, S, L> {
    /// Fail requests that take longer than `timeout`.
    pub fn timeout(
        self,
        timeout: std::time::Duration,
    ) -> HttpConnector<B, S, crate::service::util::Stack<crate::service::timeout::TimeoutLayer, L>>
    {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.timeout(timeout),
        }
    }
    // Conditionally reject requests based on `predicate`.
    ///
    /// `predicate` must implement the [`Predicate`] trait.
    ///
    /// This wraps the inner service with an instance of the [`Filter`]
    /// middleware.
    ///
    /// [`Filter`]: crate::service::filter::Filter
    /// [`Predicate`]: crate::service::filter::Predicate
    pub fn filter<P>(
        self,
        predicate: P,
    ) -> HttpConnector<B, S, crate::service::util::Stack<crate::service::filter::FilterLayer<P>, L>>
    {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.filter(predicate),
        }
    }

    /// Conditionally reject requests based on an asynchronous `predicate`.
    ///
    /// `predicate` must implement the [`AsyncPredicate`] trait.
    ///
    /// This wraps the inner service with an instance of the [`AsyncFilter`]
    /// middleware.
    ///
    /// [`AsyncFilter`]: crate::service::filter::AsyncFilter
    /// [`AsyncPredicate`]: crate::service::filter::AsyncPredicate
    pub fn filter_async<P>(
        self,
        predicate: P,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<crate::service::filter::AsyncFilterLayer<P>, L>,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.filter_async(predicate),
        }
    }
}

impl<B, S, L> HttpConnector<B, S, L> {
    /// Propagate a header from the request to the response.
    ///
    /// See [`tower_async_http::propagate_header`] for more details.
    ///
    /// [`tower_async_http::propagate_header`]: crate::service::http::propagate_header
    pub fn propagate_header(
        self,
        header: crate::net::http::HeaderName,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<
            crate::service::http::propagate_header::PropagateHeaderLayer,
            L,
        >,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.propagate_header(header),
        }
    }

    /// Add some shareable value to [request extensions].
    ///
    /// See [`tower_async_http::add_extension`] for more details.
    ///
    /// [`tower_async_http::add_extension`]: crate::service::http::add_extension
    /// [request extensions]: https://docs.rs/http/latest/http/struct.Extensions.html
    pub fn add_extension<T>(
        self,
        value: T,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<crate::service::http::add_extension::AddExtensionLayer<T>, L>,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.add_extension(value),
        }
    }

    /// Apply a transformation to the request body.
    ///
    /// See [`tower_async_http::map_request_body`] for more details.
    ///
    /// [`tower_async_http::map_request_body`]: crate::service::http::map_request_body
    pub fn map_request_body<F>(
        self,
        f: F,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<
            crate::service::http::map_request_body::MapRequestBodyLayer<F>,
            L,
        >,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.map_request_body(f),
        }
    }

    /// Apply a transformation to the response body.
    ///
    /// See [`tower_async_http::map_response_body`] for more details.
    ///
    /// [`tower_async_http::map_response_body`]: crate::service::http::map_response_body
    pub fn map_response_body<F>(
        self,
        f: F,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<
            crate::service::http::map_response_body::MapResponseBodyLayer<F>,
            L,
        >,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.map_response_body(f),
        }
    }

    /// Compresses response bodies.
    ///
    /// See [`tower_async_http::compression`] for more details.
    ///
    /// [`tower_async_http::compression`]: crate::service::http::compression
    pub fn compression(
        self,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<crate::service::http::compression::CompressionLayer, L>,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.compression(),
        }
    }

    /// Decompress response bodies.
    ///
    /// See [`tower_async_http::decompression`] for more details.
    ///
    /// [`tower_async_http::decompression`]: crate::service::http::decompression
    pub fn decompression(
        self,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<crate::service::http::decompression::DecompressionLayer, L>,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.decompression(),
        }
    }

    /// High level tracing that classifies responses using HTTP status codes.
    ///
    /// This method does not support customizing the output, to do that use [`TraceLayer`]
    /// instead.
    ///
    /// See [`tower_http::trace`] for more details.
    ///
    /// [`tower_http::trace`]: crate::service::http::trace
    /// [`TraceLayer`]: crate::service::http::trace::TraceLayer
    pub fn trace(
        self,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<
            crate::service::http::trace::TraceLayer<
                crate::service::http::classify::SharedClassifier<
                    crate::service::http::classify::ServerErrorsAsFailures,
                >,
            >,
            L,
        >,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.trace_for_http(),
        }
    }

    /// High level tracing that classifies responses using HTTP status codes.
    ///
    /// This method does not support customizing the output, to do that use [`TraceLayer`]
    /// instead.
    ///
    /// See [`tower_http::trace`] for more details.
    ///
    /// [`tower_http::trace`]: crate::service::http::trace
    /// [`TraceLayer`]: crate::service::http::trace::TraceLayer
    #[allow(clippy::type_complexity)]
    pub fn trace_layer<M, MakeSpan, OnRequest, OnResponse, OnBodyChunk, OnEos, OnFailure>(
        self,
        layer: crate::service::http::trace::TraceLayer<
            M,
            MakeSpan,
            OnRequest,
            OnResponse,
            OnBodyChunk,
            OnEos,
            OnFailure,
        >,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<
            crate::service::http::trace::TraceLayer<
                M,
                MakeSpan,
                OnRequest,
                OnResponse,
                OnBodyChunk,
                OnEos,
                OnFailure,
            >,
            L,
        >,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.layer(layer),
        }
    }

    /// Follow redirect responses using the [`Standard`] policy.
    ///
    /// See [`tower_async_http::follow_redirect`] for more details.
    ///
    /// [`tower_async_http::follow_redirect`]: crate::service::http::follow_redirect
    /// [`Standard`]: crate::service::http::follow_redirect::policy::Standard
    pub fn follow_redirects(
        self,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<
            crate::service::http::follow_redirect::FollowRedirectLayer<
                crate::service::http::follow_redirect::policy::Standard,
            >,
            L,
        >,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.follow_redirects(),
        }
    }

    /// Mark headers as [sensitive] on both requests and responses.
    ///
    /// See [`tower_async_http::sensitive_headers`] for more details.
    ///
    /// [sensitive]: https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.set_sensitive
    /// [`tower_async_http::sensitive_headers`]: crate::service::http::sensitive_headers
    pub fn sensitive_headers<I>(
        self,
        headers: I,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<
            crate::service::http::sensitive_headers::SetSensitiveHeadersLayer,
            L,
        >,
    >
    where
        I: IntoIterator<Item = crate::net::http::HeaderName>,
    {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.sensitive_headers(headers),
        }
    }

    /// Mark headers as [sensitive] on both requests.
    ///
    /// See [`tower_async_http::sensitive_headers`] for more details.
    ///
    /// [sensitive]: https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.set_sensitive
    /// [`tower_async_http::sensitive_headers`]: crate::service::http::sensitive_headers
    pub fn sensitive_request_headers(
        self,
        headers: std::sync::Arc<[crate::net::http::HeaderName]>,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<
            crate::service::http::sensitive_headers::SetSensitiveRequestHeadersLayer,
            L,
        >,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.sensitive_request_headers(headers),
        }
    }

    /// Mark headers as [sensitive] on both responses.
    ///
    /// See [`tower_async_http::sensitive_headers`] for more details.
    ///
    /// [sensitive]: https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.set_sensitive
    /// [`tower_async_http::sensitive_headers`]: crate::service::http::sensitive_headers
    pub fn sensitive_response_headers(
        self,
        headers: std::sync::Arc<[crate::net::http::HeaderName]>,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<
            crate::service::http::sensitive_headers::SetSensitiveResponseHeadersLayer,
            L,
        >,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.sensitive_response_headers(headers),
        }
    }

    /// Insert a header into the request.
    ///
    /// If a previous value exists for the same header, it is removed and replaced with the new
    /// header value.
    ///
    /// See [`tower_async_http::set_header`] for more details.
    ///
    /// [`tower_async_http::set_header`]: crate::service::http::set_header
    pub fn override_request_header<M>(
        self,
        header_name: crate::net::http::HeaderName,
        make: M,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<crate::service::http::set_header::SetRequestHeaderLayer<M>, L>,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self
                .service_builder
                .override_request_header(header_name, make),
        }
    }

    /// Append a header into the request.
    ///
    /// If previous values exist, the header will have multiple values.
    ///
    /// See [`tower_async_http::set_header`] for more details.
    ///
    /// [`tower_async_http::set_header`]: crate::service::http::set_header
    pub fn append_request_header<M>(
        self,
        header_name: crate::net::http::HeaderName,
        make: M,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<crate::service::http::set_header::SetRequestHeaderLayer<M>, L>,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self
                .service_builder
                .append_request_header(header_name, make),
        }
    }

    /// Insert a header into the request, if the header is not already present.
    ///
    /// See [`tower_async_http::set_header`] for more details.
    ///
    /// [`tower_async_http::set_header`]: crate::service::http::set_header
    pub fn insert_request_header_if_not_present<M>(
        self,
        header_name: crate::net::http::HeaderName,
        make: M,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<crate::service::http::set_header::SetRequestHeaderLayer<M>, L>,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self
                .service_builder
                .insert_request_header_if_not_present(header_name, make),
        }
    }

    /// Insert a header into the response.
    ///
    /// If a previous value exists for the same header, it is removed and replaced with the new
    /// header value.
    ///
    /// See [`tower_async_http::set_header`] for more details.
    ///
    /// [`tower_async_http::set_header`]: crate::service::http::set_header
    pub fn override_response_header<M>(
        self,
        header_name: crate::net::http::HeaderName,
        make: M,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<crate::service::http::set_header::SetResponseHeaderLayer<M>, L>,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self
                .service_builder
                .override_response_header(header_name, make),
        }
    }

    /// Append a header into the response.
    ///
    /// If previous values exist, the header will have multiple values.
    ///
    /// See [`tower_async_http::set_header`] for more details.
    ///
    /// [`tower_async_http::set_header`]: crate::service::http::set_header
    pub fn append_response_header<M>(
        self,
        header_name: crate::net::http::HeaderName,
        make: M,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<crate::service::http::set_header::SetResponseHeaderLayer<M>, L>,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self
                .service_builder
                .append_response_header(header_name, make),
        }
    }

    /// Insert a header into the response, if the header is not already present.
    ///
    /// See [`tower_async_http::set_header`] for more details.
    ///
    /// [`tower_async_http::set_header`]: crate::service::http::set_header
    pub fn insert_response_header_if_not_present<M>(
        self,
        header_name: crate::net::http::HeaderName,
        make: M,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<crate::service::http::set_header::SetResponseHeaderLayer<M>, L>,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self
                .service_builder
                .insert_response_header_if_not_present(header_name, make),
        }
    }

    /// Add request id header and extension.
    ///
    /// See [`tower_async_http::request_id`] for more details.
    ///
    /// [`tower_async_http::request_id`]: crate::service::http::request_id
    pub fn set_request_id<M>(
        self,
        header_name: crate::net::http::HeaderName,
        make_request_id: M,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<crate::service::http::request_id::SetRequestIdLayer<M>, L>,
    >
    where
        M: crate::service::http::request_id::MakeRequestId,
    {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self
                .service_builder
                .set_request_id(header_name, make_request_id),
        }
    }

    /// Add request id header and extension, using `x-request-id` as the header name.
    ///
    /// See [`tower_async_http::request_id`] for more details.
    ///
    /// [`tower_async_http::request_id`]: crate::service::http::request_id
    pub fn set_x_request_id<M>(
        self,
        make_request_id: M,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<crate::service::http::request_id::SetRequestIdLayer<M>, L>,
    >
    where
        M: crate::service::http::request_id::MakeRequestId,
    {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.set_x_request_id(make_request_id),
        }
    }

    /// Propgate request ids from requests to responses.
    ///
    /// See [`tower_async_http::request_id`] for more details.
    ///
    /// [`tower_async_http::request_id`]: crate::service::http::request_id
    pub fn propagate_request_id(
        self,
        header_name: crate::net::http::HeaderName,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<crate::service::http::request_id::PropagateRequestIdLayer, L>,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.propagate_request_id(header_name),
        }
    }

    /// Propgate request ids from requests to responses, using `x-request-id` as the header name.
    ///
    /// See [`tower_async_http::request_id`] for more details.
    ///
    /// [`tower_async_http::request_id`]: crate::service::http::request_id
    pub fn propagate_x_request_id(
        self,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<crate::service::http::request_id::PropagateRequestIdLayer, L>,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.propagate_x_request_id(),
        }
    }

    /// Catch panics and convert them into `500 Internal Server` responses.
    ///
    /// See [`tower_async_http::catch_panic`] for more details.
    ///
    /// [`tower_async_http::catch_panic`]: crate::service::http::catch_panic
    pub fn catch_panic(
        self,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<
            crate::service::http::catch_panic::CatchPanicLayer<
                crate::service::http::catch_panic::DefaultResponseForPanic,
            >,
            L,
        >,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.catch_panic(),
        }
    }

    /// Intercept requests with over-sized payloads and convert them into
    /// `413 Payload Too Large` responses.
    ///
    /// See [`tower_async_http::limit`] for more details.
    ///
    /// [`tower_async_http::limit`]: crate::service::http::limit
    pub fn request_body_limit(
        self,
        limit: usize,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<crate::service::http::limit::RequestBodyLimitLayer, L>,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.request_body_limit(limit),
        }
    }

    /// Remove trailing slashes from paths.
    ///
    /// See [`tower_async_http::normalize_path`] for more details.
    ///
    /// [`tower_async_http::normalize_path`]: crate::service::http::normalize_path
    pub fn trim_trailing_slash(
        self,
    ) -> HttpConnector<
        B,
        S,
        crate::service::util::Stack<crate::service::http::normalize_path::NormalizePathLayer, L>,
    > {
        HttpConnector {
            builder: self.builder,
            stream: self.stream,
            service_builder: self.service_builder.trim_trailing_slash(),
        }
    }
}

impl<B, S, L> HttpConnector<B, S, L>
where
    B: HyperConnServer,
    S: crate::stream::Stream + Send + 'static,
{
    pub async fn serve<TowerService, ResponseBody, D, E>(self, service: TowerService) -> ServeResult
    where
        L: Layer<TowerService>,
        L::Service: Service<Request, Response = Response<ResponseBody>, call(): Send>
            + Send
            + Sync
            + 'static,
        <L::Service as Service<Request>>::Error: Into<BoxError>,
        TowerService: Service<Request, call(): Send> + Send + Sync + 'static,
        TowerService::Error: Into<BoxError>,
        ResponseBody: http_body::Body<Data = D, Error = E> + Send + 'static,
        D: Send,
        E: Into<BoxError>,
    {
        let service = self.service_builder.service(service);
        let service = ServiceBuilder::new()
            .map_request_body(HyperBody::from)
            .service(service)
            .into_hyper_service();

        self.builder
            .hyper_serve_connection(self.stream, service)
            .await
    }
}

impl<B, S, L> HttpConnector<B, S, L>
where
    B: HyperConnWithUpgradesServer,
    S: crate::stream::Stream + Send + 'static,
{
    pub async fn serve_with_upgrades<TowerService, ResponseBody, D, E>(
        self,
        service: TowerService,
    ) -> ServeResult
    where
        L: Layer<TowerService>,
        L::Service: Service<Request, Response = Response<ResponseBody>, call(): Send>
            + Send
            + Sync
            + 'static,
        <L::Service as Service<Request>>::Error: Into<BoxError>,
        TowerService: Service<Request, call(): Send> + Send + Sync + 'static,
        TowerService::Error: Into<BoxError>,
        ResponseBody: http_body::Body<Data = D, Error = E> + Send + 'static,
        D: Send,
        E: Into<BoxError>,
    {
        let service = self.service_builder.service(service);
        let service = ServiceBuilder::new()
            .map_request_body(HyperBody::from)
            .service(service)
            .into_hyper_service();

        self.builder
            .hyper_serve_connection_with_upgrades(self.stream, service)
            .await
    }
}

pub trait HyperConnServer {
    fn hyper_serve_connection<S, Service, Body>(
        &self,
        io: TcpStream<S>,
        service: Service,
    ) -> impl std::future::Future<Output = ServeResult>
    where
        S: crate::stream::Stream + Send + 'static,
        Service: hyper::service::Service<
                crate::net::http::Request<hyper::body::Incoming>,
                Response = Response<Body>,
            > + Send
            + Sync
            + 'static,
        Service::Future: Send + 'static,
        Service::Error: Into<Box<dyn StdError + Send + Sync>>,
        Body: http_body::Body + Send + 'static,
        Body::Data: Send,
        Body::Error: Into<Box<dyn StdError + Send + Sync>>;
}

pub trait HyperConnWithUpgradesServer {
    fn hyper_serve_connection_with_upgrades<S, Service, Body>(
        &self,
        io: TcpStream<S>,
        service: Service,
    ) -> impl std::future::Future<Output = ServeResult>
    where
        S: crate::stream::Stream + Send + 'static,
        Service: hyper::service::Service<
                crate::net::http::Request<hyper::body::Incoming>,
                Response = Response<Body>,
            > + Send
            + Sync
            + 'static,
        Service::Future: Send + 'static,
        Service::Error: Into<Box<dyn StdError + Send + Sync>>,
        Body: http_body::Body + Send + 'static,
        Body::Data: Send,
        Body::Error: Into<Box<dyn StdError + Send + Sync>>;
}

impl HyperConnServer for Http1Builder {
    #[inline]
    async fn hyper_serve_connection<S, Service, Body>(
        &self,
        io: TcpStream<S>,
        service: Service,
    ) -> ServeResult
    where
        S: crate::stream::Stream + Send + 'static,
        Service: hyper::service::Service<
                crate::net::http::Request<hyper::body::Incoming>,
                Response = Response<Body>,
            > + Send
            + Sync
            + 'static,
        Service::Future: Send + 'static,
        Service::Error: Into<Box<dyn StdError + Send + Sync>>,
        Body: http_body::Body + Send + 'static,
        Body::Data: Send,
        Body::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        let io = Box::pin(io);
        let stream = TokioIo::new(io);
        self.serve_connection(stream, service).await?;
        Ok(())
    }
}

impl HyperConnWithUpgradesServer for Http1Builder {
    #[inline]
    async fn hyper_serve_connection_with_upgrades<S, Service, Body>(
        &self,
        io: TcpStream<S>,
        service: Service,
    ) -> ServeResult
    where
        S: crate::stream::Stream + Send + 'static,
        Service: hyper::service::Service<
                crate::net::http::Request<hyper::body::Incoming>,
                Response = Response<Body>,
            > + Send
            + Sync
            + 'static,
        Service::Future: Send + 'static,
        Service::Error: Into<Box<dyn StdError + Send + Sync>>,
        Body: http_body::Body + Send + 'static,
        Body::Data: Send,
        Body::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        let io = Box::pin(io);
        let stream = TokioIo::new(io);
        self.serve_connection(stream, service)
            .with_upgrades()
            .await?;
        Ok(())
    }
}

impl HyperConnServer for Http2Builder<H2Executor> {
    #[inline]
    async fn hyper_serve_connection<S, Service, Body>(
        &self,
        io: TcpStream<S>,
        service: Service,
    ) -> ServeResult
    where
        S: crate::stream::Stream + Send + 'static,
        Service: hyper::service::Service<
                crate::net::http::Request<hyper::body::Incoming>,
                Response = Response<Body>,
            > + Send
            + Sync
            + 'static,
        Service::Future: Send + 'static,
        Service::Error: Into<Box<dyn StdError + Send + Sync>>,
        Body: http_body::Body + Send + 'static,
        Body::Data: Send,
        Body::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        let io = Box::pin(io);
        let stream = TokioIo::new(io);
        self.serve_connection(stream, service).await?;
        Ok(())
    }
}

impl HyperConnServer for AutoBuilder<H2Executor> {
    #[inline]
    async fn hyper_serve_connection<S, Service, Body>(
        &self,
        io: TcpStream<S>,
        service: Service,
    ) -> ServeResult
    where
        S: crate::stream::Stream + Send + 'static,
        Service: hyper::service::Service<
                crate::net::http::Request<hyper::body::Incoming>,
                Response = Response<Body>,
            > + Send
            + Sync
            + 'static,
        Service::Future: Send + 'static,
        Service::Error: Into<Box<dyn StdError + Send + Sync>>,
        Body: http_body::Body + Send + 'static,
        Body::Data: Send,
        Body::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        let io = Box::pin(io);
        let stream = TokioIo::new(io);
        self.serve_connection(stream, service).await?;
        Ok(())
    }
}

impl HyperConnWithUpgradesServer for AutoBuilder<H2Executor> {
    #[inline]
    async fn hyper_serve_connection_with_upgrades<S, Service, Body>(
        &self,
        io: TcpStream<S>,
        service: Service,
    ) -> ServeResult
    where
        S: crate::stream::Stream + Send + 'static,
        Service: hyper::service::Service<
                crate::net::http::Request<hyper::body::Incoming>,
                Response = Response<Body>,
            > + Send
            + Sync
            + 'static,
        Service::Future: Send + 'static,
        Service::Error: Into<Box<dyn StdError + Send + Sync>>,
        Body: http_body::Body + Send + 'static,
        Body::Data: Send,
        Body::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        let io = Box::pin(io);
        let stream = TokioIo::new(io);
        self.serve_connection_with_upgrades(stream, service).await?;
        Ok(())
    }
}
