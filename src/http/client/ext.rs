use super::HttpClientError;
use crate::{
    error::BoxError,
    http::{headers::HeaderExt, Method, Request, Response, Uri},
    service::{Context, Service},
};
use std::future::Future;

/// Extends an Http Client with high level features,
/// to facilitate the creation and sending of http requests,
/// in a more ergonomic way.
pub trait HttpClientExt<State>:
    private::HttpClientExtSealed<State> + Sized + Send + Sync + 'static
{
    /// The response type returned by the `execute` method.
    type ExecuteResponse;
    /// The error type returned by the `execute` method.
    type ExecuteError;

    /// Convenience method to make a `GET` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied [`Url`] cannot be parsed.
    ///
    /// [`Url`]: crate::http::Uri
    fn get(&self, url: impl IntoUrl) -> RequestBuilder<Self, State, Self::ExecuteResponse>;

    /// Convenience method to make a `POST` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied [`Url`] cannot be parsed.
    ///
    /// [`Url`]: crate::http::Uri
    fn post(&self, url: impl IntoUrl) -> RequestBuilder<Self, State, Self::ExecuteResponse>;

    /// Convenience method to make a `PUT` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied [`Url`] cannot be parsed.
    ///
    /// [`Url`]: crate::http::Uri
    fn put(&self, url: impl IntoUrl) -> RequestBuilder<Self, State, Self::ExecuteResponse>;

    /// Convenience method to make a `PATCH` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied [`Url`] cannot be parsed.
    ///
    /// [`Url`]: crate::http::Uri
    fn patch(&self, url: impl IntoUrl) -> RequestBuilder<Self, State, Self::ExecuteResponse>;

    /// Convenience method to make a `DELETE` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied [`Url`] cannot be parsed.
    ///
    /// [`Url`]: crate::http::Uri
    fn delete(&self, url: impl IntoUrl) -> RequestBuilder<Self, State, Self::ExecuteResponse>;

    /// Convenience method to make a `HEAD` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn head(&self, url: impl IntoUrl) -> RequestBuilder<Self, State, Self::ExecuteResponse>;

    /// Start building a [`Request`] with the [`Method`] and [`Url`].
    ///
    /// Returns a [`RequestBuilder`], which will allow setting headers and
    /// the request body before sending.
    ///
    /// [`Request`]: crate::http::Request
    /// [`Method`]: crate::http::Method
    /// [`Url`]: crate::http::Uri
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied [`Url`] cannot be parsed.
    fn request(
        &self,
        method: Method,
        url: impl IntoUrl,
    ) -> RequestBuilder<Self, State, Self::ExecuteResponse>;

    /// Executes a `Request`.
    ///
    /// # Errors
    ///
    /// This method fails if there was an error while sending request.
    fn execute(
        &self,
        ctx: Context<State>,
        request: Request,
    ) -> impl Future<Output = Result<Self::ExecuteResponse, Self::ExecuteError>>;
}

impl<State, S, Body> HttpClientExt<State> for S
where
    S: Service<State, Request, Response = Response<Body>>,
    S::Error: Into<BoxError>,
{
    type ExecuteResponse = Response<Body>;
    type ExecuteError = S::Error;

    fn get(&self, url: impl IntoUrl) -> RequestBuilder<Self, State, Self::ExecuteResponse> {
        self.request(Method::GET, url)
    }

    fn post(&self, url: impl IntoUrl) -> RequestBuilder<Self, State, Self::ExecuteResponse> {
        self.request(Method::POST, url)
    }

    fn put(&self, url: impl IntoUrl) -> RequestBuilder<Self, State, Self::ExecuteResponse> {
        self.request(Method::PUT, url)
    }

    fn patch(&self, url: impl IntoUrl) -> RequestBuilder<Self, State, Self::ExecuteResponse> {
        self.request(Method::PATCH, url)
    }

    fn delete(&self, url: impl IntoUrl) -> RequestBuilder<Self, State, Self::ExecuteResponse> {
        self.request(Method::DELETE, url)
    }

    fn head(&self, url: impl IntoUrl) -> RequestBuilder<Self, State, Self::ExecuteResponse> {
        self.request(Method::HEAD, url)
    }

    fn request(
        &self,
        method: Method,
        url: impl IntoUrl,
    ) -> RequestBuilder<Self, State, Self::ExecuteResponse> {
        let uri = match url.into_url() {
            Ok(uri) => uri,
            Err(err) => {
                return RequestBuilder {
                    http_client_service: self,
                    state: RequestBuilderState::Error(err),
                    _phantom: std::marker::PhantomData,
                }
            }
        };

        let builder = crate::http::dep::http::request::Builder::new()
            .method(method)
            .uri(uri);

        RequestBuilder {
            http_client_service: self,
            state: RequestBuilderState::PreBody(builder),
            _phantom: std::marker::PhantomData,
        }
    }

    fn execute(
        &self,
        ctx: Context<State>,
        request: Request,
    ) -> impl Future<Output = Result<Self::ExecuteResponse, Self::ExecuteError>> {
        Service::serve(self, ctx, request)
    }
}

/// A trait to try to convert some type into a [`Url`].
///
/// This trait is “sealed”, such that only types within rama can implement it.
///
/// [`Url`]: crate::http::Uri
pub trait IntoUrl: private::IntoUrlSealed {}

impl IntoUrl for Uri {}
impl IntoUrl for &str {}
impl IntoUrl for String {}
impl IntoUrl for &String {}

/// A trait to try to convert some type into a [`HeaderName`].
///
/// This trait is “sealed”, such that only types within rama can implement it.
///
/// [`HeaderName`]: crate::http::HeaderName
pub trait IntoHeaderName: private::IntoHeaderNameSealed {}

impl IntoHeaderName for crate::http::HeaderName {}
impl IntoHeaderName for Option<crate::http::HeaderName> {}
impl IntoHeaderName for &str {}
impl IntoHeaderName for String {}
impl IntoHeaderName for &String {}
impl IntoHeaderName for &[u8] {}

/// A trait to try to convert some type into a [`HeaderValue`].
///
/// This trait is “sealed”, such that only types within rama can implement it.
///
/// [`HeaderValue`]: crate::http::HeaderValue
pub trait IntoHeaderValue: private::IntoHeaderValueSealed {}

impl IntoHeaderValue for crate::http::HeaderValue {}
impl IntoHeaderValue for &str {}
impl IntoHeaderValue for String {}
impl IntoHeaderValue for &String {}
impl IntoHeaderValue for &[u8] {}

mod private {
    use http::HeaderName;

    use crate::uri::Scheme;

    use super::*;

    pub trait IntoUrlSealed {
        fn into_url(self) -> Result<Uri, HttpClientError>;
    }

    impl IntoUrlSealed for Uri {
        fn into_url(self) -> Result<Uri, HttpClientError> {
            let scheme: Scheme = self.scheme().into();
            match scheme {
                Scheme::Http | Scheme::Https => Ok(self),
                _ => Err(HttpClientError::from_display(format!(
                    "Unsupported scheme: {scheme}"
                ))),
            }
        }
    }

    impl IntoUrlSealed for &str {
        fn into_url(self) -> Result<Uri, HttpClientError> {
            match self.parse::<Uri>() {
                Ok(uri) => uri.into_url(),
                Err(_) => Err(HttpClientError::from_display(format!(
                    "Invalid URL: {}",
                    self
                ))),
            }
        }
    }

    impl IntoUrlSealed for String {
        fn into_url(self) -> Result<Uri, HttpClientError> {
            self.as_str().into_url()
        }
    }

    impl IntoUrlSealed for &String {
        fn into_url(self) -> Result<Uri, HttpClientError> {
            self.as_str().into_url()
        }
    }

    pub trait IntoHeaderNameSealed {
        fn into_header_name(self) -> Result<crate::http::HeaderName, HttpClientError>;
    }

    impl IntoHeaderNameSealed for HeaderName {
        fn into_header_name(self) -> Result<crate::http::HeaderName, HttpClientError> {
            Ok(self)
        }
    }

    impl IntoHeaderNameSealed for Option<HeaderName> {
        fn into_header_name(self) -> Result<crate::http::HeaderName, HttpClientError> {
            match self {
                Some(name) => Ok(name),
                None => Err(HttpClientError::from_display("Header name is required")),
            }
        }
    }

    impl IntoHeaderNameSealed for &str {
        fn into_header_name(self) -> Result<crate::http::HeaderName, HttpClientError> {
            let name = self
                .parse::<crate::http::HeaderName>()
                .map_err(HttpClientError::from_std)?;
            Ok(name)
        }
    }

    impl IntoHeaderNameSealed for String {
        fn into_header_name(self) -> Result<crate::http::HeaderName, HttpClientError> {
            self.as_str().into_header_name()
        }
    }

    impl IntoHeaderNameSealed for &String {
        fn into_header_name(self) -> Result<crate::http::HeaderName, HttpClientError> {
            self.as_str().into_header_name()
        }
    }

    impl IntoHeaderNameSealed for &[u8] {
        fn into_header_name(self) -> Result<crate::http::HeaderName, HttpClientError> {
            let name =
                crate::http::HeaderName::from_bytes(self).map_err(HttpClientError::from_std)?;
            Ok(name)
        }
    }

    pub trait IntoHeaderValueSealed {
        fn into_header_value(self) -> Result<crate::http::HeaderValue, HttpClientError>;
    }

    impl IntoHeaderValueSealed for crate::http::HeaderValue {
        fn into_header_value(self) -> Result<crate::http::HeaderValue, HttpClientError> {
            Ok(self)
        }
    }

    impl IntoHeaderValueSealed for &str {
        fn into_header_value(self) -> Result<crate::http::HeaderValue, HttpClientError> {
            let value = self
                .parse::<crate::http::HeaderValue>()
                .map_err(HttpClientError::from_std)?;
            Ok(value)
        }
    }

    impl IntoHeaderValueSealed for String {
        fn into_header_value(self) -> Result<crate::http::HeaderValue, HttpClientError> {
            self.as_str().into_header_value()
        }
    }

    impl IntoHeaderValueSealed for &String {
        fn into_header_value(self) -> Result<crate::http::HeaderValue, HttpClientError> {
            self.as_str().into_header_value()
        }
    }

    impl IntoHeaderValueSealed for &[u8] {
        fn into_header_value(self) -> Result<crate::http::HeaderValue, HttpClientError> {
            let value =
                crate::http::HeaderValue::from_bytes(self).map_err(HttpClientError::from_std)?;
            Ok(value)
        }
    }

    pub trait HttpClientExtSealed<State> {}

    impl<State, S, Body> HttpClientExtSealed<State> for S
    where
        S: Service<State, Request, Response = Response<Body>>,
        S::Error: Into<BoxError>,
    {
    }
}

/// A builder to construct the properties of a [`Request`].
///
/// Constructed using [`HttpClientExt`].
pub struct RequestBuilder<'a, S, State, Response> {
    http_client_service: &'a S,
    state: RequestBuilderState,
    _phantom: std::marker::PhantomData<fn(State, Response) -> ()>,
}

impl<'a, S, State, Response> std::fmt::Debug for RequestBuilder<'a, S, State, Response>
where
    S: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestBuilder")
            .field("http_client_service", &self.http_client_service)
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Debug)]
enum RequestBuilderState {
    PreBody(crate::http::dep::http::request::Builder),
    PostBody(crate::http::Request),
    Error(HttpClientError),
}

impl<'a, S, State, Body> RequestBuilder<'a, S, State, Response<Body>>
where
    S: Service<State, Request, Response = Response<Body>>,
    S::Error: Into<BoxError>,
{
    /// Add a `Header` to this [`Request`].
    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: IntoHeaderName,
        V: IntoHeaderValue,
    {
        match self.state {
            RequestBuilderState::PreBody(builder) => {
                let key = match key.into_header_name() {
                    Ok(key) => key,
                    Err(err) => {
                        self.state = RequestBuilderState::Error(err);
                        return self;
                    }
                };
                let value = match value.into_header_value() {
                    Ok(value) => value,
                    Err(err) => {
                        self.state = RequestBuilderState::Error(err);
                        return self;
                    }
                };
                self.state = RequestBuilderState::PreBody(builder.header(key, value));
                self
            }
            RequestBuilderState::PostBody(mut request) => {
                let key = match key.into_header_name() {
                    Ok(key) => key,
                    Err(err) => {
                        self.state = RequestBuilderState::Error(err);
                        return self;
                    }
                };
                let value = match value.into_header_value() {
                    Ok(value) => value,
                    Err(err) => {
                        self.state = RequestBuilderState::Error(err);
                        return self;
                    }
                };
                request.headers_mut().append(key, value);
                self.state = RequestBuilderState::PostBody(request);
                self
            }
            RequestBuilderState::Error(err) => {
                self.state = RequestBuilderState::Error(err);
                self
            }
        }
    }

    /// Add a typed [`Header`] to this [`Request`].
    ///
    /// [`Header`]: crate::http::headers::Header
    pub fn typed_header<H>(self, header: H) -> Self
    where
        H: crate::http::headers::Header,
    {
        self.header(H::name().clone(), header.encode_to_value())
    }

    /// Add all `Headers` from the [`HeaderMap`] to this [`Request`].
    ///
    /// [`HeaderMap`]: crate::http::HeaderMap
    pub fn headers(mut self, headers: crate::http::HeaderMap) -> Self {
        for (key, value) in headers.into_iter() {
            self = self.header(key, value);
        }
        self
    }

    /// Enable HTTP basic authentication.
    pub fn basic_auth<U, P>(self, username: U, password: P) -> Self
    where
        U: AsRef<str>,
        P: AsRef<str>,
    {
        let header =
            crate::http::headers::Authorization::basic(username.as_ref(), password.as_ref());
        self.typed_header(header)
    }

    /// Enable HTTP bearer authentication.
    pub fn bearer_auth<T>(mut self, token: T) -> Self
    where
        T: AsRef<str>,
    {
        let header = match crate::http::headers::Authorization::bearer(token.as_ref()) {
            Ok(header) => header,
            Err(err) => {
                self.state = match self.state {
                    RequestBuilderState::Error(original_err) => {
                        RequestBuilderState::Error(original_err)
                    }
                    _ => RequestBuilderState::Error(HttpClientError::from_std(err)),
                };
                return self;
            }
        };

        self.typed_header(header)
    }

    /// Set the [`Request`]'s [`Body`].
    ///
    /// [`Body`]: crate::http::Body
    pub fn body<T>(mut self, body: T) -> Self
    where
        T: TryInto<crate::http::Body>,
        T::Error: Into<BoxError>,
    {
        self.state = match self.state {
            RequestBuilderState::PreBody(builder) => match body.try_into() {
                Ok(body) => match builder.body(body) {
                    Ok(req) => RequestBuilderState::PostBody(req),
                    Err(err) => RequestBuilderState::Error(HttpClientError::from_std(err)),
                },
                Err(err) => RequestBuilderState::Error(HttpClientError::from_boxed(err.into())),
            },
            RequestBuilderState::PostBody(mut req) => match body.try_into() {
                Ok(body) => {
                    *req.body_mut() = body;
                    RequestBuilderState::PostBody(req)
                }
                Err(err) => RequestBuilderState::Error(HttpClientError::from_boxed(err.into())),
            },
            RequestBuilderState::Error(err) => RequestBuilderState::Error(err),
        };
        self
    }

    /// Set the given value as a URL-Encoded Form [`Body`] in the [`Request`].
    ///
    /// [`Body`]: crate::http::Body
    pub fn form<T: serde::Serialize + ?Sized>(mut self, form: &T) -> Self {
        self.state = match self.state {
            RequestBuilderState::PreBody(mut builder) => match serde_html_form::to_string(form) {
                Ok(body) => {
                    let builder = match builder.headers_mut() {
                        Some(headers) => {
                            if !headers.contains_key(crate::http::header::CONTENT_TYPE) {
                                headers.insert(
                                    crate::http::header::CONTENT_TYPE,
                                    crate::http::HeaderValue::from_static(
                                        "application/x-www-form-urlencoded",
                                    ),
                                );
                            }
                            builder
                        }
                        None => builder.header(
                            crate::http::header::CONTENT_TYPE,
                            crate::http::HeaderValue::from_static(
                                "application/x-www-form-urlencoded",
                            ),
                        ),
                    };
                    match builder.body(body.into()) {
                        Ok(req) => RequestBuilderState::PostBody(req),
                        Err(err) => RequestBuilderState::Error(HttpClientError::from_std(err)),
                    }
                }
                Err(err) => RequestBuilderState::Error(HttpClientError::from_std(err)),
            },
            RequestBuilderState::PostBody(mut req) => match serde_html_form::to_string(form) {
                Ok(body) => {
                    if !req
                        .headers()
                        .contains_key(crate::http::header::CONTENT_TYPE)
                    {
                        req.headers_mut().insert(
                            crate::http::header::CONTENT_TYPE,
                            crate::http::HeaderValue::from_static(
                                "application/x-www-form-urlencoded",
                            ),
                        );
                    }
                    *req.body_mut() = body.into();
                    RequestBuilderState::PostBody(req)
                }
                Err(err) => RequestBuilderState::Error(HttpClientError::from_std(err)),
            },
            RequestBuilderState::Error(err) => RequestBuilderState::Error(err),
        };
        self
    }

    /// Set the given value as a JSON [`Body`] in the [`Request`].
    ///
    /// [`Body`]: crate::http::Body
    pub fn json<T: serde::Serialize + ?Sized>(mut self, json: &T) -> Self {
        self.state = match self.state {
            RequestBuilderState::PreBody(mut builder) => match serde_json::to_vec(json) {
                Ok(body) => {
                    let builder = match builder.headers_mut() {
                        Some(headers) => {
                            if !headers.contains_key(crate::http::header::CONTENT_TYPE) {
                                headers.insert(
                                    crate::http::header::CONTENT_TYPE,
                                    crate::http::HeaderValue::from_static("application/json"),
                                );
                            }
                            builder
                        }
                        None => builder.header(
                            crate::http::header::CONTENT_TYPE,
                            crate::http::HeaderValue::from_static("application/json"),
                        ),
                    };
                    match builder.body(body.into()) {
                        Ok(req) => RequestBuilderState::PostBody(req),
                        Err(err) => RequestBuilderState::Error(HttpClientError::from_std(err)),
                    }
                }
                Err(err) => RequestBuilderState::Error(HttpClientError::from_std(err)),
            },
            RequestBuilderState::PostBody(mut req) => match serde_json::to_vec(json) {
                Ok(body) => {
                    if !req
                        .headers()
                        .contains_key(crate::http::header::CONTENT_TYPE)
                    {
                        req.headers_mut().insert(
                            crate::http::header::CONTENT_TYPE,
                            crate::http::HeaderValue::from_static("application/json"),
                        );
                    }
                    *req.body_mut() = body.into();
                    RequestBuilderState::PostBody(req)
                }
                Err(err) => RequestBuilderState::Error(HttpClientError::from_std(err)),
            },
            RequestBuilderState::Error(err) => RequestBuilderState::Error(err),
        };
        self
    }

    /// Set the http [`Version`] of this [`Request`].
    ///
    /// [`Version`]: crate::http::Version
    pub fn version(mut self, version: crate::http::Version) -> Self {
        match self.state {
            RequestBuilderState::PreBody(builder) => {
                self.state = RequestBuilderState::PreBody(builder.version(version));
                self
            }
            RequestBuilderState::PostBody(mut request) => {
                *request.version_mut() = version;
                self.state = RequestBuilderState::PostBody(request);
                self
            }
            RequestBuilderState::Error(err) => {
                self.state = RequestBuilderState::Error(err);
                self
            }
        }
    }

    /// Constructs the [`Request`] and sends it to the target [`Uri`], returning a future [`Response`].
    ///
    /// # Errors
    ///
    /// This method fails if there was an error while sending [`Request`].
    pub async fn send(self, ctx: Context<State>) -> Result<Response<Body>, HttpClientError> {
        let request = match self.state {
            RequestBuilderState::PreBody(builder) => builder
                .body(crate::http::Body::empty())
                .map_err(HttpClientError::from_std)?,
            RequestBuilderState::PostBody(request) => request,
            RequestBuilderState::Error(err) => return Err(err),
        };

        let uri = request.uri().clone();
        match self.http_client_service.serve(ctx, request).await {
            Ok(response) => Ok(response),
            Err(err) => Err(HttpClientError::from_boxed(err.into()).with_uri(uri)),
        }
    }
}

#[cfg(test)]
mod test {
    use http::StatusCode;

    use super::*;
    use crate::{
        http::{
            layer::{
                required_header::AddRequiredRequestHeadersLayer,
                retry::{ManagedPolicy, RetryLayer},
                trace::TraceLayer,
            },
            IntoResponse,
        },
        service::{util::backoff::ExponentialBackoff, BoxService, ServiceBuilder},
    };
    use std::convert::Infallible;

    async fn fake_client_fn<S, Body>(
        _ctx: Context<S>,
        request: Request<Body>,
    ) -> Result<Response, Infallible>
    where
        S: Send + Sync + 'static,
        Body: crate::http::dep::http_body::Body + Send + 'static,
        Body::Data: Send + 'static,
        Body::Error: Send + 'static,
    {
        let ua = request
            .headers()
            .get(crate::http::header::USER_AGENT)
            .unwrap();
        assert_eq!(
            ua.to_str().unwrap(),
            format!(
                "{}/{}",
                crate::utils::info::NAME,
                crate::utils::info::VERSION
            )
        );

        Ok(StatusCode::OK.into_response())
    }

    fn map_internal_client_error<E, Body>(
        result: Result<Response<Body>, E>,
    ) -> Result<Response, crate::error::BoxError>
    where
        E: Into<crate::error::BoxError>,
        Body: crate::http::dep::http_body::Body<Data = bytes::Bytes> + Send + Sync + 'static,
        Body::Error: Into<BoxError>,
    {
        match result {
            Ok(response) => Ok(response.map(crate::http::Body::new)),
            Err(err) => Err(err.into()),
        }
    }

    type HttpClientError = crate::error::BoxError;
    type HttpClient<S> = BoxService<S, Request, Response, HttpClientError>;

    fn client<S: Send + Sync + 'static>() -> HttpClient<S> {
        let builder = ServiceBuilder::new()
            .map_result(map_internal_client_error)
            .layer(TraceLayer::new_for_http());

        #[cfg(feature = "compression")]
        let builder = builder.layer(crate::http::layer::decompression::DecompressionLayer::new());

        builder
            .layer(RetryLayer::new(
                ManagedPolicy::default().with_backoff(ExponentialBackoff::default()),
            ))
            .layer(AddRequiredRequestHeadersLayer::default())
            .service_fn(fake_client_fn)
            .boxed()
    }

    #[tokio::test]
    async fn test_client_happy_path() {
        let response = client()
            .get("http://127.0.0.1:8080")
            .send(Context::default())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
