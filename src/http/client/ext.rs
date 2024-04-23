use super::HttpClientError;
use crate::{
    http::{Body, Method, Request, Response, Uri},
    service::{Context, Service},
};
use std::future::Future;

/// Extends an Http Client with high level features,
/// to facilitate the creation and sending of http requests,
/// in a more ergonomic way.
pub trait HttpClientExt<State>: Sized {
    /// Convenience method to make a `GET` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied [`Url`] cannot be parsed.
    ///
    /// [`Url`]: crate::http::Uri
    fn get(&self, url: impl IntoUrl) -> RequestBuilder<Self, State>;

    /// Convenience method to make a `POST` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied [`Url`] cannot be parsed.
    ///
    /// [`Url`]: crate::http::Uri
    fn post(&self, url: impl IntoUrl) -> RequestBuilder<Self, State>;

    /// Convenience method to make a `PUT` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied [`Url`] cannot be parsed.
    ///
    /// [`Url`]: crate::http::Uri
    fn put(&self, url: impl IntoUrl) -> RequestBuilder<Self, State>;

    /// Convenience method to make a `PATCH` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied [`Url`] cannot be parsed.
    ///
    /// [`Url`]: crate::http::Uri
    fn patch(&self, url: impl IntoUrl) -> RequestBuilder<Self, State>;

    /// Convenience method to make a `DELETE` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied [`Url`] cannot be parsed.
    ///
    /// [`Url`]: crate::http::Uri
    fn delete(&self, url: impl IntoUrl) -> RequestBuilder<Self, State>;

    /// Convenience method to make a `HEAD` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn head(&self, url: impl IntoUrl) -> RequestBuilder<Self, State>;

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
    fn request(&self, method: Method, url: impl IntoUrl) -> RequestBuilder<Self, State>;

    /// Executes a `Request`.
    ///
    /// # Errors
    ///
    /// This method fails if there was an error while sending request.
    fn execute(
        &self,
        ctx: Context<State>,
        request: Request,
    ) -> impl Future<Output = Result<Response, HttpClientError>>;
}

impl<State, S> HttpClientExt<State> for S
where
    S: Service<State, Request, Response = Response, Error = HttpClientError>,
{
    fn get(&self, url: impl IntoUrl) -> RequestBuilder<Self, State> {
        self.request(Method::GET, url)
    }

    fn post(&self, url: impl IntoUrl) -> RequestBuilder<Self, State> {
        self.request(Method::POST, url)
    }

    fn put(&self, url: impl IntoUrl) -> RequestBuilder<Self, State> {
        self.request(Method::PUT, url)
    }

    fn patch(&self, url: impl IntoUrl) -> RequestBuilder<Self, State> {
        self.request(Method::PATCH, url)
    }

    fn delete(&self, url: impl IntoUrl) -> RequestBuilder<Self, State> {
        self.request(Method::DELETE, url)
    }

    fn head(&self, url: impl IntoUrl) -> RequestBuilder<Self, State> {
        self.request(Method::HEAD, url)
    }

    fn request(&self, method: Method, url: impl IntoUrl) -> RequestBuilder<Self, State> {
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
    ) -> impl Future<Output = Result<Response, HttpClientError>> {
        Service::serve(self, ctx, request)
    }
}

/// A trait to try to convert some type into a [`Url`]`.
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
                _ => Err(HttpClientError::InvalidScheme(scheme.to_string())),
            }
        }
    }

    impl IntoUrlSealed for &str {
        fn into_url(self) -> Result<Uri, HttpClientError> {
            match self.parse::<Uri>() {
                Ok(uri) => uri.into_url(),
                Err(_) => Err(HttpClientError::InvalidUri(self.to_owned())),
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
                None => Err(HttpClientError::MissingHeaderName),
            }
        }
    }

    impl IntoHeaderNameSealed for &str {
        fn into_header_name(self) -> Result<crate::http::HeaderName, HttpClientError> {
            let name = self.parse::<crate::http::HeaderName>()?;
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
            let name = crate::http::HeaderName::from_bytes(self)?;
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
            let value = self.parse::<crate::http::HeaderValue>()?;
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
            let value = crate::http::HeaderValue::from_bytes(self)?;
            Ok(value)
        }
    }
}

/// A builder to construct the properties of a [`Request`].
///
/// Constructed using [`HttpClientExt`].
pub struct RequestBuilder<'a, S, State> {
    http_client_service: &'a S,
    state: RequestBuilderState,
    _phantom: std::marker::PhantomData<fn(State) -> ()>,
}

impl<'a, S, State> std::fmt::Debug for RequestBuilder<'a, S, State>
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

impl<'a, State, S> RequestBuilder<'a, S, State>
where
    S: Service<State, Request, Response = Response, Error = HttpClientError>,
{
    /// Add a `Header` to this [`Request`]`.
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
        use crate::http::headers::authorization::Credentials;

        let header =
            crate::http::headers::Authorization::basic(username.as_ref(), password.as_ref());
        let mut value = header.0.encode();
        value.set_sensitive(true);

        self.header(crate::http::header::AUTHORIZATION, value)
    }

    /// Enable HTTP bearer authentication.
    pub fn bearer_auth<T>(mut self, token: T) -> Self
    where
        T: AsRef<str>,
    {
        use crate::http::headers::authorization::Credentials;

        let header = match crate::http::headers::Authorization::bearer(token.as_ref()) {
            Ok(header) => header,
            Err(err) => {
                self.state = match self.state {
                    RequestBuilderState::Error(original_err) => {
                        RequestBuilderState::Error(original_err)
                    }
                    _ => RequestBuilderState::Error(HttpClientError::HttpError(err.into())),
                };
                return self;
            }
        };

        let mut value = header.0.encode();
        value.set_sensitive(true);

        self.header(crate::http::header::AUTHORIZATION, value)
    }

    /// Set the [`Request`]'s [`Body`].
    pub fn body<T: Into<Body>>(mut self, body: T) -> Self {
        self.state = match self.state {
            RequestBuilderState::PreBody(builder) => match builder.body(body.into()) {
                Ok(req) => RequestBuilderState::PostBody(req),
                Err(err) => RequestBuilderState::Error(HttpClientError::HttpError(err.into())),
            },
            RequestBuilderState::PostBody(mut req) => {
                *req.body_mut() = body.into();
                RequestBuilderState::PostBody(req)
            }
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

    /// Constructs the [`Request`] and sends it to the target [`Uri`], returning a future [`Response`]`.
    ///
    /// # Errors
    ///
    /// This method fails if there was an error while sending [`Request`].
    pub async fn send(self, ctx: Context<State>) -> Result<Response, HttpClientError> {
        let request = match self.state {
            RequestBuilderState::PreBody(builder) => builder
                .body(Body::empty())
                .map_err(|err| HttpClientError::HttpError(err.into()))?,
            RequestBuilderState::PostBody(request) => request,
            RequestBuilderState::Error(err) => return Err(err),
        };

        self.http_client_service.serve(ctx, request).await
    }
}
