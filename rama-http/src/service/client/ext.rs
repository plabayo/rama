use crate::{Method, Request, Uri};
use rama_core::{
    Service,
    error::{BoxError, ErrorExt},
    extensions::{Extension, Extensions, ExtensionsMut},
};
use rama_http_headers::authorization::Credentials;
use rama_http_types::Response;

/// Convenience extension methods to build HTTP requests using a `Service`.
///
/// Pattern:
/// - `method(&self, ..)` returns a builder backed by a borrowed service handle
/// - `into_method(self, ..)` returns a builder backed by an owned service handle
pub trait HttpClientExt: private::HttpClientExtSealed + Sized + Send + Sync + 'static {
    /// Convenience method to make a `GET` request to a URL, from a borrowed `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn get(&self, url: impl IntoUrl) -> RequestBuilder<RQBorrowedService<'_, Self>>;

    /// Convenience method to make a `GET` request to a URL, from an owned `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn into_get(self, url: impl IntoUrl) -> RequestBuilder<RQOwnedService<Self>>;

    /// Convenience method to make a `POST` request to a URL, from a borrowed `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn post(&self, url: impl IntoUrl) -> RequestBuilder<RQBorrowedService<'_, Self>>;

    /// Convenience method to make a `POST` request to a URL, from an owned `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn into_post(self, url: impl IntoUrl) -> RequestBuilder<RQOwnedService<Self>>;

    /// Convenience method to make a `PUT` request to a URL, from a borrowed `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn put(&self, url: impl IntoUrl) -> RequestBuilder<RQBorrowedService<'_, Self>>;

    /// Convenience method to make a `PUT` request to a URL, from an owned `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn into_put(self, url: impl IntoUrl) -> RequestBuilder<RQOwnedService<Self>>;

    /// Convenience method to make a `DELETE` request to a URL, from a borrowed `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn delete(&self, url: impl IntoUrl) -> RequestBuilder<RQBorrowedService<'_, Self>>;

    /// Convenience method to make a `DELETE` request to a URL, from an owned `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn into_delete(self, url: impl IntoUrl) -> RequestBuilder<RQOwnedService<Self>>;

    /// Convenience method to make a `PATCH` request to a URL, from a borrowed `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn patch(&self, url: impl IntoUrl) -> RequestBuilder<RQBorrowedService<'_, Self>>;

    /// Convenience method to make a `PATCH` request to a URL, from an owned `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn into_patch(self, url: impl IntoUrl) -> RequestBuilder<RQOwnedService<Self>>;

    /// Convenience method to make a `HEAD` request to a URL, from a borrowed `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn head(&self, url: impl IntoUrl) -> RequestBuilder<RQBorrowedService<'_, Self>>;

    /// Convenience method to make a `HEAD` request to a URL, from an owned `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn into_head(self, url: impl IntoUrl) -> RequestBuilder<RQOwnedService<Self>>;

    /// Convenience method to make an `OPTIONS` request to a URL, from a borrowed `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn options(&self, url: impl IntoUrl) -> RequestBuilder<RQBorrowedService<'_, Self>>;

    /// Convenience method to make an `OPTIONS` request to a URL, from an owned `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn into_options(self, url: impl IntoUrl) -> RequestBuilder<RQOwnedService<Self>>;

    /// Convenience method to make a `TRACE` request to a URL, from a borrowed `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn trace(&self, url: impl IntoUrl) -> RequestBuilder<RQBorrowedService<'_, Self>>;

    /// Convenience method to make a `TRACE` request to a URL, from an owned `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn into_trace(self, url: impl IntoUrl) -> RequestBuilder<RQOwnedService<Self>>;

    /// Convenience method to make a `CONNECT` request to a URL, from a borrowed `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn connect(&self, url: impl IntoUrl) -> RequestBuilder<RQBorrowedService<'_, Self>>;

    /// Convenience method to make a `CONNECT` request to a URL, from an owned `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn into_connect(self, url: impl IntoUrl) -> RequestBuilder<RQOwnedService<Self>>;

    /// General purpose request builder using an explicit `Method`, from a borrowed `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn request(
        &self,
        method: crate::Method,
        url: impl IntoUrl,
    ) -> RequestBuilder<RQBorrowedService<'_, Self>>;

    /// General purpose request builder using an explicit `Method`, from an owned `Service`.
    ///
    /// # Errors
    /// This method fails whenever the supplied `Url` cannot be parsed.
    fn into_request(
        self,
        method: crate::Method,
        url: impl IntoUrl,
    ) -> RequestBuilder<RQOwnedService<Self>>;

    /// Build a request builder from an already constructed [`Request`], using a borrowed `Service`.
    ///
    /// This is useful if you created a `Request` elsewhere (or received one) and still want
    /// to use the fluent `RequestBuilder` API to mutate headers, body, extensions, etc.
    fn build_from_request(&self, request: Request) -> RequestBuilder<RQBorrowedService<'_, Self>>;

    /// Build a request builder from an already constructed [`Request`], using an owned `Service`.
    ///
    /// Same as [`Self::build_from_request`] but returns a builder backed by an owned `Service`,
    /// so it can be moved into spawned tasks.
    fn into_build_from_request(self, request: Request) -> RequestBuilder<RQOwnedService<Self>>;
}

impl<S, Body> HttpClientExt for S
where
    S: Service<Request, Output = Response<Body>, Error: Into<BoxError>>,
{
    fn get(&self, url: impl IntoUrl) -> RequestBuilder<RQBorrowedService<'_, Self>> {
        self.request(Method::GET, url)
    }

    fn into_get(self, url: impl IntoUrl) -> RequestBuilder<RQOwnedService<Self>> {
        self.into_request(Method::GET, url)
    }

    fn post(&self, url: impl IntoUrl) -> RequestBuilder<RQBorrowedService<'_, Self>> {
        self.request(Method::POST, url)
    }

    fn into_post(self, url: impl IntoUrl) -> RequestBuilder<RQOwnedService<Self>> {
        self.into_request(Method::POST, url)
    }

    fn put(&self, url: impl IntoUrl) -> RequestBuilder<RQBorrowedService<'_, Self>> {
        self.request(Method::PUT, url)
    }

    fn into_put(self, url: impl IntoUrl) -> RequestBuilder<RQOwnedService<Self>> {
        self.into_request(Method::PUT, url)
    }

    fn patch(&self, url: impl IntoUrl) -> RequestBuilder<RQBorrowedService<'_, Self>> {
        self.request(Method::PATCH, url)
    }

    fn into_patch(self, url: impl IntoUrl) -> RequestBuilder<RQOwnedService<Self>> {
        self.into_request(Method::PATCH, url)
    }

    fn delete(&self, url: impl IntoUrl) -> RequestBuilder<RQBorrowedService<'_, Self>> {
        self.request(Method::DELETE, url)
    }

    fn into_delete(self, url: impl IntoUrl) -> RequestBuilder<RQOwnedService<Self>> {
        self.into_request(Method::DELETE, url)
    }

    fn head(&self, url: impl IntoUrl) -> RequestBuilder<RQBorrowedService<'_, Self>> {
        self.request(Method::HEAD, url)
    }

    fn into_head(self, url: impl IntoUrl) -> RequestBuilder<RQOwnedService<Self>> {
        self.into_request(Method::HEAD, url)
    }

    fn options(&self, url: impl IntoUrl) -> RequestBuilder<RQBorrowedService<'_, Self>> {
        self.request(Method::OPTIONS, url)
    }

    fn into_options(self, url: impl IntoUrl) -> RequestBuilder<RQOwnedService<Self>> {
        self.into_request(Method::OPTIONS, url)
    }

    fn trace(&self, url: impl IntoUrl) -> RequestBuilder<RQBorrowedService<'_, Self>> {
        self.request(Method::TRACE, url)
    }

    fn into_trace(self, url: impl IntoUrl) -> RequestBuilder<RQOwnedService<Self>> {
        self.into_request(Method::TRACE, url)
    }

    fn connect(&self, url: impl IntoUrl) -> RequestBuilder<RQBorrowedService<'_, Self>> {
        self.request(Method::CONNECT, url)
    }

    fn into_connect(self, url: impl IntoUrl) -> RequestBuilder<RQOwnedService<Self>> {
        self.into_request(Method::CONNECT, url)
    }

    fn request(
        &self,
        method: Method,
        url: impl IntoUrl,
    ) -> RequestBuilder<RQBorrowedService<'_, Self>> {
        let uri = match url.into_url() {
            Ok(uri) => uri,
            Err(err) => {
                return RequestBuilder {
                    http_client_service: RQBorrowedService(self),
                    state: RequestBuilderState::Error(err),
                };
            }
        };

        let builder = crate::request::Builder::new().method(method).uri(uri);

        RequestBuilder {
            http_client_service: RQBorrowedService(self),
            state: RequestBuilderState::PreBody(builder),
        }
    }

    fn into_request(
        self,
        method: Method,
        url: impl IntoUrl,
    ) -> RequestBuilder<RQOwnedService<Self>> {
        let uri = match url.into_url() {
            Ok(uri) => uri,
            Err(err) => {
                return RequestBuilder {
                    http_client_service: RQOwnedService(self),
                    state: RequestBuilderState::Error(err),
                };
            }
        };

        let builder = crate::request::Builder::new().method(method).uri(uri);

        RequestBuilder {
            http_client_service: RQOwnedService(self),
            state: RequestBuilderState::PreBody(builder),
        }
    }

    fn build_from_request(&self, request: Request) -> RequestBuilder<RQBorrowedService<'_, Self>> {
        RequestBuilder {
            http_client_service: RQBorrowedService(self),
            state: RequestBuilderState::PostBody(request),
        }
    }

    fn into_build_from_request(self, request: Request) -> RequestBuilder<RQOwnedService<Self>> {
        RequestBuilder {
            http_client_service: RQOwnedService(self),
            state: RequestBuilderState::PostBody(request),
        }
    }
}

/// A trait to try to convert some type into a [`Url`].
///
/// This trait is “sealed”, such that only types within rama can implement it.
///
/// [`Url`]: crate::Uri
pub trait IntoUrl: private::IntoUrlSealed {}

impl IntoUrl for Uri {}
impl IntoUrl for &str {}
impl IntoUrl for String {}
impl IntoUrl for &String {}

/// A trait to try to convert some type into a [`HeaderName`].
///
/// This trait is “sealed”, such that only types within rama can implement it.
///
/// [`HeaderName`]: crate::HeaderName
pub trait IntoHeaderName: private::IntoHeaderNameSealed {}

impl IntoHeaderName for crate::HeaderName {}
impl IntoHeaderName for Option<crate::HeaderName> {}
impl IntoHeaderName for &str {}
impl IntoHeaderName for String {}
impl IntoHeaderName for &String {}
impl IntoHeaderName for &[u8] {}

/// A trait to try to convert some type into a [`HeaderValue`].
///
/// This trait is “sealed”, such that only types within rama can implement it.
///
/// [`HeaderValue`]: crate::HeaderValue
pub trait IntoHeaderValue: private::IntoHeaderValueSealed {}

impl IntoHeaderValue for crate::HeaderValue {}
impl IntoHeaderValue for &str {}
impl IntoHeaderValue for String {}
impl IntoHeaderValue for &String {}
impl IntoHeaderValue for &[u8] {}

mod private {
    use rama_http_types::HeaderName;
    use rama_net::Protocol;

    use super::*;

    pub trait IntoUrlSealed {
        fn into_url(self) -> Result<Uri, BoxError>;
    }

    impl IntoUrlSealed for Uri {
        fn into_url(self) -> Result<Uri, BoxError> {
            let protocol: Option<Protocol> = self.scheme().map(Into::into);
            match protocol {
                Some(protocol) => {
                    if protocol.is_http() || protocol.is_ws() {
                        Ok(self)
                    } else {
                        Err(BoxError::from("unsupported protocol")
                            .context_field("protocol", protocol))
                    }
                }
                None => Err(BoxError::from("Missing scheme in URI")),
            }
        }
    }

    impl IntoUrlSealed for &str {
        fn into_url(self) -> Result<Uri, BoxError> {
            match self.parse::<Uri>() {
                Ok(uri) => uri.into_url(),
                Err(_) => Err(BoxError::from("invalid url").context_str_field("raw_str", self)),
            }
        }
    }

    impl IntoUrlSealed for String {
        #[inline(always)]
        fn into_url(self) -> Result<Uri, BoxError> {
            self.as_str().into_url()
        }
    }

    impl IntoUrlSealed for &String {
        #[inline(always)]
        fn into_url(self) -> Result<Uri, BoxError> {
            self.as_str().into_url()
        }
    }

    pub trait IntoHeaderNameSealed {
        fn into_header_name(self) -> Result<crate::HeaderName, BoxError>;
    }

    impl IntoHeaderNameSealed for HeaderName {
        fn into_header_name(self) -> Result<crate::HeaderName, BoxError> {
            Ok(self)
        }
    }

    impl IntoHeaderNameSealed for Option<HeaderName> {
        fn into_header_name(self) -> Result<crate::HeaderName, BoxError> {
            match self {
                Some(name) => Ok(name),
                None => Err(BoxError::from("Header name is required")),
            }
        }
    }

    impl IntoHeaderNameSealed for &str {
        fn into_header_name(self) -> Result<crate::HeaderName, BoxError> {
            let name = self.parse::<crate::HeaderName>()?;
            Ok(name)
        }
    }

    impl IntoHeaderNameSealed for String {
        #[inline(always)]
        fn into_header_name(self) -> Result<crate::HeaderName, BoxError> {
            self.as_str().into_header_name()
        }
    }

    impl IntoHeaderNameSealed for &String {
        #[inline(always)]
        fn into_header_name(self) -> Result<crate::HeaderName, BoxError> {
            self.as_str().into_header_name()
        }
    }

    impl IntoHeaderNameSealed for &[u8] {
        fn into_header_name(self) -> Result<crate::HeaderName, BoxError> {
            let name = crate::HeaderName::from_bytes(self)?;
            Ok(name)
        }
    }

    pub trait IntoHeaderValueSealed {
        fn into_header_value(self) -> Result<crate::HeaderValue, BoxError>;
    }

    impl IntoHeaderValueSealed for crate::HeaderValue {
        fn into_header_value(self) -> Result<crate::HeaderValue, BoxError> {
            Ok(self)
        }
    }

    impl IntoHeaderValueSealed for &str {
        fn into_header_value(self) -> Result<crate::HeaderValue, BoxError> {
            let value = self.parse::<crate::HeaderValue>()?;
            Ok(value)
        }
    }

    impl IntoHeaderValueSealed for String {
        fn into_header_value(self) -> Result<crate::HeaderValue, BoxError> {
            self.as_str().into_header_value()
        }
    }

    impl IntoHeaderValueSealed for &String {
        #[inline(always)]
        fn into_header_value(self) -> Result<crate::HeaderValue, BoxError> {
            self.as_str().into_header_value()
        }
    }

    impl IntoHeaderValueSealed for &[u8] {
        fn into_header_value(self) -> Result<crate::HeaderValue, BoxError> {
            let value = crate::HeaderValue::from_bytes(self)?;
            Ok(value)
        }
    }

    pub trait HttpClientExtSealed {}

    impl<S, Body> HttpClientExtSealed for S where
        S: Service<Request, Output = Response<Body>, Error: Into<BoxError>>
    {
    }
}

#[derive(Debug)]
/// A builder to construct the properties of a [`Request`].
///
/// Constructed using [`HttpClientExt`].
pub struct RequestBuilder<S> {
    http_client_service: S,
    state: RequestBuilderState,
}
#[derive(Debug)]
pub struct RQOwnedService<S>(S);
#[derive(Debug)]
pub struct RQBorrowedService<'a, S>(&'a S);

/// Internal trait that is implemented for all `S` variants of `RequestBuilder`.
///
/// You never need to implement this trait yourself, but you might need to trait bound it,
/// if you have generic code over a [`RequestBuilder`].
pub trait RequestServiceHandle {
    type Body;
    type Svc: Service<Request, Output = Response<Self::Body>, Error: Into<BoxError>>;

    fn svc_ref(&self) -> &Self::Svc;
}

impl<'a, S, Body> RequestServiceHandle for RQBorrowedService<'a, S>
where
    S: Service<Request, Output = Response<Body>, Error: Into<BoxError>>,
{
    type Body = Body;
    type Svc = S;

    #[inline]
    fn svc_ref(&self) -> &S {
        self.0
    }
}

impl<S, Body> RequestServiceHandle for RQOwnedService<S>
where
    S: Service<Request, Output = Response<Body>, Error: Into<BoxError>>,
{
    type Body = Body;
    type Svc = S;

    #[inline]
    fn svc_ref(&self) -> &S {
        &self.0
    }
}

#[derive(Debug)]
enum RequestBuilderState {
    PreBody(crate::request::Builder),
    PostBody(crate::Request),
    Error(BoxError),
}

impl<S> RequestBuilder<S> {
    /// Add a `Header` to this [`Request`].
    #[must_use]
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

    /// Add a typed [`HeaderEncode`] to this [`Request`].
    ///
    /// [`HeaderEncode`]: crate::headers::HeaderEncode
    #[must_use]
    pub fn typed_header<H>(self, header: H) -> Self
    where
        H: crate::headers::HeaderEncode,
    {
        if let Some(value) = header.encode_to_value() {
            self.header(H::name().clone(), value)
        } else {
            self
        }
    }

    /// Add all `Headers` from the [`HeaderMap`] to this [`Request`].
    ///
    /// [`HeaderMap`]: crate::HeaderMap
    #[must_use]
    pub fn headers(mut self, headers: crate::HeaderMap) -> Self {
        for (key, value) in headers.into_iter() {
            self = self.header(key, value);
        }
        self
    }

    /// Overwrite a `Header` to this [`Request`].
    #[must_use]
    pub fn overwrite_header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: IntoHeaderName,
        V: IntoHeaderValue,
    {
        match self.state {
            RequestBuilderState::PreBody(mut builder) => {
                // None in case builder has errors
                if let Some(headers) = builder.headers_mut() {
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
                    let _ = headers.insert(key, value);
                }

                self.state = RequestBuilderState::PreBody(builder);
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
                let _ = request.headers_mut().insert(key, value);
                self.state = RequestBuilderState::PostBody(request);
                self
            }
            RequestBuilderState::Error(err) => {
                self.state = RequestBuilderState::Error(err);
                self
            }
        }
    }

    /// Overwrite a typed [`HeaderEncode`] to this [`Request`].
    ///
    /// [`HeaderEncode`]: crate::headers::HeaderEncode
    #[must_use]
    pub fn overwrite_typed_header<H>(self, header: H) -> Self
    where
        H: crate::headers::HeaderEncode,
    {
        if let Some(value) = header.encode_to_value() {
            self.overwrite_header(H::name().clone(), value)
        } else {
            self
        }
    }

    /// Enable HTTP authentication.
    #[must_use]
    pub fn auth(self, credentials: impl Credentials) -> Self {
        let header = crate::headers::Authorization::new(credentials);
        self.typed_header(header)
    }

    /// Adds an extension to this builder
    #[must_use]
    pub fn extension<T>(mut self, extension: T) -> Self
    where
        T: Extension + Clone,
    {
        match self.state {
            RequestBuilderState::PreBody(builder) => {
                let builder = builder.extension(extension);
                self.state = RequestBuilderState::PreBody(builder);
                self
            }
            RequestBuilderState::PostBody(mut request) => {
                request.extensions_mut().insert(extension);
                self.state = RequestBuilderState::PostBody(request);
                self
            }
            state @ RequestBuilderState::Error(_) => {
                self.state = state;
                self
            }
        }
    }

    /// Get mutable access to the underlying [`Extensions`]
    ///
    /// This function will return None if [`Extensions`] are not available,
    /// or if this builder is in an error state
    pub fn extensions_mut(&mut self) -> Option<&mut Extensions> {
        match &mut self.state {
            RequestBuilderState::PreBody(builder) => builder.extensions_mut(),
            RequestBuilderState::PostBody(request) => Some(request.extensions_mut()),
            RequestBuilderState::Error(_) => None,
        }
    }

    /// Set the [`Request`]'s [`Body`].
    ///
    /// [`Body`]: crate::Body
    #[must_use]
    pub fn body<T>(mut self, body: T) -> Self
    where
        T: TryInto<crate::Body, Error: Into<BoxError>>,
    {
        self.state = match self.state {
            RequestBuilderState::PreBody(builder) => match body.try_into() {
                Ok(body) => match builder.body(body) {
                    Ok(req) => RequestBuilderState::PostBody(req),
                    Err(err) => RequestBuilderState::Error(BoxError::from(err)),
                },
                Err(err) => RequestBuilderState::Error(err.into()),
            },
            RequestBuilderState::PostBody(mut req) => match body.try_into() {
                Ok(body) => {
                    *req.body_mut() = body;
                    RequestBuilderState::PostBody(req)
                }
                Err(err) => RequestBuilderState::Error(BoxError::from(err.into())),
            },
            RequestBuilderState::Error(err) => RequestBuilderState::Error(err),
        };
        self
    }

    /// Set the given value as a URL-Encoded Form [`Body`] in the [`Request`].
    ///
    /// [`Body`]: crate::Body
    #[must_use]
    pub fn form<T: serde::Serialize + ?Sized>(mut self, form: &T) -> Self {
        self.state = match self.state {
            RequestBuilderState::PreBody(mut builder) => match serde_html_form::to_string(form) {
                Ok(body) => {
                    let builder = match builder.headers_mut() {
                        Some(headers) => {
                            if !headers.contains_key(crate::header::CONTENT_TYPE) {
                                headers.insert(
                                    crate::header::CONTENT_TYPE,
                                    crate::HeaderValue::from_static(
                                        "application/x-www-form-urlencoded",
                                    ),
                                );
                            }
                            builder
                        }
                        None => builder.header(
                            crate::header::CONTENT_TYPE,
                            crate::HeaderValue::from_static("application/x-www-form-urlencoded"),
                        ),
                    };
                    match builder.body(body.into()) {
                        Ok(req) => RequestBuilderState::PostBody(req),
                        Err(err) => RequestBuilderState::Error(BoxError::from(err)),
                    }
                }
                Err(err) => RequestBuilderState::Error(BoxError::from(err)),
            },
            RequestBuilderState::PostBody(mut req) => match serde_html_form::to_string(form) {
                Ok(body) => {
                    if !req.headers().contains_key(crate::header::CONTENT_TYPE) {
                        req.headers_mut().insert(
                            crate::header::CONTENT_TYPE,
                            crate::HeaderValue::from_static("application/x-www-form-urlencoded"),
                        );
                    }
                    *req.body_mut() = body.into();
                    RequestBuilderState::PostBody(req)
                }
                Err(err) => RequestBuilderState::Error(BoxError::from(err)),
            },
            RequestBuilderState::Error(err) => RequestBuilderState::Error(err),
        };
        self
    }

    /// Set the given value as a JSON [`Body`] in the [`Request`].
    ///
    /// [`Body`]: crate::Body
    #[must_use]
    pub fn json<T: serde::Serialize + ?Sized>(mut self, json: &T) -> Self {
        self.state = match self.state {
            RequestBuilderState::PreBody(mut builder) => match serde_json::to_vec(json) {
                Ok(body) => {
                    let builder = match builder.headers_mut() {
                        Some(headers) => {
                            if !headers.contains_key(crate::header::CONTENT_TYPE) {
                                headers.insert(
                                    crate::header::CONTENT_TYPE,
                                    crate::HeaderValue::from_static("application/json"),
                                );
                            }
                            builder
                        }
                        None => builder.header(
                            crate::header::CONTENT_TYPE,
                            crate::HeaderValue::from_static("application/json"),
                        ),
                    };
                    match builder.body(body.into()) {
                        Ok(req) => RequestBuilderState::PostBody(req),
                        Err(err) => RequestBuilderState::Error(BoxError::from(err)),
                    }
                }
                Err(err) => RequestBuilderState::Error(BoxError::from(err)),
            },
            RequestBuilderState::PostBody(mut req) => match serde_json::to_vec(json) {
                Ok(body) => {
                    if !req.headers().contains_key(crate::header::CONTENT_TYPE) {
                        req.headers_mut().insert(
                            crate::header::CONTENT_TYPE,
                            crate::HeaderValue::from_static("application/json"),
                        );
                    }
                    *req.body_mut() = body.into();
                    RequestBuilderState::PostBody(req)
                }
                Err(err) => RequestBuilderState::Error(BoxError::from(err)),
            },
            RequestBuilderState::Error(err) => RequestBuilderState::Error(err),
        };
        self
    }

    /// Set the http [`Version`] of this [`Request`].
    ///
    /// [`Version`]: crate::Version
    #[must_use]
    pub fn version(mut self, version: crate::Version) -> Self {
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
}

impl<S> RequestBuilder<S> {
    /// Constructs the [`Request`].
    ///
    /// # Errors
    ///
    /// This method fails if there was an error while building the [`Request`].
    pub fn try_into_request(self) -> Result<Request, BoxError> {
        Ok(match self.state {
            RequestBuilderState::PreBody(builder) => builder.body(crate::Body::empty())?,
            RequestBuilderState::PostBody(request) => request,
            RequestBuilderState::Error(err) => return Err(err),
        })
    }
}

impl<S, Body> RequestBuilder<RQOwnedService<S>>
where
    S: Service<Request, Output = Response<Body>, Error: Into<BoxError>>,
{
    /// Constructs the [`Request`] and return it together with the inner [`Service`].
    ///
    /// # Errors
    ///
    /// This method fails if there was an error while building the [`Request`].
    pub fn try_into_parts(self) -> Result<(Request, S), BoxError> {
        let request = match self.state {
            RequestBuilderState::PreBody(builder) => builder.body(crate::Body::empty())?,
            RequestBuilderState::PostBody(request) => request,
            RequestBuilderState::Error(err) => return Err(err),
        };

        Ok((request, self.http_client_service.0))
    }
}

impl<S: RequestServiceHandle> RequestBuilder<S> {
    /// Constructs the [`Request`] and sends it to the target [`Uri`],
    /// returning the [`Service`]'s result.
    ///
    /// # Errors
    ///
    /// This method fails if there was an error while building the [`Request`]
    /// or processing it using the inner [`Service`].
    pub async fn send(self) -> Result<Response<S::Body>, BoxError> {
        let request = match self.state {
            RequestBuilderState::PreBody(builder) => builder.body(crate::Body::empty())?,
            RequestBuilderState::PostBody(request) => request,
            RequestBuilderState::Error(err) => return Err(err),
        };

        let uri = request.uri().clone();

        match self.http_client_service.svc_ref().serve(request).await {
            Ok(response) => Ok(response),
            Err(err) => Err(err.context("send request").context_field("uri", uri)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{
        StreamingBody,
        layer::{
            required_header::AddRequiredRequestHeadersLayer,
            retry::{ManagedPolicy, RetryLayer},
            trace::TraceLayer,
        },
        service::web::response::IntoResponse,
    };

    use rama_core::{
        layer::{Layer, MapResultLayer},
        service::{BoxService, service_fn},
    };
    use rama_http_types::{Response, StatusCode};
    use rama_utils::backoff::ExponentialBackoff;

    use std::convert::Infallible;

    async fn fake_client_fn<Body>(request: Request<Body>) -> Result<Response, Infallible>
    where
        Body: StreamingBody<Data: Send + 'static, Error: Send + 'static> + Send + 'static,
    {
        let ua = request.headers().get(crate::header::USER_AGENT).unwrap();
        assert_eq!(
            ua.to_str().unwrap(),
            format!("{}/{}", rama_utils::info::NAME, rama_utils::info::VERSION)
        );

        Ok(StatusCode::OK.into_response())
    }

    fn map_internal_client_error<E, Body>(
        result: Result<Response<Body>, E>,
    ) -> Result<Response, rama_core::error::BoxError>
    where
        E: Into<rama_core::error::BoxError>,
        Body: StreamingBody<Data = rama_core::bytes::Bytes, Error: Into<BoxError>>
            + Send
            + Sync
            + 'static,
    {
        match result {
            Ok(response) => Ok(response.map(crate::Body::new)),
            Err(err) => Err(err.into()),
        }
    }

    type HttpClient = BoxService<Request, Response, BoxError>;

    fn client() -> HttpClient {
        let builder = (
            MapResultLayer::new(map_internal_client_error),
            TraceLayer::new_for_http(),
        );

        #[cfg(feature = "compression")]
        let builder = (
            builder,
            crate::layer::decompression::DecompressionLayer::new(),
        );

        (
            builder,
            RetryLayer::new(ManagedPolicy::default().with_backoff(ExponentialBackoff::default())),
            AddRequiredRequestHeadersLayer::default(),
        )
            .into_layer(service_fn(fake_client_fn))
            .boxed()
    }

    #[tokio::test]
    async fn test_client_happy_path() {
        let response = client().get("http://127.0.0.1:8080").send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
