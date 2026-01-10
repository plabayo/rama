use crate::metadata::{MetadataMap, MetadataValue};
use rama_core::{
    error::{ErrorContext as _, OpaqueError},
    extensions::{Extensions, ExtensionsMut, ExtensionsRef},
    futures::Stream,
};
use rama_http::header::{self, RAMA_ID_HEADER_VALUE, USER_AGENT};
use rama_utils::str::smol_str::{SmolStr, format_smolstr};
use std::time::Duration;

/// A gRPC request and metadata from an RPC call.
#[derive(Debug)]
pub struct Request<T> {
    metadata: MetadataMap,
    message: T,
    extensions: Extensions,
}

/// Trait implemented by RPC request types.
///
/// Types implementing this trait can be used as arguments to client RPC
/// methods without explicitly wrapping them into `rama_grpc::Request`s. The purpose
/// is to make client calls slightly more convenient to write.
///
/// Code generation and blanket implementations handle this for you,
/// so it is not necessary to implement this trait directly.
///
/// # Example
///
/// Given the following gRPC method definition:
/// ```proto
/// rpc GetFeature(Point) returns (Feature) {}
/// ```
///
/// we can call `get_feature` in two equivalent ways:
/// ```rust
/// # pub struct Point {}
/// # pub struct Client {}
/// # impl Client {
/// #   fn get_feature(&self, r: impl rama_grpc::IntoRequest<Point>) {}
/// # }
/// # let client = Client {};
/// use rama_grpc::Request;
///
/// client.get_feature(Point {});
/// client.get_feature(Request::new(Point {}));
/// ```
pub trait IntoRequest<T>: sealed::Sealed {
    /// Wrap the input message `T` in a `rama_grpc::Request`
    fn into_request(self) -> Request<T>;
}

/// Trait implemented by RPC streaming request types.
///
/// Types implementing this trait can be used as arguments to client streaming
/// RPC methods without explicitly wrapping them into `rama_grpc::Request`s. The
/// purpose is to make client calls slightly more convenient to write.
///
/// Code generation and blanket implementations handle this for you,
/// so it is not necessary to implement this trait directly.
///
/// # Example
///
/// Given the following gRPC service method definition:
/// ```proto
/// rpc RecordRoute(stream Point) returns (RouteSummary) {}
/// ```
/// we can call `record_route` in two equivalent ways:
///
/// ```rust
/// # #[derive(Clone)]
/// # pub struct Point {};
/// # pub struct Client {};
/// # impl Client {
/// #   fn record_route(&self, r: impl rama_grpc::IntoStreamingRequest<Message = Point>) {}
/// # }
/// # let client = Client {};
/// use rama_grpc::Request;
///
/// let messages = vec![Point {}, Point {}];
///
/// client.record_route(Request::new(rama_core::stream::iter(messages.clone())));
/// client.record_route(rama_core::stream::iter(messages));
/// ```
pub trait IntoStreamingRequest: sealed::Sealed {
    /// The RPC request stream type
    type Stream: Stream<Item = Self::Message> + Send + Sync + 'static;

    /// The RPC request type
    type Message;

    /// Wrap the stream of messages in a `rama_grpc::Request`
    fn into_streaming_request(self) -> Request<Self::Stream>;
}

impl<T> Request<T> {
    /// Create a new gRPC request.
    ///
    /// ```rust
    /// # use rama_grpc::Request;
    /// # pub struct HelloRequest {
    /// #   pub name: String,
    /// # }
    /// Request::new(HelloRequest {
    ///    name: "Bob".into(),
    /// });
    /// ```
    pub fn new(message: T) -> Self {
        Self {
            metadata: MetadataMap::new(),
            message,
            extensions: Extensions::new(),
        }
    }

    /// Get a reference to the message
    pub fn get_ref(&self) -> &T {
        &self.message
    }

    /// Get a mutable reference to the message
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.message
    }

    /// Get a reference to the custom request metadata.
    pub fn metadata(&self) -> &MetadataMap {
        &self.metadata
    }

    /// Get a mutable reference to the request metadata.
    pub fn metadata_mut(&mut self) -> &mut MetadataMap {
        &mut self.metadata
    }

    /// Consumes `self`, returning the message
    pub fn into_inner(self) -> T {
        self.message
    }

    /// Consumes `self` returning the parts of the request.
    pub fn into_parts(self) -> (MetadataMap, Extensions, T) {
        (self.metadata, self.extensions, self.message)
    }

    /// Create a new gRPC request from metadata, extensions and message.
    pub fn from_parts(metadata: MetadataMap, extensions: Extensions, message: T) -> Self {
        Self {
            metadata,
            extensions,
            message,
        }
    }

    pub(crate) fn from_http_parts(parts: rama_http_types::request::Parts, message: T) -> Self {
        Self {
            metadata: MetadataMap::from_headers(parts.headers),
            message,
            extensions: parts.extensions,
        }
    }

    /// Convert an HTTP request to a gRPC request
    pub fn from_http(http: rama_http_types::Request<T>) -> Self {
        let (parts, message) = http.into_parts();
        Self::from_http_parts(parts, message)
    }

    pub(crate) fn into_http(
        self,
        uri: rama_http_types::Uri,
        method: rama_http_types::Method,
        version: rama_http_types::Version,
        sanitize_headers: SanitizeHeaders,
    ) -> rama_http_types::Request<T> {
        let mut request = rama_http_types::Request::new(self.message);

        *request.version_mut() = version;
        *request.method_mut() = method;
        *request.uri_mut() = uri;
        *request.headers_mut() = match sanitize_headers {
            SanitizeHeaders::Yes => self.metadata.into_sanitized_headers(),
            SanitizeHeaders::No => self.metadata.into_headers(),
        };
        *request.extensions_mut() = self.extensions;

        if let header::Entry::Vacant(header) = request.headers_mut().entry(USER_AGENT) {
            header.insert(RAMA_ID_HEADER_VALUE.clone());
        }

        request
    }

    #[doc(hidden)]
    pub fn map<F, U>(self, f: F) -> Request<U>
    where
        F: FnOnce(T) -> U,
    {
        let message = f(self.message);

        Request {
            metadata: self.metadata,
            message,
            extensions: self.extensions,
        }
    }

    /// Set the max duration the request is allowed to take.
    ///
    /// Requires the server to support the `grpc-timeout` metadata, which rama-grpc does.
    ///
    /// The duration will be formatted according to [the spec] and use the most precise unit
    /// possible.
    ///
    /// [the spec]: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
    pub fn try_set_timeout(&mut self, deadline: Duration) -> Result<(), OpaqueError> {
        let value: MetadataValue<_> = duration_to_grpc_timeout(deadline)
            .context("format duration as grpc timeout")?
            .parse()
            .context("parse grpc timeout as ValueEncoding")?;
        self.metadata_mut()
            .insert(crate::metadata::GRPC_TIMEOUT_HEADER, value);
        Ok(())
    }
}

impl<T> ExtensionsRef for Request<T> {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<T> ExtensionsMut for Request<T> {
    fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }
}

impl<T> IntoRequest<T> for T {
    fn into_request(self) -> Request<Self> {
        Request::new(self)
    }
}

impl<T> IntoRequest<T> for Request<T> {
    fn into_request(self) -> Self {
        self
    }
}

impl<T> IntoStreamingRequest for T
where
    T: Stream + Send + Sync + 'static,
{
    type Stream = T;
    type Message = T::Item;

    fn into_streaming_request(self) -> Request<Self> {
        Request::new(self)
    }
}

impl<T> IntoStreamingRequest for Request<T>
where
    T: Stream + Send + Sync + 'static,
{
    type Stream = T;
    type Message = T::Item;

    fn into_streaming_request(self) -> Self {
        self
    }
}

impl<T> sealed::Sealed for T {}

mod sealed {
    pub trait Sealed {}
}

fn duration_to_grpc_timeout(duration: Duration) -> Option<SmolStr> {
    fn try_format<T: Into<u128>>(
        duration: Duration,
        unit: char,
        convert: impl FnOnce(Duration) -> T,
    ) -> Option<SmolStr> {
        // The gRPC spec specifies that the timeout most be at most 8 digits. So this is the largest a
        // value can be before we need to use a bigger unit.
        const MAX_SIZE: u128 = 99_999_999; // exactly 8 digits

        let value = convert(duration).into();
        if value > MAX_SIZE {
            None
        } else {
            Some(format_smolstr!("{value}{unit}"))
        }
    }

    // pick the most precise unit that is less than or equal to 8 digits as per the gRPC spec
    try_format(duration, 'n', |d| d.as_nanos())
        .or_else(|| try_format(duration, 'u', |d| d.as_micros()))
        .or_else(|| try_format(duration, 'm', |d| d.as_millis()))
        .or_else(|| try_format(duration, 'S', |d| d.as_secs()))
        .or_else(|| try_format(duration, 'M', |d| d.as_secs() / 60))
        .or_else(|| {
            try_format(duration, 'H', |d| {
                let minutes = d.as_secs() / 60;
                minutes / 60
            })
        })
}

/// When converting a `rama_grpc::Request` into a `http::Request` should reserved
/// headers be removed?
#[derive(Debug, Clone, Copy)]
pub(crate) enum SanitizeHeaders {
    Yes,
    No,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{MetadataKey, MetadataValue};

    #[test]
    fn reserved_headers_are_excluded() {
        let mut r = Request::new(1);

        for header in &MetadataMap::GRPC_RESERVED_HEADERS {
            r.metadata_mut().insert(
                MetadataKey::unchecked_from_header_name(header.clone()),
                MetadataValue::from_static("invalid"),
            );
        }

        let http_request = r.into_http(
            rama_http_types::Uri::default(),
            rama_http_types::Method::POST,
            rama_http_types::Version::HTTP_2,
            SanitizeHeaders::Yes,
        );
        assert_eq!(1, http_request.headers().len());
        assert!(http_request.headers().contains_key(USER_AGENT));
    }

    #[test]
    fn preserves_user_agent() {
        let mut r = Request::new(1);

        r.metadata_mut().insert(
            MetadataKey::from_static("user-agent"),
            MetadataValue::from_static("Custom/1.2.3"),
        );

        let http_request = r.into_http(
            rama_http_types::Uri::default(),
            rama_http_types::Method::POST,
            rama_http_types::Version::HTTP_2,
            SanitizeHeaders::Yes,
        );
        let user_agent = http_request.headers().get("user-agent").unwrap();
        assert_eq!(user_agent, "Custom/1.2.3");
    }

    #[test]
    fn duration_to_grpc_timeout_less_than_second() {
        let timeout = Duration::from_millis(500);
        let value = duration_to_grpc_timeout(timeout).unwrap();
        assert_eq!(value, format!("{}u", timeout.as_micros()));
    }

    #[test]
    fn duration_to_grpc_timeout_more_than_second() {
        let timeout = Duration::from_secs(30);
        let value = duration_to_grpc_timeout(timeout).unwrap();
        assert_eq!(value, format!("{}u", timeout.as_micros()));
    }

    #[test]
    fn duration_to_grpc_timeout_a_very_long_time() {
        let one_hour = Duration::from_secs(60 * 60);
        let value = duration_to_grpc_timeout(one_hour).unwrap();
        assert_eq!(value, format!("{}m", one_hour.as_millis()));
    }
}
