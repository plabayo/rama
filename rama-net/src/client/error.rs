use core::{convert::Infallible, fmt};

use rama_core::{
    error::{BoxError, ErrorExt as _, error_chain, extra::OpaqueError},
    telemetry::tracing,
};

/// The architectural domain in which establishing a client connection failed.
///
/// Domains describe the role a protocol or component plays in a connector stack
/// rather than assigning protocols to fixed OSI layers. For example, TLS to a
/// proxy is part of [`Transport`](Self::Transport), while TLS to the origin is
/// part of [`Application`](Self::Application).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConnectionErrorDomain {
    /// Establishing the usable transport path selected for the connection.
    ///
    /// This is the route-dependent domain. A route planner can generally use
    /// it as the signal that trying the next route may produce a different
    /// outcome.
    Transport,
    /// Establishing the end-to-end connection over the selected transport path.
    ///
    /// This is not limited to a strict OSI application-layer protocol. It also
    /// includes protocols and handshakes between the transport path and the final
    /// application protocol, such as TLS to the origin. Which domain a protocol
    /// belongs to depends on its role: TLS to a proxy is transport establishment,
    /// while TLS to the origin is end-to-end application establishment.
    /// A different transport route should not normally be tried for these
    /// failures because the selected route was already usable.
    Application,
    /// Client-local connection acquisition or orchestration failed.
    ///
    /// These failures originate in the connector stack itself rather than in a
    /// remote route or application peer. Examples include invalid local
    /// configuration or input, connection-pool bookkeeping failures, exhaustion
    /// of a local resource, and cancellation of the overall connection attempt.
    /// These failures are not specific to a selected route.
    Local,
    /// The failure has not been classified. Consumers should not assume that
    /// trying another route is safe merely because the domain is unknown.
    Unknown,
}

impl fmt::Display for ConnectionErrorDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Transport => "transport",
            Self::Application => "application",
            Self::Local => "local",
            Self::Unknown => "unknown",
        })
    }
}

/// A protocol-independent description of what prevented connection setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConnectionErrorKind {
    /// An endpoint, route, or required resource was unavailable.
    Unavailable,
    /// Connection setup exceeded its allowed duration.
    Timeout,
    /// A peer explicitly rejected the connection operation.
    Rejected,
    /// Connection setup requires authentication or authentication failed.
    Authentication,
    /// A protocol handshake or negotiation failed.
    Protocol,
    /// The connection input or configuration is invalid.
    InvalidInput,
    /// Local connection machinery failed unexpectedly.
    Internal,
    /// The failure does not fit another kind.
    Other,
}

impl fmt::Display for ConnectionErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "unavailable",
            Self::Timeout => "timeout",
            Self::Rejected => "rejected",
            Self::Authentication => "authentication",
            Self::Protocol => "protocol",
            Self::InvalidInput => "invalid-input",
            Self::Internal => "internal",
            Self::Other => "other",
        })
    }
}

/// A classified error produced while establishing a client connection.
///
/// The original error remains available as the source. Adding context only
/// wraps that source and therefore preserves the classification.
#[must_use = "a connection error should be returned or handled"]
pub struct ConnectionError {
    source: BoxError,
    domain: ConnectionErrorDomain,
    kind: ConnectionErrorKind,
}

impl ConnectionError {
    /// Create a classified connection error.
    pub fn new(
        source: impl Into<BoxError>,
        domain: ConnectionErrorDomain,
        kind: ConnectionErrorKind,
    ) -> Self {
        Self {
            source: source.into(),
            domain,
            kind,
        }
    }

    /// Create an error which occurred while establishing the transport path.
    pub fn transport(source: impl Into<BoxError>, kind: ConnectionErrorKind) -> Self {
        Self::new(source, ConnectionErrorDomain::Transport, kind)
    }

    /// Create an error which occurred while establishing the end-to-end connection.
    ///
    /// This includes intermediate end-to-end protocols such as TLS to the origin,
    /// not only the final application protocol.
    pub fn application(source: impl Into<BoxError>, kind: ConnectionErrorKind) -> Self {
        Self::new(source, ConnectionErrorDomain::Application, kind)
    }

    /// Create an error produced by client-local acquisition or orchestration machinery.
    pub fn local(source: impl Into<BoxError>, kind: ConnectionErrorKind) -> Self {
        Self::new(source, ConnectionErrorDomain::Local, kind)
    }

    /// Create an unclassified connection error.
    pub fn unknown(source: impl Into<BoxError>) -> Self {
        Self::new(
            source,
            ConnectionErrorDomain::Unknown,
            ConnectionErrorKind::Other,
        )
    }

    /// Return the architectural domain in which the failure occurred.
    #[inline]
    pub fn domain(&self) -> ConnectionErrorDomain {
        self.domain
    }

    /// Return the protocol-independent kind of failure.
    #[inline]
    pub fn kind(&self) -> ConnectionErrorKind {
        self.kind
    }

    /// Return the original error, including any attached context.
    #[inline]
    pub fn get_ref(&self) -> &(dyn core::error::Error + Send + Sync + 'static) {
        self.source.as_ref()
    }

    /// Consume this error and return its boxed source.
    #[inline]
    pub fn into_source(self) -> BoxError {
        self.source
    }

    /// Convert this error into a [`BoxError`] without losing its classification.
    #[inline]
    pub fn into_box_error(self) -> BoxError {
        Box::new(self)
    }

    /// Convert this error into an [`OpaqueError`] without losing its classification.
    #[inline]
    pub fn into_opaque_error(self) -> OpaqueError {
        self.into_box_error().into_opaque_error()
    }

    /// Add context to the source error.
    pub fn context<M>(mut self, value: M) -> Self
    where
        M: fmt::Debug + fmt::Display + Send + Sync + 'static,
    {
        self.source = self.source.context(value);
        self
    }

    /// Add context using [`fmt::LowerHex`] for its formatting.
    pub fn context_hex<M>(mut self, value: M) -> Self
    where
        M: fmt::Debug + Send + Sync + 'static,
    {
        self.source = self.source.context_hex(value);
        self
    }

    /// Add context using [`fmt::Debug`] for its display formatting.
    pub fn context_debug<M>(mut self, value: M) -> Self
    where
        M: fmt::Debug + Send + Sync + 'static,
    {
        self.source = self.source.context_debug(value);
        self
    }

    /// Add keyed context to the source error.
    pub fn context_field<M>(mut self, key: &'static str, value: M) -> Self
    where
        M: fmt::Debug + fmt::Display + Send + Sync + 'static,
    {
        self.source = self.source.context_field(key, value);
        self
    }

    /// Add a keyed string-like context value to the source error.
    pub fn context_str_field<M>(mut self, key: &'static str, value: M) -> Self
    where
        M: Into<String>,
    {
        self.source = self.source.context_str_field(key, value);
        self
    }

    /// Add keyed context using [`fmt::LowerHex`] for its formatting.
    pub fn context_hex_field<M>(mut self, key: &'static str, value: M) -> Self
    where
        M: fmt::Debug + Send + Sync + 'static,
    {
        self.source = self.source.context_hex_field(key, value);
        self
    }

    /// Add keyed context using [`fmt::Debug`] for its display formatting.
    pub fn context_debug_field<M>(mut self, key: &'static str, value: M) -> Self
    where
        M: fmt::Debug + Send + Sync + 'static,
    {
        self.source = self.source.context_debug_field(key, value);
        self
    }

    /// Lazily add context to the source error.
    pub fn with_context<C, F>(mut self, create: F) -> Self
    where
        C: fmt::Debug + fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.source = self.source.with_context(create);
        self
    }

    /// Lazily add context using [`fmt::LowerHex`] for its formatting.
    pub fn with_context_hex<C, F>(mut self, create: F) -> Self
    where
        C: fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.source = self.source.with_context_hex(create);
        self
    }

    /// Lazily add context using [`fmt::Debug`] for its display formatting.
    pub fn with_context_debug<C, F>(mut self, create: F) -> Self
    where
        C: fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.source = self.source.with_context_debug(create);
        self
    }

    /// Lazily add keyed context to the source error.
    pub fn with_context_field<C, F>(mut self, key: &'static str, create: F) -> Self
    where
        C: fmt::Debug + fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.source = self.source.with_context_field(key, create);
        self
    }

    /// Lazily add a keyed string-like context value to the source error.
    pub fn with_context_str_field<C, F>(mut self, key: &'static str, create: F) -> Self
    where
        C: Into<String>,
        F: FnOnce() -> C,
    {
        self.source = self.source.with_context_str_field(key, create);
        self
    }

    /// Lazily add keyed context using [`fmt::LowerHex`] for its formatting.
    pub fn with_context_hex_field<C, F>(mut self, key: &'static str, create: F) -> Self
    where
        C: fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.source = self.source.with_context_hex_field(key, create);
        self
    }

    /// Lazily add keyed context using [`fmt::Debug`] for its display formatting.
    pub fn with_context_debug_field<C, F>(mut self, key: &'static str, create: F) -> Self
    where
        C: fmt::Debug + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.source = self.source.with_context_debug_field(key, create);
        self
    }

    /// Capture a backtrace and attach it to the source error.
    pub fn backtrace(mut self) -> Self {
        self.source = self.source.backtrace();
        self
    }

    fn classification_in_source_chain(
        source: &(dyn core::error::Error + 'static),
    ) -> Option<(ConnectionErrorDomain, ConnectionErrorKind)> {
        let mut timeout = false;
        // Protect conversion from a malformed error implementation with a cyclic
        // source chain. Rama's own wrappers are shallow and acyclic.
        for error in error_chain(source, 64) {
            if let Some(error) = error.downcast_ref::<Self>() {
                return Some((error.domain, error.kind));
            }
            timeout |= error.is::<rama_core::layer::timeout::Elapsed>()
                || error.is::<tokio::time::error::Elapsed>();
        }
        timeout.then_some((
            ConnectionErrorDomain::Transport,
            ConnectionErrorKind::Timeout,
        ))
    }
}

impl From<BoxError> for ConnectionError {
    fn from(source: BoxError) -> Self {
        let source = match source.downcast::<Self>() {
            Ok(error) => return *error,
            Err(source) => source,
        };

        let (domain, kind) =
            Self::classification_in_source_chain(source.as_ref()).unwrap_or_else(|| {
                tracing::debug!(
                    "connector error is unclassified; retry-based routing will treat it as terminal"
                );
                (ConnectionErrorDomain::Unknown, ConnectionErrorKind::Other)
            });

        Self {
            source,
            domain,
            kind,
        }
    }
}

impl From<Infallible> for ConnectionError {
    fn from(error: Infallible) -> Self {
        match error {}
    }
}

impl fmt::Debug for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionError")
            .field("domain", &self.domain)
            .field("kind", &self.kind)
            .field("source", &self.source)
            .finish()
    }
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, f)
    }
}

impl core::error::Error for ConnectionError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::{Layer, Service, error::ErrorContext as _};

    #[derive(Debug)]
    struct TestError(&'static str);

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl core::error::Error for TestError {}

    #[derive(Debug)]
    struct CyclicError;

    impl fmt::Display for CyclicError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("cyclic error")
        }
    }

    impl core::error::Error for CyclicError {
        fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
            Some(self)
        }
    }

    fn unavailable_transport_error() -> ConnectionError {
        ConnectionError::transport(
            TestError("connect failed"),
            ConnectionErrorKind::Unavailable,
        )
    }

    fn assert_unavailable_transport(error: &ConnectionError) {
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
    }

    #[test]
    fn display_preserves_source_message() {
        let error = unavailable_transport_error();
        assert_eq!(error.to_string(), "connect failed");
        assert!(error.get_ref().is::<TestError>());
    }

    #[test]
    fn direct_box_roundtrip_preserves_classification() {
        let error = ConnectionError::from(unavailable_transport_error().into_box_error());
        assert_unavailable_transport(&error);
        assert!(error.get_ref().is::<TestError>());
    }

    #[test]
    fn contextual_box_roundtrip_preserves_classification() {
        let boxed = unavailable_transport_error()
            .into_box_error()
            .context("dial selected endpoint")
            .context_field("attempt", 2);

        let error = ConnectionError::from(boxed);
        assert_unavailable_transport(&error);
        let message = error.to_string();
        assert!(message.contains("dial selected endpoint"), "{message}");
        assert!(message.contains("attempt=\"2\""), "{message}");
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_layer_error_is_classified_as_transport_timeout() {
        let source =
            rama_core::layer::timeout::TimeoutLayer::new(core::time::Duration::from_secs(1));
        let error = source
            .into_layer(rama_core::service::service_fn(async |(): ()| {
                core::future::pending::<Result<(), Infallible>>().await
            }))
            .serve(())
            .await
            .unwrap_err();

        let error = ConnectionError::from(error.context("connector attempt"));
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Timeout);
    }

    #[test]
    fn result_context_roundtrip_preserves_classification() {
        fn contextualized() -> Result<(), ConnectionError> {
            let result: Result<(), ConnectionError> = Err(unavailable_transport_error());
            result.context("establish connection")?;
            Ok(())
        }

        let error = contextualized().unwrap_err();
        assert_unavailable_transport(&error);
        assert!(error.to_string().contains("establish connection"));
    }

    #[test]
    fn inherent_context_api_preserves_classification() {
        let error = unavailable_transport_error()
            .context("context")
            .context_hex(255)
            .context_debug(Some("debug"))
            .context_field("field", 1)
            .context_str_field("str", "value")
            .context_hex_field("hex", 255)
            .context_debug_field("debug", Some(2))
            .with_context(|| "lazy-context")
            .with_context_hex(|| 16)
            .with_context_debug(|| Some("lazy-debug"))
            .with_context_field("lazy-field", || 3)
            .with_context_str_field("lazy-str", || "lazy-value")
            .with_context_hex_field("lazy-hex", || 32)
            .with_context_debug_field("lazy-debug-field", || Some(4));

        assert_unavailable_transport(&error);
        let message = error.to_string();
        for expected in [
            "context",
            "field=\"1\"",
            "str=\"value\"",
            "lazy-context",
            "lazy-field=\"3\"",
            "lazy-str=\"lazy-value\"",
        ] {
            assert!(
                message.contains(expected),
                "missing {expected:?} in {message}"
            );
        }
    }

    #[test]
    fn unknown_box_error_gets_safe_classification() {
        let source: BoxError = Box::new(TestError("legacy error"));
        let error = ConnectionError::from(source);

        assert_eq!(error.domain(), ConnectionErrorDomain::Unknown);
        assert_eq!(error.kind(), ConnectionErrorKind::Other);
        assert_eq!(error.to_string(), "legacy error");
    }

    #[test]
    fn cyclic_source_chain_gets_safe_classification() {
        let source: BoxError = Box::new(CyclicError);
        let error = ConnectionError::from(source);

        assert_eq!(error.domain(), ConnectionErrorDomain::Unknown);
        assert_eq!(error.kind(), ConnectionErrorKind::Other);
        assert_eq!(error.to_string(), "cyclic error");
    }

    #[test]
    fn backtrace_and_opaque_roundtrip_preserve_classification() {
        let opaque = unavailable_transport_error()
            .backtrace()
            .into_opaque_error();
        let error = ConnectionError::from(opaque.into_box_error());

        assert_unavailable_transport(&error);
        assert_eq!(error.to_string(), "connect failed");
    }
}
