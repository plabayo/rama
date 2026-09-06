use std::fmt;

use rama_core::error::{BoxError, error_chain_with};
use rama_http_types::{StatusCode, Version};
use rama_net::client::{ConnectionError, ConnectionErrorDomain, ConnectionErrorKind};

#[derive(Debug)]
/// Error returned while establishing an HTTP proxy tunnel.
pub enum HttpProxyError {
    /// Proxy authentication required during CONNECT.
    ///
    /// (Proxy returned HTTP 407)
    AuthRequired,
    /// Proxy is Unavailable
    ///
    /// (Proxy returned HTTP 503)
    Unavailable,
    /// I/O error happened as part of HTTP Proxy Connection Establishment
    ///
    /// (e.g. some kind of TCP error)
    Transport(BoxError),
    /// The configured HTTP version cannot establish a CONNECT tunnel.
    InvalidVersion(Version),
    /// The proxy rejected CONNECT with an unexpected response status.
    Rejected(StatusCode),
    /// The proxy reached the requested upstream but could not establish the
    /// tunnel (HTTP 502 or 504).
    UpstreamFailure(StatusCode),
}

impl fmt::Display for HttpProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthRequired => {
                write!(f, "http proxy error: proxy auth required (http 407)")
            }
            Self::Unavailable => {
                write!(f, "http proxy error: proxy unavailable (http 503)")
            }
            Self::Transport(error) => {
                write!(f, "http proxy error: transport error: I/O [{error}]")
            }
            Self::InvalidVersion(version) => {
                write!(f, "http proxy error: invalid CONNECT version: {version:?}")
            }
            Self::Rejected(status) => {
                write!(f, "http proxy error: CONNECT rejected with status {status}")
            }
            Self::UpstreamFailure(status) => {
                write!(
                    f,
                    "http proxy error: CONNECT upstream failed with status {status}"
                )
            }
        }
    }
}

impl From<HttpProxyError> for ConnectionError {
    fn from(error: HttpProxyError) -> Self {
        let (domain, kind) = match &error {
            HttpProxyError::AuthRequired => (
                ConnectionErrorDomain::Transport,
                ConnectionErrorKind::Authentication,
            ),
            HttpProxyError::Unavailable => (
                ConnectionErrorDomain::Transport,
                ConnectionErrorKind::Unavailable,
            ),
            HttpProxyError::Transport(source) => (
                ConnectionErrorDomain::Transport,
                classify_handshake_error(source.as_ref()),
            ),
            HttpProxyError::Rejected(_) => (
                ConnectionErrorDomain::Transport,
                ConnectionErrorKind::Rejected,
            ),
            // A 502/504 CONNECT response says the selected proxy did reach the
            // requested upstream. Treat it as destination-scoped so an
            // ordered proxy plan does not amplify the same origin failure.
            HttpProxyError::UpstreamFailure(_) => (
                ConnectionErrorDomain::Application,
                ConnectionErrorKind::Unavailable,
            ),
            HttpProxyError::InvalidVersion(_) => (
                ConnectionErrorDomain::Local,
                ConnectionErrorKind::InvalidInput,
            ),
        };

        Self::new(error, domain, kind)
    }
}

fn classify_handshake_error(error: &(dyn std::error::Error + 'static)) -> ConnectionErrorKind {
    let mut kind = ConnectionErrorKind::Protocol;
    // Unknown handshake failures must not permit implicit DIRECT fallback.
    // Inspect causes before accepting a closed/canceled outer HTTP operation:
    // an H2 protocol error may be wrapped in just such an operation.
    for error in error_chain_with(error, 32, handshake_source) {
        if let Some(http) = error.downcast_ref::<rama_http_core::Error>() {
            if http.is_parse() || http.is_user() {
                return ConnectionErrorKind::Protocol;
            }
            if http.is_timeout() {
                kind = ConnectionErrorKind::Timeout;
            } else if http.is_closed() || http.is_canceled() || http.is_incomplete_message() {
                kind = ConnectionErrorKind::Unavailable;
            }
        }
        if let Some(h2) = error.downcast_ref::<rama_http_core::h2::Error>()
            && h2.get_io().is_none()
        {
            return ConnectionErrorKind::Protocol;
        }
        if let Some(io) = error.downcast_ref::<std::io::Error>() {
            kind = if io.kind() == std::io::ErrorKind::TimedOut {
                ConnectionErrorKind::Timeout
            } else if rama_net::conn::is_connection_error(io) {
                ConnectionErrorKind::Unavailable
            } else {
                ConnectionErrorKind::Protocol
            };
        }
    }
    kind
}

fn handshake_source<'a>(
    error: &'a (dyn std::error::Error + 'static),
) -> Option<&'a (dyn std::error::Error + 'static)> {
    // H2 and I/O errors can retain a cause that Error::source does not expose.
    if let Some(h2) = error.downcast_ref::<rama_http_core::h2::Error>()
        && let Some(io) = h2.get_io()
    {
        return Some(io);
    }
    if let Some(io) = error.downcast_ref::<std::io::Error>()
        && let Some(source) = io.get_ref()
    {
        return Some(source);
    }
    error.source()
}

impl From<std::io::Error> for HttpProxyError {
    fn from(value: std::io::Error) -> Self {
        Self::Transport(value.into())
    }
}

impl std::error::Error for HttpProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let Self::Transport(err) = self else {
            return None;
        };

        // filter out generic io errors,
        // but do allow custom errors (e.g. because IP is blocked)
        let err_ref = err.source().unwrap_or_else(|| err.as_ref());
        if err_ref.is::<std::io::Error>() {
            Some(self)
        } else {
            Some(err_ref)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn closed_and_canceled_http_dispatch_remain_unavailable() {
        for wait_ready in [false, true] {
            let (io, _peer) = tokio::io::duplex(1024);
            let (mut sender, driver) = rama_http_core::client::conn::http1::handshake::<
                _,
                rama_http_types::Body,
            >(rama_core::ServiceInput::new(io))
            .await
            .unwrap();
            drop(driver);
            let error = if wait_ready {
                let error = sender.ready().await.unwrap_err();
                assert!(error.is_closed());
                error
            } else {
                let request = rama_http_types::Request::connect(
                    rama_net::uri::Uri::parse_authority_form("example.com:443").unwrap(),
                )
                .body(rama_http_types::Body::empty())
                .unwrap();
                let error = sender.send_request(request).await.unwrap_err();
                assert!(error.is_canceled());
                error
            };
            let error = ConnectionError::from(HttpProxyError::Transport(error.into()));
            assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
            assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
        }
    }

    #[test]
    fn classifies_handshake_protocol_and_io_errors() {
        for (source, expected) in [
            (
                BoxError::from(rama_http_core::h2::Error::from(
                    rama_http_core::h2::Reason::PROTOCOL_ERROR,
                )),
                ConnectionErrorKind::Protocol,
            ),
            (
                BoxError::from(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
                ConnectionErrorKind::Unavailable,
            ),
            (
                BoxError::from(std::io::Error::from(std::io::ErrorKind::TimedOut)),
                ConnectionErrorKind::Timeout,
            ),
            (
                BoxError::from(std::io::Error::from(std::io::ErrorKind::InvalidData)),
                ConnectionErrorKind::Protocol,
            ),
            (
                BoxError::from(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
                ConnectionErrorKind::Protocol,
            ),
            (
                BoxError::from(std::io::Error::other(rama_http_core::h2::Error::from(
                    rama_http_core::h2::Reason::PROTOCOL_ERROR,
                ))),
                ConnectionErrorKind::Protocol,
            ),
            (
                BoxError::from("unknown handshake failure"),
                ConnectionErrorKind::Protocol,
            ),
        ] {
            let error = ConnectionError::from(HttpProxyError::Transport(source));
            assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
            assert_eq!(error.kind(), expected);
        }
    }

    #[test]
    fn handshake_classification_inspects_hidden_io_causes() {
        use std::io::{Error, ErrorKind};

        for (outer, inner, expected) in [
            (
                ErrorKind::ConnectionRefused,
                ErrorKind::InvalidData,
                ConnectionErrorKind::Protocol,
            ),
            (
                ErrorKind::InvalidData,
                ErrorKind::ConnectionRefused,
                ConnectionErrorKind::Unavailable,
            ),
            (
                ErrorKind::ConnectionRefused,
                ErrorKind::TimedOut,
                ConnectionErrorKind::Timeout,
            ),
            (
                ErrorKind::TimedOut,
                ErrorKind::ConnectionRefused,
                ConnectionErrorKind::Unavailable,
            ),
        ] {
            let error = Error::new(outer, Error::from(inner));
            assert_eq!(classify_handshake_error(&error), expected);
        }

        let error = Error::new(
            ErrorKind::ConnectionRefused,
            rama_http_core::h2::Error::from(rama_http_core::h2::Reason::PROTOCOL_ERROR),
        );
        assert_eq!(
            classify_handshake_error(&error),
            ConnectionErrorKind::Protocol
        );

        let error = Error::new(ErrorKind::ConnectionRefused, "unknown cause");
        assert_eq!(
            classify_handshake_error(&error),
            ConnectionErrorKind::Unavailable
        );
    }

    #[tokio::test]
    async fn handshake_classification_inspects_hidden_h2_io_cause() {
        let (io, peer) = tokio::io::duplex(64);
        drop(peer);
        let error = rama_http_core::h2::client::handshake(rama_core::ServiceInput::new(io))
            .await
            .unwrap_err();
        assert_eq!(
            error.get_io().unwrap().kind(),
            std::io::ErrorKind::BrokenPipe
        );
        assert!(std::error::Error::source(&error).is_none());

        let error = ConnectionError::from(HttpProxyError::Transport(error.into()));
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
    }

    #[test]
    fn handshake_classification_bounds_hidden_causes() {
        for (depth, expected) in [
            (32, ConnectionErrorKind::Protocol),
            (33, ConnectionErrorKind::Unavailable),
        ] {
            let mut error = std::io::Error::from(std::io::ErrorKind::InvalidData);
            for _ in 1..depth {
                error = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, error);
            }
            assert_eq!(classify_handshake_error(&error), expected, "depth {depth}");
        }
    }

    #[test]
    fn classifies_proxy_responses() {
        let error = ConnectionError::from(HttpProxyError::AuthRequired);
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Authentication);

        let error = ConnectionError::from(HttpProxyError::Unavailable);
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);

        let error = ConnectionError::from(HttpProxyError::Rejected(StatusCode::FORBIDDEN));
        assert_eq!(error.domain(), ConnectionErrorDomain::Transport);
        assert_eq!(error.kind(), ConnectionErrorKind::Rejected);

        for status in [StatusCode::BAD_GATEWAY, StatusCode::GATEWAY_TIMEOUT] {
            let proxy_error = HttpProxyError::UpstreamFailure(status);
            assert_eq!(
                proxy_error.to_string(),
                format!("http proxy error: CONNECT upstream failed with status {status}")
            );
            let error = ConnectionError::from(proxy_error);
            assert_eq!(error.domain(), ConnectionErrorDomain::Application);
            assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
        }

        let error = ConnectionError::from(HttpProxyError::InvalidVersion(Version::HTTP_3));
        assert_eq!(error.domain(), ConnectionErrorDomain::Local);
        assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
    }
}
