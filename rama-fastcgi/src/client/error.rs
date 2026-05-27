use std::fmt;

use rama_core::error::BoxError;

use crate::proto::ProtocolError;

/// Error returned by FastCGI client framing operations.
///
/// The variants that carry a [`ProtocolStatus`][crate::proto::ProtocolStatus] —
/// [`ClientError::is_overloaded`], [`ClientError::is_cant_mpx_conn`], and
/// [`ClientError::is_unknown_role`] — are returned when the backend application
/// sends a non-`RequestComplete` status in its `FCGI_END_REQUEST` record. They
/// can be detected and used to drive retry or failover logic at a higher layer.
#[derive(Debug)]
pub struct ClientError {
    pub(super) kind: ClientErrorKind,
    pub(super) source: Option<BoxError>,
}

#[derive(Debug)]
pub(super) enum ClientErrorKind {
    IO,
    Protocol,
    /// Backend sent `FCGI_END_REQUEST` with `FCGI_OVERLOADED`.
    Overloaded,
    /// Backend sent `FCGI_END_REQUEST` with `FCGI_CANT_MPX_CONN`.
    CantMpxConn,
    /// Backend sent `FCGI_END_REQUEST` with `FCGI_UNKNOWN_ROLE`.
    UnknownRole,
}

impl ClientError {
    pub(super) fn io(err: std::io::Error) -> Self {
        Self {
            kind: ClientErrorKind::IO,
            source: Some(err.into()),
        }
    }

    pub(super) fn protocol(err: ProtocolError) -> Self {
        Self {
            kind: ClientErrorKind::Protocol,
            source: Some(err.into()),
        }
    }

    /// Returns `true` if the backend reported it is temporarily overloaded.
    ///
    /// A retry layer may use this to route the request to a different backend.
    pub fn is_overloaded(&self) -> bool {
        matches!(self.kind, ClientErrorKind::Overloaded)
    }

    /// Returns `true` if the backend cannot handle concurrent requests on this
    /// connection (`FCGI_CANT_MPX_CONN`).
    ///
    /// The caller should open a fresh connection and resend the request.
    pub fn is_cant_mpx_conn(&self) -> bool {
        matches!(self.kind, ClientErrorKind::CantMpxConn)
    }

    /// Returns `true` if the backend did not recognise the requested role.
    pub fn is_unknown_role(&self) -> bool {
        matches!(self.kind, ClientErrorKind::UnknownRole)
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ClientErrorKind::IO => write!(f, "fastcgi client: I/O error"),
            ClientErrorKind::Protocol => write!(f, "fastcgi client: protocol error"),
            ClientErrorKind::Overloaded => {
                write!(f, "fastcgi client: backend is overloaded (FCGI_OVERLOADED)")
            }
            ClientErrorKind::CantMpxConn => write!(
                f,
                "fastcgi client: connection cannot be multiplexed (FCGI_CANT_MPX_CONN)"
            ),
            ClientErrorKind::UnknownRole => write!(
                f,
                "fastcgi client: backend does not recognise the role (FCGI_UNKNOWN_ROLE)"
            ),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().and_then(|e| e.source())
    }
}
