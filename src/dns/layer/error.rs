use crate::net::address::Authority;

/// Error type returned by the [`DnsService`].
///
/// [`DnsService`]: crate::dns::layer::DnsService
#[derive(Debug)]
pub enum DnsError<E> {
    /// The hostname was not found in the request, while it was required.
    HostnameNotFound,
    /// The hostname could not be mapped, for some unknown reason.
    MappingNotFound(Option<Authority>),
    /// A used header was invalid.
    InvalidHeader(String),
    /// An error occurred while dynamically resolving the hostname.
    DynamicResolveError(std::io::Error),
    /// An error occurred by the internal [`Service`] wrapped and called by
    /// the [`DnsService`].
    ///
    /// [`Service`]: crate::service::Service
    /// [`DnsService`]: crate::dns::layer::DnsService
    ServiceError(E),
}

impl<E> std::fmt::Display for DnsError<E>
where
    E: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::HostnameNotFound => write!(f, "hostname not found"),
            DnsError::MappingNotFound(host) => write!(f, "mapping not found: {:?}", host),
            DnsError::InvalidHeader(header) => write!(f, "invalid header: {}", header),
            DnsError::DynamicResolveError(err) => write!(f, "dynamic resolve error: {}", err),
            DnsError::ServiceError(err) => write!(f, "service error: {}", err),
        }
    }
}

impl<E> std::error::Error for DnsError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DnsError::DynamicResolveError(err) => Some(err),
            DnsError::ServiceError(err) => Some(err),
            _ => None,
        }
    }
}

impl<E> From<std::io::Error> for DnsError<E> {
    fn from(err: std::io::Error) -> Self {
        DnsError::DynamicResolveError(err)
    }
}
