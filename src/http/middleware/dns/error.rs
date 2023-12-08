#[derive(Debug)]
pub enum DnsError {
    HostnameNotFound,
    MappingNotFound(String),
    DynamicResolveError(std::io::Error),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::HostnameNotFound => write!(f, "hostname not found"),
            DnsError::MappingNotFound(host) => write!(f, "mapping not found: {}", host),
            DnsError::DynamicResolveError(err) => write!(f, "dynamic resolve error: {}", err),
        }
    }
}

impl std::error::Error for DnsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DnsError::DynamicResolveError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for DnsError {
    fn from(err: std::io::Error) -> Self {
        DnsError::DynamicResolveError(err)
    }
}

pub type DnsResult<T> = std::result::Result<T, DnsError>;
