use super::{Basic, Bearer};

#[derive(Debug, Clone)]
/// Proxy credentials.
pub enum ProxyCredentials {
    /// [`Basic`]` credentials.
    Basic(Basic),
    /// [`Bearer`] credentials.
    Bearer(Bearer),
}
