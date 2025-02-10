use rama_net::tls::client::ClientHello;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, Hash)]
pub struct TlsProfile {
    pub client_hello: ClientHello,
}
