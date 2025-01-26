use rama_net::tls::client::ClientHello;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "memory-db", derive(venndb::VennDB))]
pub struct TlsProfile {
    #[cfg_attr(feature = "memory-db", venndb(key))]
    pub ja4: String,
    pub client_hello: ClientHello,
}
