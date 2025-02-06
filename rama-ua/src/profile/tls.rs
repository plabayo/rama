use rama_net::tls::client::ClientHello;
use serde::{Deserialize, Serialize};

use highway::HighwayHasher;

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct UserAgentTlsProfile {
    pub ua_kind: UserAgentKind,
    pub ua_kind_version: usize,
    pub platform_kind: PlatformKind,
    pub tls: TlsProfile,
}

impl UserAgentTlsProfile {
    pub fn key(&self) -> u64 {
        let mut hasher = HighwayHasher::default();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Hash)]
pub struct TlsProfile {
    pub ja4: String,
    pub client_hello: ClientHello,
}
