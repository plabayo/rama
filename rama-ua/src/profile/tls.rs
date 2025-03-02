use std::sync::Arc;

use rama_net::tls::client::{ClientConfig, ClientHello, ServerVerifyMode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct TlsProfile {
    pub client_config: Arc<ClientConfig>,
}

impl<'de> Deserialize<'de> for TlsProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let input = TlsProfileSerde::deserialize(deserializer)?;
        let mut cfg = ClientConfig::from(input.client_hello);
        if input.insecure {
            cfg.server_verify_mode = Some(ServerVerifyMode::Disable);
        }
        Ok(Self {
            client_config: Arc::new(cfg),
        })
    }
}

impl Serialize for TlsProfile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let insecure = matches!(
            self.client_config.server_verify_mode,
            Some(ServerVerifyMode::Disable)
        );
        TlsProfileSerde {
            client_hello: self.client_config.as_ref().clone().into(),
            insecure,
        }
        .serialize(serializer)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TlsProfileSerde {
    client_hello: ClientHello,
    insecure: bool,
}
