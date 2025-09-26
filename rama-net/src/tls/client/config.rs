use std::sync::Arc;

use rama_core::{combinators::Either3, extensions::Extensions};

use super::{ClientHelloExtension, merge_client_hello_lists};
use crate::tls::{CipherSuite, CompressionAlgorithm, DataEncoding, KeyLogIntent, ProtocolVersion};

#[derive(Debug, Clone, Default)]
pub struct ClientConfigChain {
    configs: Vec<Arc<ClientConfig>>,
}

#[derive(Debug)]
pub struct ClientConfigChainRef<'a> {
    data: ClientConfigChainRefData<'a>,
}

impl ClientConfigChainRef<'_> {
    pub fn append(&mut self, cfg: impl Into<Arc<ClientConfig>>) {
        let mut data = ClientConfigChainRefData::Dummy;
        std::mem::swap(&mut self.data, &mut data);
        self.data = data.append(cfg);
    }

    pub fn prepend(&mut self, cfg: impl Into<Arc<ClientConfig>>) {
        let mut data = ClientConfigChainRefData::Dummy;
        std::mem::swap(&mut self.data, &mut data);
        self.data = data.prepend(cfg);
    }

    pub fn into_owned(self) -> ClientConfigChain {
        match self.data {
            ClientConfigChainRefData::Chain(client_config_chain) => ClientConfigChain {
                configs: client_config_chain.configs.clone(),
            },
            ClientConfigChainRefData::Single(client_config) => ClientConfigChain {
                configs: vec![client_config.clone()],
            },
            ClientConfigChainRefData::Owned(configs) => ClientConfigChain { configs },
            ClientConfigChainRefData::Dummy => unreachable!(),
        }
    }
    pub fn iter(&self) -> impl Iterator<Item = &ClientConfig> {
        match &self.data {
            ClientConfigChainRefData::Chain(client_config_chain) => {
                Either3::A(client_config_chain.configs.iter().map(|a| a.as_ref()))
            }
            ClientConfigChainRefData::Single(client_config) => {
                Either3::B(std::iter::once(client_config.as_ref()))
            }
            ClientConfigChainRefData::Owned(configs) => {
                Either3::C(configs.iter().map(|a| a.as_ref()))
            }
            ClientConfigChainRefData::Dummy => unreachable!(),
        }
    }
}

#[derive(Debug)]
enum ClientConfigChainRefData<'a> {
    Chain(&'a ClientConfigChain),
    Single(&'a Arc<ClientConfig>),
    Owned(Vec<Arc<ClientConfig>>),
    Dummy,
}

impl ClientConfigChainRefData<'_> {
    fn append(self, cfg: impl Into<Arc<ClientConfig>>) -> Self {
        let mut configs = match self {
            ClientConfigChainRefData::Chain(client_config_chain) => {
                client_config_chain.configs.clone()
            }
            ClientConfigChainRefData::Single(client_config) => vec![client_config.clone()],
            ClientConfigChainRefData::Owned(client_configs) => client_configs,
            ClientConfigChainRefData::Dummy => unreachable!(),
        };
        configs.push(cfg.into());
        ClientConfigChainRefData::Owned(configs)
    }

    fn prepend(self, cfg: impl Into<Arc<ClientConfig>>) -> Self {
        ClientConfigChainRefData::Owned(match self {
            ClientConfigChainRefData::Chain(client_config_chain) => {
                let mut v = Vec::with_capacity(client_config_chain.configs.len() + 1);
                v.push(cfg.into());
                v.extend(client_config_chain.configs.iter().cloned());
                v
            }
            ClientConfigChainRefData::Single(client_config) => {
                vec![cfg.into(), client_config.clone()]
            }
            ClientConfigChainRefData::Owned(client_configs) => {
                let mut v = Vec::with_capacity(client_configs.len() + 1);
                v.push(cfg.into());
                v.extend(client_configs);
                v
            }
            ClientConfigChainRefData::Dummy => unreachable!(),
        })
    }
}

#[must_use]
pub fn extract_client_config_from_extensions(ext: &Extensions) -> Option<ClientConfigChainRef<'_>> {
    match ext.get::<ClientConfigChain>() {
        Some(chain) => Some(ClientConfigChainRef {
            data: ClientConfigChainRefData::Chain(chain),
        }),
        None => ext
            .get::<Arc<ClientConfig>>()
            .map(|cfg| ClientConfigChainRef {
                data: ClientConfigChainRefData::Single(cfg),
            }),
    }
}

pub fn append_client_config_to_extensions(ext: &mut Extensions, cfg: impl Into<Arc<ClientConfig>>) {
    match ext.get_mut::<ClientConfigChain>() {
        Some(chain) => {
            chain.configs.push(cfg.into());
        }
        None => match ext.remove::<Arc<ClientConfig>>() {
            Some(old_cfg) => {
                ext.insert(ClientConfigChain {
                    configs: vec![old_cfg, cfg.into()],
                });
            }
            None => {
                ext.insert(ClientConfigChain::from(cfg.into()));
            }
        },
    }
}

pub fn append_all_client_configs_to_extensions(
    ext: &mut Extensions,
    cfg_it: impl IntoIterator<Item: Into<Arc<ClientConfig>>>,
) {
    let cfg_it = cfg_it.into_iter();
    match ext.get_mut::<ClientConfigChain>() {
        Some(chain) => {
            chain.configs.extend(cfg_it.map(Into::into));
        }
        None => {
            if let Some(old_cfg) = ext.remove::<Arc<ClientConfig>>() {
                let (lb, _) = cfg_it.size_hint();
                assert!(lb < usize::MAX);

                let mut configs = Vec::with_capacity(lb + 1);
                configs.push(old_cfg);
                configs.extend(cfg_it.map(Into::into));

                ext.insert(ClientConfigChain { configs });
            } else {
                let chain: ClientConfigChain = cfg_it.collect();
                ext.insert(chain);
            }
        }
    }
}

impl From<ClientConfig> for ClientConfigChain {
    fn from(value: ClientConfig) -> Self {
        Self {
            configs: vec![Arc::new(value)],
        }
    }
}

impl From<Arc<ClientConfig>> for ClientConfigChain {
    fn from(value: Arc<ClientConfig>) -> Self {
        Self {
            configs: vec![value],
        }
    }
}

impl<Item> FromIterator<Item> for ClientConfigChain
where
    Item: Into<Arc<ClientConfig>>,
{
    fn from_iter<T: IntoIterator<Item = Item>>(iter: T) -> Self {
        Self {
            configs: iter.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, Default)]
/// Common API to configure a Proxy TLS Client
///
/// See [`ClientConfig`] for more information,
/// this is only a new-type wrapper to be able to differentiate
/// the info found in context for a dynamic https client.
pub struct ProxyClientConfig(pub Arc<ClientConfig>);

#[derive(Debug, Clone, Default)]
/// Common API to configure a TLS Client
pub struct ClientConfig {
    /// optional intent for cipher suites to be used by client
    pub cipher_suites: Option<Vec<CipherSuite>>,
    /// optional intent for compression algorithms to be used by client
    pub compression_algorithms: Option<Vec<CompressionAlgorithm>>,
    /// optional intent for extensions to be used by client
    ///
    /// Commpon examples are:
    ///
    /// - [`super::ClientHelloExtension::ApplicationLayerProtocolNegotiation`]
    /// - [`super::ClientHelloExtension::SupportedVersions`]
    pub extensions: Option<Vec<ClientHelloExtension>>,
    /// optionally define how server should be verified by client
    pub server_verify_mode: Option<ServerVerifyMode>,
    /// optionally define raw (PEM-encoded) client auth certs
    pub client_auth: Option<ClientAuth>,
    /// key log intent
    pub key_logger: Option<KeyLogIntent>,
    /// if enabled server certificates will be stored in [`NegotiatedTlsParameters`]
    pub store_server_certificate_chain: bool,
}

impl ClientConfig {
    /// Merge this [`ClientConfig`] with aother one.
    pub fn merge(&mut self, other: Self) {
        if let Some(cipher_suites) = other.cipher_suites {
            self.cipher_suites = Some(cipher_suites);
        }

        if let Some(compression_algorithms) = other.compression_algorithms {
            self.compression_algorithms = Some(compression_algorithms);
        }

        self.extensions = match (self.extensions.take(), other.extensions) {
            (Some(our_ext), Some(other_ext)) => Some(merge_client_hello_lists(our_ext, other_ext)),
            (None, Some(other_ext)) => Some(other_ext),
            (maybe_our_ext, None) => maybe_our_ext,
        };

        if let Some(server_verify_mode) = other.server_verify_mode {
            self.server_verify_mode = Some(server_verify_mode);
        }

        if let Some(client_auth) = other.client_auth {
            self.client_auth = Some(client_auth);
        }

        if let Some(key_logger) = other.key_logger {
            self.key_logger = Some(key_logger);
        }
    }
}

#[derive(Debug, Clone)]
/// The kind of client auth to be used.
pub enum ClientAuth {
    /// Request the tls implementation to generate self-signed single data
    SelfSigned,
    /// Single data provided by the configurator
    Single(ClientAuthData),
}

#[derive(Debug, Clone)]
/// Raw private key and certificate data to facilitate client authentication.
pub struct ClientAuthData {
    /// private key used by client
    pub private_key: DataEncoding,
    /// certificate chain as a companion to the private key
    pub cert_chain: DataEncoding,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Mode of server verification by a (tls) client
pub enum ServerVerifyMode {
    #[default]
    /// Use the default verification approach as defined
    /// by the implementation of the used (tls) client
    Auto,
    /// Explicitly disable server verification (if possible)
    Disable,
}

impl From<super::ClientHello> for ClientConfig {
    fn from(value: super::ClientHello) -> Self {
        Self {
            cipher_suites: (!value.cipher_suites.is_empty()).then_some(value.cipher_suites),
            compression_algorithms: (!value.compression_algorithms.is_empty())
                .then_some(value.compression_algorithms),
            extensions: (!value.extensions.is_empty()).then_some(value.extensions),
            ..Default::default()
        }
    }
}

impl From<ClientConfig> for super::ClientHello {
    fn from(value: ClientConfig) -> Self {
        Self {
            protocol_version: ProtocolVersion::TLSv1_2,
            cipher_suites: value.cipher_suites.unwrap_or_default(),
            compression_algorithms: value.compression_algorithms.unwrap_or_default(),
            extensions: value.extensions.unwrap_or_default(),
        }
    }
}
