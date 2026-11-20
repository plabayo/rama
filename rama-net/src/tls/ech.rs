use crate::address::HostWithPort;
use rama_core::{bytes::Bytes, extensions::Extension};

/// ECHConfigList for one physical service endpoint.
///
/// Discovery layers and custom preknowledge providers share this extension.
/// The TLS backend validates the opaque list before use. This is endpoint data,
/// not a request to enable ECH or permission to weaken caller policy. Never apply
/// it to a proxy handshake merely because it is present on the origin request.
#[derive(Clone, Extension)]
#[extension(tags(net, tls), scope(connection))]
pub struct TargetEchConfig {
    target: HostWithPort,
    config_list: Bytes,
}

impl TargetEchConfig {
    /// Associate an opaque TLS ECHConfigList with its physical endpoint.
    pub fn new(target: HostWithPort, config_list: impl Into<Bytes>) -> Self {
        Self {
            target,
            config_list: config_list.into(),
        }
    }

    /// Endpoint for which this configuration was obtained.
    pub fn target(&self) -> &HostWithPort {
        &self.target
    }

    /// TLS-framed ECHConfigList, including its two-byte list length.
    pub fn config_list(&self) -> &Bytes {
        &self.config_list
    }

    /// Check both host and port before using the configuration.
    pub fn matches_target(&self, target: &HostWithPort) -> bool {
        &self.target == target
    }
}

impl core::fmt::Debug for TargetEchConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TargetEchConfig")
            .field("target", &self.target)
            .field("config_list_len", &self.config_list.len())
            .finish()
    }
}

/// HTTPS service-binding facts for one physical TLS hop.
///
/// These are discovery facts, not caller ECH intent. Evaluate them only after
/// request/profile settings have been installed. They also describe a bare
/// fallback endpoint without a `TargetEchConfig`.
#[derive(Debug, Clone, PartialEq, Eq, Extension)]
#[extension(tags(net, tls), scope(connection))]
pub struct TargetEchServiceBinding {
    /// Exact endpoint to which these facts apply; never apply origin facts to a proxy.
    pub target: HostWithPort,
    /// All compatible alternatives published ECH. A capable, authenticated client
    /// whose final intent enables ECH must use an accepted real configuration.
    pub reliant: bool,
    /// This record mandates ECH support. A client without effective ECH intent
    /// or backend support must skip this candidate.
    pub mandatory: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoint_binding_and_debug_do_not_expose_config_bytes() {
        let config = TargetEchConfig::new(
            "example.com:443".parse().unwrap(),
            Bytes::from_static(b"secret"),
        );
        assert!(config.matches_target(&"example.com:443".parse().unwrap()));
        assert!(!config.matches_target(&"example.com:8443".parse().unwrap()));
        assert!(!config.matches_target(&"proxy.example:443".parse().unwrap()));
        assert_eq!(config.config_list().as_ref(), b"secret");
        assert!(!format!("{config:?}").contains("secret"));
    }
}
