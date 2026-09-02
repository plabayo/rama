//! Socket configuration and Rama service integration.

use rama_core::{Service, error::BoxError};
use rama_net::{
    address::SocketAddress,
    socket::{
        SocketOptions,
        opts::{Domain, Protocol, Type},
    },
};

use crate::{DatagramError, DatagramFeature, DatagramSocket as _, UdpPacketSocket};

/// Configuration shared by UDP packet-socket factories.
#[derive(Debug, Clone)]
pub struct UdpSocketConfig {
    socket_options: SocketOptions,
    required_features: Vec<DatagramFeature>,
    receive_original_destination: bool,
}

impl UdpSocketConfig {
    /// Construct default UDP socket configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Replace Rama's general platform socket options.
        ///
        /// The address supplied to `bind` takes precedence over `options.address`.
        /// On Apple platforms the packet adapter can raise an explicitly small
        /// send buffer to avoid a kernel `sendmsg` ancillary-data defect.
        pub fn socket_options(mut self, options: SocketOptions) -> Self {
            self.socket_options = options;
            self
        }
    }

    /// Inspect the general platform socket options.
    #[must_use]
    pub fn socket_options(&self) -> &SocketOptions {
        &self.socket_options
    }

    /// Features that socket creation must provide.
    #[must_use]
    pub fn required_features(&self) -> &[DatagramFeature] {
        &self.required_features
    }

    fn validate_capabilities(
        &self,
        capabilities: crate::DatagramCapabilities,
    ) -> Result<(), DatagramError> {
        for &feature in &self.required_features {
            if !capabilities.supports(feature) {
                return Err(DatagramError::Unsupported(feature));
            }
        }
        Ok(())
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enable transparent-proxy original-destination metadata when supported.
        pub fn receive_original_destination(mut self, enabled: bool) -> Self {
            self.receive_original_destination = enabled;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Require `feature`, failing socket creation when it is unavailable.
        pub fn required_feature(mut self, feature: DatagramFeature) -> Self {
            if !self.required_features.contains(&feature) {
                self.required_features.push(feature);
            }
            if feature == DatagramFeature::ReceiveOriginalDestination {
                self.receive_original_destination = true;
            }
            self
        }
    }
}

impl Default for UdpSocketConfig {
    fn default() -> Self {
        Self {
            socket_options: SocketOptions::default_udp(),
            required_features: Vec::new(),
            receive_original_destination: false,
        }
    }
}

/// Rama service/factory for configured [`UdpPacketSocket`] instances.
#[derive(Debug, Clone, Default)]
pub struct UdpSocketFactory {
    config: UdpSocketConfig,
}

impl UdpSocketFactory {
    /// Construct a factory from `config`.
    #[must_use]
    pub const fn new(config: UdpSocketConfig) -> Self {
        Self { config }
    }

    /// Inspect this factory's configuration.
    #[must_use]
    pub const fn config(&self) -> &UdpSocketConfig {
        &self.config
    }

    /// Bind a configured packet socket.
    pub async fn bind<A>(&self, address: A) -> Result<UdpPacketSocket, DatagramError>
    where
        A: TryInto<SocketAddress, Error: Into<BoxError>>,
    {
        let address = address
            .try_into()
            .map_err(|error| std::io::Error::other(error.into()))?;
        self.bind_address(address).await
    }

    async fn bind_address(&self, address: SocketAddress) -> Result<UdpPacketSocket, DatagramError> {
        let mut options = self.config.socket_options.clone();
        options.address = Some(address);
        options.r#type = Type::Datagram;
        options.protocol = Some(Protocol::UDP);
        let socket = options.try_build_socket(Domain::from(address))?;
        let socket =
            UdpPacketSocket::from_std(socket.into(), self.config.receive_original_destination)?;
        self.config.validate_capabilities(socket.capabilities())?;
        Ok(socket)
    }
}

impl Service<SocketAddress> for UdpSocketFactory {
    type Output = UdpPacketSocket;
    type Error = DatagramError;

    async fn serve(&self, address: SocketAddress) -> Result<Self::Output, Self::Error> {
        self.bind_address(address).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_builders_preserve_options_and_deduplicate_requirements() {
        let mut options = SocketOptions::default_udp();
        options.broadcast = Some(true);
        let mut config = UdpSocketConfig::new()
            .with_socket_options(options)
            .with_required_feature(DatagramFeature::SendEcn)
            .with_required_feature(DatagramFeature::SendEcn);

        assert_eq!(config.socket_options().broadcast, Some(true));
        assert_eq!(config.required_features(), &[DatagramFeature::SendEcn]);
        assert!(!config.receive_original_destination);

        config.set_required_feature(DatagramFeature::ReceiveOriginalDestination);
        assert_eq!(
            config.required_features(),
            &[
                DatagramFeature::SendEcn,
                DatagramFeature::ReceiveOriginalDestination,
            ]
        );
        assert!(config.receive_original_destination);

        assert!(matches!(
            config.validate_capabilities(crate::DatagramCapabilities::portable()),
            Err(DatagramError::Unsupported(DatagramFeature::SendEcn))
        ));
        let capabilities = crate::DatagramCapabilities {
            send_ecn: true,
            receive_original_destination: true,
            ..crate::DatagramCapabilities::portable()
        };
        config.validate_capabilities(capabilities).unwrap();
    }
}
