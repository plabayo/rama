//! Socket configuration and Rama service integration.

use rama_core::{Service, error::BoxError};
use rama_net::{
    address::SocketAddress,
    socket::{
        SocketOptions,
        opts::{Domain, Protocol, Type},
    },
};

use crate::{DatagramError, DatagramFeature, DatagramSocket as _, UdpPacketSocket, UdpSocket};

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

    /// Wrap a socket the caller bound, as if this configuration had created it.
    ///
    /// Only the packet metadata this configuration asks for is set up, and the features it
    /// requires are validated; socket options the caller applied are left as they are and none of
    /// this configuration's [`SocketOptions`] are applied to an already bound socket. A socket
    /// whose capabilities do not meet a required feature is refused, and the socket is dropped
    /// with the error rather than returned.
    pub fn wrap_core(
        &self,
        socket: rama_net::socket::core::Socket,
    ) -> Result<UdpPacketSocket, DatagramError> {
        self.wrap_std(socket.into())
    }

    /// The same for a standard socket. See [`wrap_core`](Self::wrap_core).
    pub fn wrap_std(&self, socket: std::net::UdpSocket) -> Result<UdpPacketSocket, DatagramError> {
        let socket = UdpPacketSocket::from_std(socket, self.receive_original_destination)?;
        self.validate_capabilities(socket.capabilities())?;
        Ok(socket)
    }

    /// The same for a Tokio socket. See [`wrap_core`](Self::wrap_core).
    ///
    /// The socket is already registered with the runtime by its owner, which is also who put it in
    /// non-blocking mode: `tokio::net::UdpSocket::from_std` requires that of its caller and does
    /// not do it. Only the metadata setup happens here.
    pub fn wrap_tokio(&self, socket: UdpSocket) -> Result<UdpPacketSocket, DatagramError> {
        let socket = UdpPacketSocket::from_registered(socket, self.receive_original_destination)?;
        self.validate_capabilities(socket.capabilities())?;
        Ok(socket)
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
        self.config.wrap_core(socket)
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

    /// Wrapping a socket the caller bound sets up the metadata the configuration asks for and
    /// validates what it requires, through both entries. Where the platform provides
    /// transparent-proxy original destinations the feature is reported; where it does not, the
    /// requirement is refused by name.
    #[tokio::test]
    async fn wrapping_requests_the_configured_metadata() {
        let feature = DatagramFeature::ReceiveOriginalDestination;
        let config = UdpSocketConfig::default().with_required_feature(feature);

        let bound = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        check_wrapped(feature, config.wrap_std(bound));

        let bound = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        bound.set_nonblocking(true).unwrap();
        let registered = crate::UdpSocket::from_std(bound).unwrap();
        check_wrapped(feature, config.wrap_tokio(registered));
    }

    fn check_wrapped(feature: DatagramFeature, wrapped: Result<UdpPacketSocket, DatagramError>) {
        match wrapped {
            Ok(socket) => {
                assert!(
                    socket.capabilities().supports(feature),
                    "a socket that satisfied the requirement reports the feature"
                );
            }
            Err(DatagramError::Unsupported(refused)) => {
                assert_eq!(refused, feature, "the refusal names the feature");
                #[cfg(any(target_os = "android", target_os = "linux"))]
                panic!("this platform sets the original-destination options when asked");
            }
            Err(other) => {
                // The platform has the option and refused to set it, which privileges can cause.
                assert!(
                    matches!(other, DatagramError::Io(_)),
                    "the platform's own error is kept: {other:?}"
                );
            }
        }
    }
}
