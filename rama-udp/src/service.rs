//! Socket configuration and Rama service integration.

#[cfg(target_vendor = "apple")]
use std::net::SocketAddr;

use rama_core::{Service, error::BoxError, telemetry::tracing};
use rama_net::{
    address::SocketAddress,
    socket::{
        SocketOptions,
        core::Socket,
        opts::{Domain, Protocol, Type},
    },
};

use crate::{DatagramError, DatagramFeature, DatagramSocket as _, UdpPacketSocket, UdpSocket};

#[cfg(target_vendor = "apple")]
mod dual_stack;

/// Configuration shared by UDP packet-socket factories.
#[derive(Debug, Clone)]
pub struct UdpSocketConfig {
    socket_options: SocketOptions,
    required_features: Vec<DatagramFeature>,
    receive_original_destination: bool,
    min_buffer_size: Option<usize>,
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
        /// Ask for at least this many bytes of kernel receive and send buffer (`SO_RCVBUF`,
        /// `SO_SNDBUF`) on the sockets this configuration binds, as far as the platform allows.
        ///
        /// A platform limit (`net.core.rmem_max` on Linux, `kern.ipc.maxsockbuf` on macOS) caps
        /// the request without failing the bind; on Linux the cap is lifted with the `*FORCE`
        /// options when the process holds `CAP_NET_ADMIN`. A buffer given an explicit size in
        /// [`SocketOptions`] is left to that size. Wrapped sockets are not resized.
        pub fn min_buffer_size(mut self, bytes: Option<usize>) -> Self {
            self.min_buffer_size = bytes;
            self
        }
    }

    /// The buffer floor [`Self::with_min_buffer_size`] asks for.
    #[must_use]
    pub fn min_buffer_size(&self) -> Option<usize> {
        self.min_buffer_size
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
            min_buffer_size: None,
        }
    }
}

/// Which kernel buffer of a socket to grow.
#[derive(Debug, Clone, Copy)]
enum Buffer {
    Receive,
    Send,
}

impl Buffer {
    fn get(self, socket: &Socket) -> std::io::Result<usize> {
        match self {
            Self::Receive => socket.recv_buffer_size(),
            Self::Send => socket.send_buffer_size(),
        }
    }

    fn set(self, socket: &Socket, bytes: usize) -> std::io::Result<()> {
        match self {
            Self::Receive => socket.set_recv_buffer_size(bytes),
            Self::Send => socket.set_send_buffer_size(bytes),
        }
    }

    /// Lift the platform cap for a privileged process; anything refused is left as it was.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn force(self, socket: &Socket, bytes: usize) {
        let name = match self {
            Self::Receive => libc::SO_RCVBUFFORCE,
            Self::Send => libc::SO_SNDBUFFORCE,
        };
        // The kernel takes the value as a C int; a request past that is simply not forceable.
        let Ok(value) = libc::c_int::try_from(bytes) else {
            return;
        };
        drop(crate::sys::set_socket_option(
            socket,
            libc::SOL_SOCKET,
            name,
            value,
        ));
    }
}

/// Grow one buffer of `socket` towards `wanted` bytes: the platform may cap the request, a
/// request over the platform's maximum is halved until one is taken, and a privileged process
/// lifts the cap. The size read back is what the kernel accounts with, so a Linux socket that
/// reports the doubled value counts as satisfied.
fn grow_buffer(socket: &Socket, buffer: Buffer, wanted: usize) {
    let before = buffer.get(socket).unwrap_or(0);
    if before >= wanted {
        return;
    }
    let mut request = wanted;
    while request > before && buffer.set(socket, request).is_err() {
        request /= 2;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if buffer.get(socket).unwrap_or(0) < wanted {
        buffer.force(socket, wanted);
    }
    let after = buffer.get(socket).unwrap_or(0);
    if after < wanted {
        tracing::debug!(
            ?buffer,
            before,
            after,
            wanted,
            "udp socket buffer stays under the requested floor: the platform limit applies"
        );
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
    ///
    /// On Apple platforms a dual-stack IPv6 wildcard binding uses two sockets on the same
    /// port. Both binds must succeed before this returns; without explicit reuse options, an
    /// occupied port in either family fails the bind. IPv6-only bindings and caller-wrapped
    /// sockets keep their native behavior. Common socket options apply to both sockets; IPv6 options apply only to
    /// the IPv6 socket.
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
        #[cfg(target_vendor = "apple")]
        {
            options.address = None;
        }
        options.r#type = Type::Datagram;
        options.protocol = Some(Protocol::UDP);
        let socket = options.try_build_socket(Domain::from(address))?;
        #[cfg(target_vendor = "apple")]
        {
            if address.ip_addr.is_ipv6() && address.ip_addr.is_unspecified() && !socket.only_v6()? {
                return dual_stack::bind(self, options, socket, address);
            }
            socket.bind(&SocketAddr::from(address).into())?;
        }
        self.prepare_socket(socket, &options)
    }

    fn prepare_socket(
        &self,
        socket: Socket,
        options: &SocketOptions,
    ) -> Result<UdpPacketSocket, DatagramError> {
        if let Some(wanted) = self.config.min_buffer_size {
            if options.recv_buffer_size.is_none() {
                grow_buffer(&socket, Buffer::Receive, wanted);
            }
            if options.send_buffer_size.is_none() {
                grow_buffer(&socket, Buffer::Send, wanted);
            }
        }
        let mut socket = self.config.wrap_core(socket)?;
        socket.cache_bound_address()?;
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

    /// A buffer floor never shrinks a socket's buffers, grows them as far as the platform allows
    /// and leaves an explicitly sized buffer alone.
    #[tokio::test]
    async fn a_buffer_floor_grows_the_kernel_buffers_best_effort() {
        let socket = Socket::new(Domain::IPv4.into(), Type::Datagram.into(), None).unwrap();
        let before = socket.recv_buffer_size().unwrap();
        grow_buffer(&socket, Buffer::Receive, before * 2);
        assert!(socket.recv_buffer_size().unwrap() >= before);
        grow_buffer(&socket, Buffer::Send, 1);
        assert!(
            socket.send_buffer_size().unwrap() > 1,
            "a floor below the size changes nothing"
        );

        let address: SocketAddress = "127.0.0.1:0".parse().unwrap();
        let mut options = SocketOptions::default_udp();
        options.recv_buffer_size = Some(before);
        let config = UdpSocketConfig::default()
            .with_socket_options(options)
            .with_min_buffer_size(before * 4);
        assert_eq!(config.min_buffer_size(), Some(before * 4));
        UdpSocketFactory::new(config).bind(address).await.unwrap();
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
            Err(other) => panic!(
                "an unexpected error: the metadata setup turns a refused socket option into a \
                 capability the socket does not have, so a required feature is refused by name \
                 rather than as an error: {other:?}"
            ),
        }
    }
}
