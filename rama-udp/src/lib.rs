//! Protocol-neutral UDP module for Rama.
//!
//! Existing applications can keep using the reexported Tokio [`UdpSocket`] and
//! simple bind helpers. Packet-oriented protocols can use the runtime-neutral
//! [`DatagramSocket`] and [`DatagramSender`] traits, with [`UdpPacketSocket`]
//! as the Tokio-backed implementation. A deterministic in-memory backend is
//! available from `test_utils` when its feature is enabled.
//!
//! This crate reports socket implementation limits and ancillary capabilities.
//! It does not infer a path MTU or provide congestion control, retransmission,
//! or other upper-transport behavior.
//!
//! # Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]

mod batch;
pub use batch::{DatagramSender, DatagramSenderExt, DatagramSocket, DatagramSocketExt};

mod meta;
pub use meta::{
    DatagramCapabilities, DatagramError, DatagramFeature, DatagramMetadata, EcnCodepoint,
    MAX_UDP_PAYLOAD_IPV4, MAX_UDP_PAYLOAD_IPV6, ReceiveTimestamp,
};

#[cfg(any(test, feature = "test-utils"))]
#[cfg_attr(docsrs, doc(cfg(feature = "test-utils")))]
pub mod test_utils;

mod packet;
pub use packet::SendDatagram;

mod packet_socket;
pub use packet_socket::{UdpPacketSender, UdpPacketSocket};

mod service;
pub use service::{UdpSocketConfig, UdpSocketFactory};

mod sys;

mod log {
    #[cfg(any(target_vendor = "apple", windows))]
    pub(crate) use rama_core::telemetry::tracing::debug;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) use rama_core::telemetry::tracing::{debug, info, warn};
}

mod connected_framed;
pub use connected_framed::ConnectedUdpFramed;

mod socket;
pub use socket::{
    UdpSocket, bind_udp_socket_with_connect, bind_udp_with_address, bind_udp_with_socket,
};

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))
)]
pub use socket::bind_udp_with_device;

#[doc(inline)]
pub use tokio_util::udp::UdpFramed;
