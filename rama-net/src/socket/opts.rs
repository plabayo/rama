//! Options and types in function of creating [`Socket`]s.

use crate::address::SocketAddress;

use super::core::{
    Domain as SocketDomain, Protocol as SocketProtocol, SockAddr, Socket,
    TcpKeepalive as SocketTcpKeepAlive, Type as SocketType,
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

/// Specification of the communication domain for a [`Socket`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, Eq, PartialEq)]
pub enum Domain {
    /// Domain for IPv4 communication, corresponding to `AF_INET`.
    #[default]
    IPv4,
    /// Domain for IPv6 communication, corresponding to `AF_INET6`.
    IPv6,
    /// Domain for Unix socket communication, corresponding to `AF_UNIX`.
    Unix,
}

impl Domain {
    #[inline]
    pub fn as_socket_domain(self) -> SocketDomain {
        self.into()
    }
}

impl From<Domain> for SocketDomain {
    fn from(value: Domain) -> Self {
        match value {
            Domain::IPv4 => SocketDomain::IPV4,
            Domain::IPv6 => SocketDomain::IPV6,
            Domain::Unix => SocketDomain::UNIX,
        }
    }
}

/// Protocol specification used for creating [`Socket`]s.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, Eq, PartialEq)]
pub enum Protocol {
    /// Protocol corresponding to `ICMPv4` (`sys::IPPROTO_ICMP`)
    ICMPV4,
    /// Protocol corresponding to `ICMPv6` (`sys::IPPROTO_ICMPV6`)
    ICMPV6,
    #[default]
    /// Protocol corresponding to `TCP` (`sys::IPPROTO_TCP`)
    TCP,
    /// Protocol corresponding to `UDP` (`sys::IPPROTO_UDP`)
    UDP,
    #[cfg(target_os = "linux")]
    /// Protocol corresponding to `MPTCP` (`sys::IPPROTO_MPTCP`)
    MPTCP,
    #[cfg(target_os = "linux")]
    /// Protocol corresponding to `DCCP` (`sys::IPPROTO_DCCP`)
    DCCP,
    #[cfg(any(target_os = "freebsd", target_os = "linux"))]
    /// Protocol corresponding to `SCTP` (`sys::IPPROTO_SCTP`)
    SCTP,
}

impl Protocol {
    #[inline]
    pub fn as_socket_protocol(self) -> SocketProtocol {
        self.into()
    }
}

impl From<Protocol> for SocketProtocol {
    fn from(value: Protocol) -> Self {
        match value {
            Protocol::ICMPV4 => SocketProtocol::ICMPV4,
            Protocol::ICMPV6 => SocketProtocol::ICMPV6,
            Protocol::TCP => SocketProtocol::TCP,
            Protocol::UDP => SocketProtocol::UDP,
            #[cfg(target_os = "linux")]
            Protocol::MPTCP => SocketProtocol::MPTCP,
            #[cfg(target_os = "linux")]
            Protocol::DCCP => SocketProtocol::DCCP,
            #[cfg(any(target_os = "freebsd", target_os = "linux"))]
            Protocol::SCTP => SocketProtocol::SCTP,
        }
    }
}

/// Specification of communication semantics on a [`Socket`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, Eq, PartialEq)]
pub enum Type {
    /// Type corresponding to `SOCK_STREAM`.
    ///
    /// Used for protocols such as [`Protocol::TCP`].
    #[default]
    Stream,
    /// Type corresponding to `SOCK_DGRAM`.
    ///
    /// Used for protocols such as [`Protocol::UDP`].
    Datagram,
    #[cfg(target_os = "linux")]
    /// Type corresponding to `SOCK_DCCP`.
    ///
    /// Used for the [`Protocol::DCCP`].
    DCCP,
    #[cfg(not(target_os = "espidf"))]
    /// Type corresponding to `SOCK_SEQPACKET`.
    SequencePacket,
    #[cfg(not(any(target_os = "redox", target_os = "espidf")))]
    /// Type corresponding to `SOCK_RAW`.
    Raw,
}

impl Type {
    #[inline]
    pub fn as_socket_type(self) -> SocketType {
        self.into()
    }
}

impl From<Type> for SocketType {
    fn from(value: Type) -> Self {
        match value {
            Type::Stream => SocketType::STREAM,
            Type::Datagram => SocketType::DGRAM,
            #[cfg(target_os = "linux")]
            Type::DCCP => SocketType::DCCP,
            #[cfg(not(target_os = "espidf"))]
            Type::SequencePacket => SocketType::SEQPACKET,
            #[cfg(not(any(target_os = "redox", target_os = "espidf")))]
            Type::Raw => SocketType::RAW,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
/// Configures a [`Socket`]'s TCP keepalive parameters.
///
/// See [`SocketOptions::tcp_keepalive`].
pub struct TcpKeepAlive {
    /// Set the amount of time after which TCP keepalive probes will be sent on
    /// idle connections.
    ///
    /// This will set `TCP_KEEPALIVE` on macOS and iOS, and
    /// `TCP_KEEPIDLE` on all other Unix operating systems, except
    /// OpenBSD and Haiku which don't support any way to set this
    /// option. On Windows, this sets the value of the `tcp_keepalive`
    /// struct's `keepalivetime` field.
    ///
    /// Some platforms specify this value in seconds, so sub-second
    /// specifications may be omitted.
    pub time: Option<Duration>,

    #[cfg(not(any(
        target_os = "openbsd",
        target_os = "redox",
        target_os = "solaris",
        target_os = "nto",
        target_os = "espidf",
        target_os = "vita",
        target_os = "haiku",
    )))]
    /// Set the value of the `TCP_KEEPINTVL` option. On Windows, this sets the
    /// value of the `tcp_keepalive` struct's `keepaliveinterval` field.
    ///
    /// Sets the time interval between TCP keepalive probes.
    ///
    /// Some platforms specify this value in seconds, so sub-second
    /// specifications may be omitted.
    pub interval: Option<Duration>,

    #[cfg(not(any(
        target_os = "openbsd",
        target_os = "redox",
        target_os = "solaris",
        target_os = "windows",
        target_os = "nto",
        target_os = "espidf",
        target_os = "vita",
        target_os = "haiku",
    )))]
    /// Set the value of the `TCP_KEEPCNT` option.
    ///
    /// Set the maximum number of TCP keepalive probes that will be sent before
    /// dropping a connection, if TCP keepalive is enabled on this [`Socket`].
    pub retries: Option<u32>,
}

impl<'de> Deserialize<'de> for TcpKeepAlive {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Variants {
            Time(Option<Duration>),
            Options {
                time: Option<Duration>,
                #[cfg(not(any(
                    target_os = "openbsd",
                    target_os = "redox",
                    target_os = "solaris",
                    target_os = "nto",
                    target_os = "espidf",
                    target_os = "vita",
                    target_os = "haiku",
                )))]
                interval: Option<Duration>,
                #[cfg(not(any(
                    target_os = "openbsd",
                    target_os = "redox",
                    target_os = "solaris",
                    target_os = "windows",
                    target_os = "nto",
                    target_os = "espidf",
                    target_os = "vita",
                    target_os = "haiku",
                )))]
                retries: Option<u32>,
            },
        }

        match Variants::deserialize(deserializer)? {
            Variants::Time(time) => Ok(TcpKeepAlive {
                time,
                ..Default::default()
            }),
            Variants::Options {
                time,
                #[cfg(not(any(
                    target_os = "openbsd",
                    target_os = "redox",
                    target_os = "solaris",
                    target_os = "nto",
                    target_os = "espidf",
                    target_os = "vita",
                    target_os = "haiku",
                )))]
                interval,
                #[cfg(not(any(
                    target_os = "openbsd",
                    target_os = "redox",
                    target_os = "solaris",
                    target_os = "windows",
                    target_os = "nto",
                    target_os = "espidf",
                    target_os = "vita",
                    target_os = "haiku",
                )))]
                retries,
            } => Ok(TcpKeepAlive {
                time,
                #[cfg(not(any(
                    target_os = "openbsd",
                    target_os = "redox",
                    target_os = "solaris",
                    target_os = "nto",
                    target_os = "espidf",
                    target_os = "vita",
                    target_os = "haiku",
                )))]
                interval,
                #[cfg(not(any(
                    target_os = "openbsd",
                    target_os = "redox",
                    target_os = "solaris",
                    target_os = "windows",
                    target_os = "nto",
                    target_os = "espidf",
                    target_os = "vita",
                    target_os = "haiku",
                )))]
                retries,
            }),
        }
    }
}

impl TcpKeepAlive {
    #[inline]
    pub fn into_socket_keep_alive(self) -> SocketTcpKeepAlive {
        self.into()
    }
}

impl From<TcpKeepAlive> for SocketTcpKeepAlive {
    fn from(value: TcpKeepAlive) -> Self {
        let ka = SocketTcpKeepAlive::new();

        let ka = match value.time {
            Some(time) => ka.with_time(time),
            None => ka,
        };

        #[cfg(not(any(
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "nto",
            target_os = "espidf",
            target_os = "vita",
            target_os = "haiku",
        )))]
        let ka = match value.interval {
            Some(interval) => ka.with_interval(interval),
            None => ka,
        };

        #[cfg(not(any(
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "windows",
            target_os = "nto",
            target_os = "espidf",
            target_os = "vita",
            target_os = "haiku",
        )))]
        let ka = match value.retries {
            Some(retries) => ka.with_retries(retries),
            None => ka,
        };

        ka
    }
}

impl SocketOptions {
    /// Create a default TCP (Ipv4) [`SocketOptions`].
    #[inline]
    pub fn default_tcp() -> SocketOptions {
        Default::default()
    }

    /// Create a default TCP (Ipv6) [`SocketOptions`].
    #[inline]
    pub fn default_tcp_v6() -> SocketOptions {
        SocketOptions {
            domain: Domain::IPv6,
            r#type: Type::Stream,
            protocol: Some(Protocol::TCP),
            ..Default::default()
        }
    }
    /// Create a default UDP (Ipv4) [`SocketOptions`].
    #[inline]
    pub fn default_udp() -> SocketOptions {
        SocketOptions {
            domain: Domain::IPv4,
            r#type: Type::Datagram,
            protocol: Some(Protocol::UDP),
            ..Default::default()
        }
    }

    /// Create a default UDP (Ipv6) [`SocketOptions`].
    #[inline]
    pub fn default_udp_v6() -> SocketOptions {
        SocketOptions {
            domain: Domain::IPv6,
            r#type: Type::Datagram,
            protocol: Some(Protocol::UDP),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SocketOptions {
    pub domain: Domain,
    pub r#type: Type,
    pub protocol: Option<Protocol>,

    /// Bind the [`Socket`] to the specified address.
    pub address: Option<SocketAddress>,

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    /// Bind the [`Socket`] to the specified device.
    ///
    /// Sets the value for the `SO_BINDTODEVICE` option on this [`Socket`]].
    ///
    /// If a socket is bound to an interface, only packets received from
    /// that particular interface are processed by the socket.
    /// Note that this only works for some socket types, particularly [`Domain::IPv4`] [`Socket`]s.
    pub device: Option<super::DeviceName>,

    /// Set the value of the `SO_BROADCAST` option for this [`Socket`].
    ///
    /// When enabled, this [`Socket`] is allowed to send packets to a broadcast address.
    pub broadcast: Option<bool>,

    /// Set value for the `SO_KEEPALIVE` option on this [`Socket`].
    ///
    /// Enable sending of keep-alive messages on connection-oriented [`Socket`]s.
    pub keep_alive: Option<bool>,

    /// Set value for the `SO_LINGER` option on this socket.
    ///
    /// If linger is not None, a close(2) or shutdown(2)
    /// will not return until all queued messages for the socket have
    /// been successfully sent or the linger timeout has been reached.
    /// Otherwise, the call returns immediately and the closing is done in
    /// the background. When the socket is closed as part of exit(2),
    /// it always lingers in the background.
    ///
    /// ## Notes
    ///
    /// On most OSs the duration only has a precision of seconds and will be silently truncated.
    ///
    /// On Apple platforms (e.g. macOS, iOS, etc) this uses `SO_LINGER_SEC`.
    pub linger: Option<Duration>,

    #[cfg(not(target_os = "redox"))]
    /// Set value for the SO_OOBINLINE option on this [`Socket`].
    ///
    /// If this option is enabled,
    /// out-of-band data is directly placed into the receive data stream.
    /// Otherwise, out-of-band data is passed only when the `MSG_OOB` flag
    /// is set during receiving. As per [RFC6093], TCP [`Socket`]s using the Urgent
    /// mechanism are encouraged to set this flag.
    ///
    /// [RFC6093]: https://datatracker.ietf.org/doc/html/rfc6093
    pub out_of_band_inline: Option<bool>,

    #[cfg(all(unix, target_os = "linux"))]
    /// Set value for the `SO_PASSCRED` option on this [`Socket`].
    ///
    /// If this option is enabled, enables the receiving of the `SCM_CREDENTIALS` control messages.
    pub passcred: Option<bool>,

    /// Set value for the `SO_RCVBUF` option on this [`Socket`].
    ///
    /// Changes the size of the operating system’s receive buffer associated with the [`Socket`].
    pub recv_buffer_size: Option<usize>,

    /// Set value for the `SO_RCVTIMEO` option on this [`Socket`].
    ///
    /// If timeout is None, then read and recv calls will block indefinitely.
    pub read_timeout: Option<Duration>,

    /// Set value for the `SO_REUSEADDR` option on this [`Socket`].
    ///
    /// This indicates that further calls to bind may allow reuse of local addresses.
    /// For IPv4 [`Socket`]s this means that a [`Socket`] may bind even when there’s a [`Socket`] already
    /// listening on this port.
    pub reuse_address: Option<bool>,

    /// Set value for the `SO_SNDBUF` option on this [`Socket`].
    ///
    /// Changes the size of the operating system’s send buffer
    /// associated with the [`Socket`].
    pub send_buffer_size: Option<usize>,

    /// Set value for the SO_SNDTIMEO option on this [`Socket`].
    ///
    /// If timeout is None, then write and send calls will block indefinitely.
    pub write_timeout: Option<Duration>,

    #[cfg(not(any(target_os = "redox", target_os = "espidf")))]
    /// Set the value of the `IP_HDRINCL` option on this [`Socket`].
    ///
    /// If enabled, the user supplies an IP header in front of the user data.
    /// Valid only for [`Type::Raw`] [`Socket`]s; see [raw(7)] for more information.
    ///
    /// When this flag is enabled, the values set by
    /// `IP_OPTIONS`, [`IP_TTL`], and [`IP_TOS`] are ignored.
    ///
    /// [raw(7)]: https://man7.org/linux/man-pages/man7/raw.7.html
    /// [`IP_TTL`]: SocketOptions::ttl
    /// [`IP_TOS`]: SocketOptions::tos
    pub header_included: Option<bool>,

    #[cfg(not(any(
        target_os = "redox",
        target_os = "espidf",
        target_os = "openbsd",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd"
    )))]
    /// Set the value of the `IP_HDRINCL` option on this [`Socket`].
    ///
    /// If enabled, the user supplies an IP header in front of the user data.
    /// Valid only for [`Type::Raw`] [`Socket`]s; see [raw(7)] for more information.
    ///
    /// When this flag is enabled, the values set by `IP_OPTIONS` are ignored.
    ///
    /// [raw(7)]: https://man7.org/linux/man-pages/man7/raw.7.html
    pub header_included_v6: Option<bool>,

    #[cfg(target_os = "linux")]
    /// Set the value of the `IP_TRANSPARENT` option on this [`Socket`].
    ///
    /// Setting this boolean option enables transparent proxying on this [`Socket`].
    ///
    /// This [`Socket`] option allows the calling application to bind to a
    /// nonlocal IP address and operate both as a client and a server with
    /// the foreign address as the local endpoint.
    ///
    /// ## NOTE
    ///
    /// This requires that routing be set up in a way that packets
    /// going to the foreign address are routed through the TProxy box
    /// (i.e., the system hosting the application that employs the `IP_TRANSPARENT` socket option).
    /// Enabling this [`Socket`] option requires superuser privileges (the `CAP_NET_ADMIN` capability).
    ///
    /// TProxy redirection with the iptables `TPROXY` target also requires
    /// that this option be set on the redirected socket.
    pub ip_transparent: Option<bool>,

    /// Set the value of the `IP_TTL` option for this [`Socket`].
    ///
    /// This value sets the time-to-live field that
    /// is used in every packet sent from this [`Socket`].
    pub ttl: Option<u32>,

    #[cfg(not(any(
        target_os = "fuchsia",
        target_os = "redox",
        target_os = "solaris",
        target_os = "illumos",
        target_os = "haiku",
    )))]
    /// Set the value of the `IP_TOS` option for this [`Socket`].
    ///
    /// This value sets the type-of-service field that is used in every packet sent from this [`Socket`].
    ///
    /// ## NOTE
    ///
    /// <https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options>
    /// documents that not all versions of windows support `IP_TOS`.
    pub tos: Option<u32>,

    #[cfg(not(any(
        target_os = "aix",
        target_os = "dragonfly",
        target_os = "fuchsia",
        target_os = "hurd",
        target_os = "illumos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "solaris",
        target_os = "haiku",
        target_os = "nto",
        target_os = "espidf",
        target_os = "vita",
    )))]
    /// Set the value of the `IP_RECVTOS` option for this [`Socket`].
    ///
    /// If enabled, the `IP_TOS` ancillary message is passed with incoming packets.
    /// It contains a byte which specifies the Type of Service/Precedence field of the packet header.
    pub recv_tos: Option<bool>,

    /// Set the value of the `IPV6_MULTICAST_HOPS` option for this [`Socket`].
    ///
    /// Indicates the number of “routers” multicast packets will transit for this [`Socket`].
    /// The default value is 1 which means that multicast packets don’t leave the local network unless
    /// explicitly requested.
    pub multicast_hops_v6: Option<u32>,

    #[cfg(target_os = "linux")]
    /// Set the value of the `IP_MULTICAST_ALL` option for this [`Socket`].
    ///
    /// This option can be used to modify the delivery policy of
    /// multicast messages. The argument is a boolean (defaults to true).
    /// If set to true, the socket will receive messages from all the groups
    /// that have been joined globally on the whole system.
    /// Otherwise, it will deliver messages only from the groups
    /// that have been explicitly joined
    /// (for example via the `IP_ADD_MEMBERSHIP` option)
    /// on this particular socket.
    pub multicast_all_v4: Option<bool>,

    #[cfg(target_os = "linux")]
    /// Set the value of the `IPV6_MULTICAST_ALL` option for this [`Socket`].
    ///
    /// This option can be used to modify the delivery policy of multicast messages.
    /// The argument is a boolean (defaults to true). If set to true,
    /// the socket will receive messages from all the groups that have been
    /// joined globally on the whole system. Otherwise, it will deliver messages
    /// only from the groups that have been explicitly joined (for example via the
    /// `IPV6_ADD_MEMBERSHIP` option) on this particular socket.
    pub multicast_all_v6: Option<bool>,

    /// Set the value of the `IP_MULTICAST_IF` option for this [`Socket`].
    ///
    /// If enabled, multicast packets will be looped back to the local socket.
    /// Note that this may not have any affect on IPv6 sockets.
    pub multicast_interface_v4: Option<Ipv4Addr>,

    /// Set the value of the `IPV6_MULTICAST_IF` option for this [`Socket`].
    ///
    /// Specifies the interface to use for routing multicast packets.
    /// Unlike ipv4, this is generally required in ipv6 contexts where
    /// network routing prefixes may overlap.
    pub multicast_interface_v6: Option<u32>,

    /// Set the value of the `IP_MULTICAST_LOOP` option for this [`Socket`].
    ///
    /// If enabled, multicast packets will be looped back to the local [`Socket`].
    /// Note that this may not have any affect on IPv6 [`Socket`]s.
    pub multicast_loop_v4: Option<bool>,

    /// Set the value of the `IPV6_MULTICAST_LOOP` option for this [`Socket`].
    ///
    /// Controls whether this [`Socket`] sees the multicast packets
    /// it sends itself. Note that this may not have any affect on IPv4 [`Socket`]s.
    pub multicast_loop_v6: Option<bool>,

    /// Set the value of the `IP_MULTICAST_TTL` option for this [`Socket`].
    ///
    /// Indicates the time-to-live value of outgoing multicast packets
    /// for this [`Socket`]. The default value is 1 which means that multicast
    /// packets don’t leave the local network unless explicitly requested.
    ///
    /// Note that this may not have any affect on IPv6 [`Socket`]s.
    pub multicast_ttl_v4: Option<u32>,

    /// Set the value for the `IPV6_UNICAST_HOPS` option on this [`Socket`].
    ///
    /// Specifies the hop limit for ipv6 unicast packets
    pub unicast_hops_v6: Option<u32>,

    /// Set the value for the IPV6_V6ONLY option on this [`Socket`].
    ///
    /// If this is set to true then the socket is restricted to
    /// sending and receiving IPv6 packets only.
    /// In this case two IPv4 and IPv6 applications can bind the same port at the same time.
    ///
    /// If this is set to false then the socket can be used to send
    /// and receive packets from an IPv4-mapped IPv6 address.
    pub only_v6: Option<bool>,

    #[cfg(not(any(
        target_os = "dragonfly",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "solaris",
        target_os = "haiku",
        target_os = "hurd",
        target_os = "espidf",
        target_os = "vita",
    )))]
    /// Set the value of the `IPV6_RECVTCLASS` option for this [`Socket`].
    ///
    /// If enabled, the `IPV6_TCLASS` ancillary message is passed
    /// with incoming packets. It contains a byte which specifies
    /// the traffic class field of the packet header.
    pub recv_tclass_v6: Option<bool>,

    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    /// Set the value of the `IPV6_TCLASS` option for this [`Socket`].
    ///
    /// Specifies the traffic class field that is used in every packets
    /// sent from this [`Socket`].
    pub tclass_v6: Option<u32>,

    #[cfg(not(any(
        windows,
        target_os = "dragonfly",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "solaris",
        target_os = "haiku",
        target_os = "hurd",
        target_os = "espidf",
        target_os = "vita",
    )))]
    /// Set the value of the `IPV6_RECVHOPLIMIT` option for this [`Socket`].
    ///
    /// The received hop limit is returned as ancillary data by `recvmsg()`
    /// only if the application has enabled the `IPV6_RECVHOPLIMIT` [`Socket`] option.
    pub recv_hoplimit_v6: Option<bool>,

    /// Set parameters configuring TCP keepalive probes for this [`Socket`].
    ///
    /// The supported parameters depend on the operating system, and are
    /// configured using the [`TcpKeepAlive`] struct. At a minimum, all systems
    /// support configuring the [keepalive time]: the time after which the OS
    /// will start sending keepalive messages on an idle connection.
    ///
    /// [keepalive time]: TcpKeepAlive::time
    ///
    /// # Notes
    ///
    /// * This will enable `SO_KEEPALIVE` on this [`Socket`], if it is not already
    ///   enabled.
    /// * On some platforms, such as Windows, any keepalive parameters *not*
    ///   configured by the `TcpKeepalive` struct passed to this function may be
    ///   overwritten with their default values. Therefore, this function should
    ///   either only be called once per [`Socket`], or the same parameters should
    ///   be passed every time it is called.
    pub tcp_keep_alive: Option<TcpKeepAlive>,

    /// Set the value of the `TCP_NODELAY` option on this [`Socket`].
    ///
    /// If set, this option disables the Nagle algorithm.
    /// This means that segments are always sent as soon as possible,
    /// even if there is only a small amount of data. When not set,
    /// data is buffered until there is a sufficient amount to send out,
    /// thereby avoiding the frequent sending of small packets.
    pub tcp_no_delay: Option<bool>,

    #[cfg(all(unix, not(target_os = "redox")))]
    /// Sets the value of the `TCP_MAXSEG` option on this [`Socket`].
    ///
    /// The `TCP_MAXSEG` option denotes the TCP Maximum Segment Size
    /// and is only available on TCP [`Socket`]s.
    pub tcp_max_segments: Option<u32>,

    #[cfg(any(target_os = "freebsd", target_os = "linux"))]
    /// Set the value of the `TCP_CONGESTION` option for this [`Socket`].
    ///
    /// Specifies the TCP congestion control algorithm to use for this socket.
    ///
    /// The value must be a valid TCP congestion control algorithm name of the
    /// platform. For example, Linux may supports "reno", "cubic".
    pub tcp_congestion: Option<String>,

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    /// Sets the value for the `SO_MARK` option on this [`Socket`].
    ///
    /// This value sets the socket mark field for each packet sent through this [`Socket`].
    /// Changing the mark can be used for mark-based routing without netfilter or for packet filtering.
    ///
    /// On Linux this function requires the CAP_NET_ADMIN capability.
    pub mark: Option<u32>,

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    /// Set the value of the `TCP_CORK` option on this [`Socket`].
    ///
    /// If set, don't send out partial frames. All queued partial frames are
    /// sent when the option is cleared again. There is a 200 millisecond ceiling on
    /// the time for which output is corked by `TCP_CORK`. If this ceiling is reached,
    /// then queued data is automatically transmitted.
    pub tcp_cork: Option<bool>,

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    /// Set the value of the `TCP_QUICKACK` option on this [`Socket`].
    ///
    /// If set, acks are sent immediately, rather than delayed if needed in accordance to normal
    /// TCP operation. This flag is not permanent, it only enables a switch to or from quickack mode.
    /// Subsequent operation of the TCP protocol will once again enter/leave quickack mode depending on
    /// internal protocol processing and factors such as delayed ack timeouts occurring and data transfer.
    pub tcp_quick_ack: Option<bool>,

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    /// Set the value of the `TCP_THIN_LINEAR_TIMEOUTS` option on this [`Socket`].
    ///
    /// If set, the kernel will dynamically detect a thin-stream connection
    /// if there are less than four packets in flight.
    /// With less than four packets in flight the normal TCP fast retransmission will not be effective.
    /// The kernel will modify the retransmission to avoid the very high latencies that thin stream
    /// suffer because of exponential backoff.
    pub tcp_thin_linear_timeouts: Option<bool>,

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    /// Set the value of the `TCP_USER_TIMEOUT` option on this [`Socket`].
    ///
    /// If set, this specifies the maximum amount of time that transmitted data may remain
    /// unacknowledged or buffered data may remain untransmitted before TCP will forcibly close the
    /// corresponding connection.
    ///
    /// Setting `timeout` to `None` or a zero duration causes the system default timeouts to
    /// be used. If `timeout` in milliseconds is larger than `c_uint::MAX`, the timeout is clamped
    /// to `c_uint::MAX`. For example, when `c_uint` is a 32-bit value, this limits the timeout to
    /// approximately 49.71 days.
    pub tcp_user_timeout: Option<Duration>,

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    /// Set value for the `IP_FREEBIND` option on this [`Socket`].
    ///
    /// If enabled, this boolean option allows binding to an IP address that is
    /// nonlocal or does not (yet) exist.  This permits listening on a [`Socket`],
    /// without requiring the underlying network interface or the specified
    /// dynamic IP address to be up at the time that the application is trying
    /// to bind to it.
    pub freebind: Option<bool>,

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    /// Set value for the `IPV6_FREEBIND` option on this [`Socket`].
    ///
    /// This is an IPv6 counterpart of `IP_FREEBIND` [`Socket`] option on
    /// Android/Linux. For more information about this option, see
    /// [`set_freebind`].
    ///
    /// [`set_freebind`]: SocketOptions::freebind
    pub freebind_ipv6: Option<bool>,

    #[cfg(target_os = "linux")]
    /// Set value for the `SO_INCOMING_CPU` option on this [`Socket`].
    ///
    /// Sets the CPU affinity of the [`Socket`].
    pub cpu_affinity: Option<usize>,

    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    /// Set value for the `SO_REUSEPORT` option on this [`Socket`].
    ///
    /// This indicates that further calls to `bind` may allow reuse of local
    /// addresses. For IPv4 [`Socket`]s this means that a [`Socket`] may bind even when
    /// there's a [`Socket`] already listening on this port.
    pub reuse_port: Option<bool>,

    #[cfg(target_os = "linux")]
    /// Set value for the `DCCP_SOCKOPT_SERVICE` option on this [`Socket`].
    ///
    /// Sets the DCCP service. The specification mandates use of service codes.
    /// If this [`Socket`] option is not set, the [`Socket`] will fall back to 0 (which
    /// means that no meaningful service code is present). On active [`Socket`]s
    /// this is set before [`connect`]. On passive [`Socket`]s up to 32 service
    /// codes can be set before calling [`bind`]
    ///
    /// [`connect`]: Socket::connect
    /// [`bind`]: Socket::bind
    pub dccp_service: Option<u32>,

    #[cfg(target_os = "linux")]
    /// Set value for the `DCCP_SOCKOPT_CCID` option on this [`Socket`].
    ///
    /// This option sets both the TX and RX CCIDs at the same time.
    pub dccp_ccid: Option<u8>,

    #[cfg(target_os = "linux")]
    /// Set value for the `DCCP_SOCKOPT_SERVER_TIMEWAIT` option on this [`Socket`].
    ///
    /// Enables a listening [`Socket`] to hold timewait state when closing the
    /// connection. This option must be set after `accept` returns.
    pub dccp_server_timewait: Option<bool>,

    #[cfg(target_os = "linux")]
    /// Set value for the `DCCP_SOCKOPT_SEND_CSCOV` option on this [`Socket`].
    ///
    /// Both this option and `DCCP_SOCKOPT_RECV_CSCOV` are used for setting the
    /// partial checksum coverage. The default is that checksums always cover
    /// the entire packet and that only fully covered application data is
    /// accepted by the receiver. Hence, when using this feature on the sender,
    /// it must be enabled at the receiver too, with suitable choice of CsCov.
    pub dccp_send_cscov: Option<u32>,

    #[cfg(target_os = "linux")]
    /// Set the value of the `DCCP_SOCKOPT_RECV_CSCOV` option on this [`Socket`].
    ///
    /// This option is only useful when combined with [`dccp_send_cscov`].
    ///
    /// [`dccp_send_cscov`]: Socket::dccp_send_cscov
    pub dccp_recv_cscov: Option<u32>,

    #[cfg(target_os = "linux")]
    /// Set value for the `DCCP_SOCKOPT_QPOLICY_TXQLEN` option on this [`Socket`].
    ///
    /// This option sets the maximum length of the output queue. A zero value is
    /// interpreted as unbounded queue length.
    pub dccp_qpolicy_txqlen: Option<u32>,
}

impl SocketOptions {
    pub fn try_build_socket(&self) -> io::Result<Socket> {
        let socket = Socket::new(
            self.domain.into(),
            self.r#type.into(),
            self.protocol.map(Into::into),
        )?;

        if let Some(addr) = self.address {
            let std_addr: SocketAddr = addr.into();
            let socket_addr: SockAddr = std_addr.into();
            socket.bind(&socket_addr)?;
        }

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(ref device) = self.device {
            socket.bind_device(Some(device.as_bytes()))?;
        }

        if let Some(broadcast) = self.broadcast {
            socket.set_broadcast(broadcast)?;
        }
        if let Some(keep_alive) = self.keep_alive {
            socket.set_keepalive(keep_alive)?;
        }
        if let Some(linger) = self.linger {
            socket.set_linger(Some(linger))?;
        }
        #[cfg(not(target_os = "redox"))]
        if let Some(oob) = self.out_of_band_inline {
            socket.set_out_of_band_inline(oob)?;
        }
        #[cfg(all(unix, target_os = "linux"))]
        if let Some(passcred) = self.passcred {
            socket.set_passcred(passcred)?;
        }
        if let Some(n) = self.recv_buffer_size {
            socket.set_recv_buffer_size(n)?;
        }
        if let Some(duration) = self.read_timeout {
            socket.set_read_timeout(Some(duration))?;
        }
        if let Some(reuse) = self.reuse_address {
            socket.set_reuse_address(reuse)?;
        }
        if let Some(n) = self.send_buffer_size {
            socket.set_send_buffer_size(n)?;
        }
        if let Some(duration) = self.write_timeout {
            socket.set_write_timeout(Some(duration))?;
        }
        #[cfg(not(any(target_os = "redox", target_os = "espidf")))]
        if let Some(header_included) = self.header_included {
            socket.set_header_included_v4(header_included)?;
        }
        #[cfg(not(any(
            target_os = "redox",
            target_os = "espidf",
            target_os = "openbsd",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "netbsd"
        )))]
        if let Some(header_included) = self.header_included {
            socket.set_header_included_v6(header_included)?;
        }
        #[cfg(target_os = "linux")]
        if let Some(transparent) = self.ip_transparent {
            socket.set_ip_transparent_v4(transparent)?;
        }
        if let Some(ttl) = self.ttl {
            socket.set_ttl_v4(ttl)?;
        }
        #[cfg(not(any(
            target_os = "fuchsia",
            target_os = "redox",
            target_os = "solaris",
            target_os = "illumos",
            target_os = "haiku",
        )))]
        if let Some(tos) = self.tos {
            socket.set_tos_v4(tos)?;
        }
        #[cfg(not(any(
            target_os = "aix",
            target_os = "dragonfly",
            target_os = "fuchsia",
            target_os = "hurd",
            target_os = "illumos",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "haiku",
            target_os = "nto",
            target_os = "espidf",
            target_os = "vita",
        )))]
        if let Some(recv_tos) = self.recv_tos {
            socket.set_recv_tos_v4(recv_tos)?;
        }
        if let Some(loop_v4) = self.multicast_loop_v4 {
            socket.set_multicast_loop_v4(loop_v4)?;
        }
        if let Some(loop_v6) = self.multicast_loop_v6 {
            socket.set_multicast_loop_v6(loop_v6)?;
        }
        if let Some(ttl) = self.multicast_ttl_v4 {
            socket.set_multicast_ttl_v4(ttl)?;
        }
        if let Some(hops) = self.multicast_hops_v6 {
            socket.set_multicast_hops_v6(hops)?;
        }
        #[cfg(target_os = "linux")]
        if let Some(all) = self.multicast_all_v4 {
            socket.set_multicast_all_v4(all)?;
        }
        #[cfg(target_os = "linux")]
        if let Some(all) = self.multicast_all_v6 {
            socket.set_multicast_all_v6(all)?;
        }
        if let Some(interface) = self.multicast_interface_v4.as_ref() {
            socket.set_multicast_if_v4(interface)?;
        }
        if let Some(interface) = self.multicast_interface_v6 {
            socket.set_multicast_if_v6(interface)?;
        }
        if let Some(hops) = self.unicast_hops_v6 {
            socket.set_unicast_hops_v6(hops)?;
        }
        if let Some(only_v6) = self.only_v6 {
            socket.set_only_v6(only_v6)?;
        }

        #[cfg(not(any(
            windows,
            target_os = "dragonfly",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "espidf",
            target_os = "vita",
        )))]
        if let Some(recv) = self.recv_hoplimit_v6 {
            socket.set_recv_hoplimit_v6(recv)?;
        }

        #[cfg(not(any(
            windows,
            target_os = "dragonfly",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "espidf",
            target_os = "vita",
        )))]
        if let Some(recv) = self.recv_tclass_v6 {
            socket.set_recv_tclass_v6(recv)?;
        }

        #[cfg(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "linux",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        if let Some(tclass_v6) = self.tclass_v6 {
            socket.set_tclass_v6(tclass_v6)?;
        }

        if let Some(keep_alive) = self.tcp_keep_alive.clone() {
            socket.set_tcp_keepalive(&keep_alive.into_socket_keep_alive())?;
        }
        if let Some(no_delay) = self.tcp_no_delay {
            socket.set_tcp_nodelay(no_delay)?;
        }

        #[cfg(all(unix, not(target_os = "redox")))]
        if let Some(mss) = self.tcp_max_segments {
            socket.set_tcp_mss(mss)?;
        }

        #[cfg(any(target_os = "freebsd", target_os = "linux"))]
        if let Some(algo) = self.tcp_congestion.as_ref() {
            socket.set_tcp_congestion(algo.as_bytes())?;
        }

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        {
            if let Some(mark) = self.mark {
                socket.set_mark(mark)?;
            }
            if let Some(cork) = self.tcp_cork {
                socket.set_tcp_cork(cork)?;
            }
            if let Some(quickack) = self.tcp_quick_ack {
                socket.set_tcp_quickack(quickack)?;
            }
            if let Some(timeouts) = self.tcp_thin_linear_timeouts {
                socket.set_tcp_thin_linear_timeouts(timeouts)?;
            }
            if let Some(tcp_user_timeout) = self.tcp_user_timeout {
                socket.set_tcp_user_timeout(Some(tcp_user_timeout))?;
            }
            if let Some(freebind) = self.freebind {
                socket.set_freebind_v4(freebind)?;
            }
            if let Some(freebind_ipv6) = self.freebind_ipv6 {
                socket.set_freebind_v6(freebind_ipv6)?;
            }
        }

        #[cfg(target_os = "linux")]
        if let Some(cpu) = self.cpu_affinity {
            socket.set_cpu_affinity(cpu)?;
        }

        #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        if let Some(reuse) = self.reuse_port {
            socket.set_reuse_port(reuse)?;
        }

        #[cfg(target_os = "linux")]
        {
            if let Some(service) = self.dccp_service {
                socket.set_dccp_service(service)?;
            }
            if let Some(ccid) = self.dccp_ccid {
                socket.set_dccp_ccid(ccid)?;
            }
            if let Some(timewait) = self.dccp_server_timewait {
                socket.set_dccp_server_timewait(timewait)?;
            }
            if let Some(send_cscov) = self.dccp_send_cscov {
                socket.set_dccp_send_cscov(send_cscov)?;
            }
            if let Some(recv_cscov) = self.dccp_recv_cscov {
                socket.set_dccp_recv_cscov(recv_cscov)?;
            }
            if let Some(txqlen) = self.dccp_qpolicy_txqlen {
                socket.set_dccp_qpolicy_txqlen(txqlen)?;
            }
        }

        Ok(socket)
    }
}
