use std::{
    ffi::{c_int, c_uint},
    io::{self, IoSliceMut},
    mem,
    net::{IpAddr, Ipv4Addr},
    os::windows::io::AsRawSocket,
    ptr,
    sync::{
        LazyLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use rama_net::socket::core::{SockAddr, SockAddrStorage, socklen_t};
use windows_sys::Win32::Networking::WinSock;

use crate::log::debug;

use super::{
    EcnCodepoint, RecvMeta, SocketCapabilities, Transmit, UdpSockRef,
    cmsg::{self, CMsgHdr},
};

/// Packet-oriented UDP socket state for Windows.
///
/// Unlike a standard Windows UDP socket, this allows ECN bits to be read and written.
#[derive(Debug)]
pub(crate) struct UdpSocketState {
    max_gso_segments: AtomicUsize,
    may_fragment: bool,
    pktinfo_supported: bool,

    /// Whether the underlying Winsock provider supports IPv4 ECN socket options/control messages.
    ///
    /// Some environments (notably Wine/Proton) don't implement IP_RECVECN/IP_ECN.
    /// ECN is best-effort: when unsupported we continue without it.
    ecn_v4_supported: bool,

    /// Whether the underlying Winsock provider supports IPv6 ECN socket options/control messages.
    ecn_v6_supported: bool,
}

impl UdpSocketState {
    pub(crate) fn new(
        socket: UdpSockRef<'_>,
        _receive_original_destination: bool,
    ) -> io::Result<Self> {
        let UdpSockRef(socket) = socket;
        if CMSG_LEN
            < WinSock::CMSGHDR::cmsg_space(size_of::<WinSock::IN6_PKTINFO>())
                + WinSock::CMSGHDR::cmsg_space(size_of::<c_int>())
                + WinSock::CMSGHDR::cmsg_space(size_of::<u32>())
            || align_of::<WinSock::CMSGHDR>() > align_of::<cmsg::Aligned<[u8; 0]>>()
        {
            return Err(io::Error::other(
                "invalid UDP control-message buffer layout",
            ));
        }

        socket.set_nonblocking(true)?;
        let addr = socket.local_addr()?;
        let is_ipv6 = addr.as_socket_ipv6().is_some();
        let v6only = if is_ipv6 {
            // SAFETY: the socket handle is valid, and `result` and `len` are
            // writable values with matching sizes for `IPV6_V6ONLY`.
            unsafe {
                let mut result: u32 = 0;
                let mut len = size_of_val(&result) as i32;
                let rc = WinSock::getsockopt(
                    socket.as_raw_socket() as _,
                    WinSock::IPPROTO_IPV6,
                    WinSock::IPV6_V6ONLY as _,
                    &mut result as *mut _ as _,
                    &mut len,
                );
                if rc == -1 {
                    return Err(io::Error::last_os_error());
                }
                result != 0
            }
        } else {
            true
        };
        let is_ipv4 = !is_ipv6 || !v6only;

        // We don't support old versions of Windows that do not enable access to `WSARecvMsg()`
        if WSARECVMSG_PTR.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "network stack does not support WSARecvMsg function",
            ));
        }

        let mut ecn_v4_supported = !is_ipv4;
        let mut ecn_v6_supported = !is_ipv6;
        let mut pktinfo_v4_supported = !is_ipv4;
        let mut pktinfo_v6_supported = !is_ipv6;
        let mut may_fragment = false;

        if is_ipv4 {
            may_fragment |= set_socket_option(
                &*socket,
                WinSock::IPPROTO_IP,
                WinSock::IP_DONTFRAGMENT,
                OPTION_ON,
            )
            .is_err();

            pktinfo_v4_supported = set_socket_option(
                &*socket,
                WinSock::IPPROTO_IP,
                WinSock::IP_PKTINFO,
                OPTION_ON,
            )
            .is_ok();

            ecn_v4_supported = set_socket_option(
                &*socket,
                WinSock::IPPROTO_IP,
                WinSock::IP_RECVECN,
                OPTION_ON,
            )
            .is_ok();
        }

        if is_ipv6 {
            may_fragment |= set_socket_option(
                &*socket,
                WinSock::IPPROTO_IPV6,
                WinSock::IPV6_DONTFRAG,
                OPTION_ON,
            )
            .is_err();

            pktinfo_v6_supported = set_socket_option(
                &*socket,
                WinSock::IPPROTO_IPV6,
                WinSock::IPV6_PKTINFO,
                OPTION_ON,
            )
            .is_ok();

            ecn_v6_supported = set_socket_option(
                &*socket,
                WinSock::IPPROTO_IPV6,
                WinSock::IPV6_RECVECN,
                OPTION_ON,
            )
            .is_ok();
        }

        Ok(Self {
            max_gso_segments: AtomicUsize::new(max_gso_segments(&*socket)?),
            may_fragment,
            pktinfo_supported: pktinfo_v4_supported && pktinfo_v6_supported,
            ecn_v4_supported,
            ecn_v6_supported,
        })
    }

    /// Sends a [`Transmit`] on the given socket without any additional error handling.
    pub(crate) fn try_send(
        &self,
        socket: &UdpSockRef<'_>,
        transmit: &Transmit<'_>,
    ) -> io::Result<()> {
        let result = send(
            socket,
            transmit,
            self.ecn_v4_supported,
            self.ecn_v6_supported,
        );
        if result
            .as_ref()
            .is_err_and(|error| error.kind() != io::ErrorKind::WouldBlock)
            && transmit.segment_size.is_some()
        {
            // Winsock does not provide a reliable provider-independent error
            // discriminator for failed UDP segmentation. Conservatively stop
            // scheduling the optimization after any completed send error; the
            // original error is still returned to the caller.
            self.max_gso_segments.store(1, Ordering::Relaxed);
        }
        result
    }

    pub(crate) fn recv(
        &self,
        socket: &UdpSockRef<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        let _ = self.may_fragment;
        let Some(wsa_recvmsg_ptr) = *WSARECVMSG_PTR else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "network stack does not support WSARecvMsg function",
            ));
        };

        // The portable message-header API does not expose the inner WSAMSG.
        let mut ctrl_buf = cmsg::Aligned([0; CMSG_LEN]);
        // SAFETY: all-zero is a valid unspecified `SOCKADDR_INET`; the receive
        // call initializes the address and reports its length.
        let mut source: WinSock::SOCKADDR_INET = unsafe { mem::zeroed() };
        let mut data = WinSock::WSABUF {
            buf: bufs[0].as_mut_ptr(),
            len: bufs[0].len() as _,
        };

        let ctrl = WinSock::WSABUF {
            buf: ctrl_buf.0.as_mut_ptr(),
            len: ctrl_buf.0.len() as _,
        };

        let mut wsa_msg = WinSock::WSAMSG {
            name: &mut source as *mut _ as *mut _,
            namelen: size_of_val(&source) as _,
            lpBuffers: &mut data,
            Control: ctrl,
            dwBufferCount: 1,
            dwFlags: 0,
        };

        let mut len = 0;
        let mut truncated = false;
        // SAFETY: `wsa_msg` points to live writable address, payload and control
        // buffers with their matching lengths; `len` is a valid output pointer.
        unsafe {
            let rc = (wsa_recvmsg_ptr)(
                socket.0.as_raw_socket() as usize,
                &mut wsa_msg,
                &mut len,
                ptr::null_mut(),
                None,
            );
            if rc == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(WinSock::WSAEMSGSIZE) {
                    truncated = true;
                } else {
                    return Err(error);
                }
            }
        }
        truncated |= wsa_msg.dwFlags & WinSock::MSG_PARTIAL != 0;

        let initialize_address = |addr_storage: *mut SockAddrStorage, len: *mut socklen_t| {
            // SAFETY: try_init provides a valid pointer to its length slot.
            unsafe { *len = size_of_val(&source) as _ };
            // SAFETY: both pointers are valid for one SOCKADDR_INET value.
            unsafe { ptr::copy_nonoverlapping(&source, addr_storage.cast(), 1) };
            Ok(())
        };
        // SAFETY: the initializer writes one complete `SOCKADDR_INET` and sets
        // the corresponding length before returning success.
        let (_, addr) = unsafe { SockAddr::try_init(initialize_address)? };
        let addr = addr.as_socket();

        // Decode control messages (PKTINFO and ECN)
        let mut ecn_bits = None;
        let mut dst_ip = None;
        let mut interface_index = None;
        let mut stride = len;

        // SAFETY: `WSARecvMsg` initialized the reported part of the control
        // buffer, which remains alive for the whole iteration.
        let cmsg_iter = unsafe { cmsg::Iter::new(&wsa_msg) };
        for cmsg in cmsg_iter {
            const UDP_COALESCED_INFO: i32 = WinSock::UDP_COALESCED_INFO as i32;
            // [header (len)][data][padding(len + sizeof(data))] -> [header][data][padding]
            match (cmsg.cmsg_level, cmsg.cmsg_type) {
                (WinSock::IPPROTO_IP, WinSock::IP_PKTINFO) => {
                    // SAFETY: `cmsg` was yielded from the live native control
                    // buffer walked by `cmsg_iter`.
                    let pktinfo =
                        unsafe { cmsg::decode::<WinSock::IN_PKTINFO, WinSock::CMSGHDR>(cmsg) }?;
                    // Addr is stored in big endian format
                    // SAFETY: `decode` initialized every byte of `IN_PKTINFO`;
                    // reading this union view yields its IPv4 address bytes.
                    let ip4 = Ipv4Addr::from(u32::from_be(unsafe { pktinfo.ipi_addr.S_un.S_addr }));
                    dst_ip = Some(ip4.into());
                    interface_index = Some(pktinfo.ipi_ifindex);
                }
                (WinSock::IPPROTO_IPV6, WinSock::IPV6_PKTINFO) => {
                    // SAFETY: `cmsg` was yielded from the live native control
                    // buffer walked by `cmsg_iter`.
                    let pktinfo =
                        unsafe { cmsg::decode::<WinSock::IN6_PKTINFO, WinSock::CMSGHDR>(cmsg) }?;
                    // Addr is stored in big endian format
                    // SAFETY: `decode` initialized every byte of `IN6_PKTINFO`;
                    // the byte-array union view covers the complete IPv6 address.
                    dst_ip = Some(IpAddr::from(unsafe { pktinfo.ipi6_addr.u.Byte }));
                    interface_index = Some(pktinfo.ipi6_ifindex);
                }
                (WinSock::IPPROTO_IP, WinSock::IP_ECN)
                | (WinSock::IPPROTO_IPV6, WinSock::IPV6_ECN) => {
                    // ECN is a C integer https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ecn
                    // SAFETY: `cmsg` was yielded from the live native control
                    // buffer walked by `cmsg_iter`.
                    ecn_bits = Some(unsafe { cmsg::decode::<c_int, WinSock::CMSGHDR>(cmsg) }?);
                }
                (WinSock::IPPROTO_UDP, UDP_COALESCED_INFO) => {
                    // Has type u32 (aka DWORD) per
                    // https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-udp-socket-options
                    // SAFETY: `cmsg` was yielded from the live native control
                    // buffer walked by `cmsg_iter`.
                    stride = unsafe { cmsg::decode::<u32, WinSock::CMSGHDR>(cmsg) }?;
                }
                _ => {}
            }
        }

        let len = len as usize;
        meta[0] = RecvMeta {
            len,
            original_len: len,
            stride: stride as usize,
            addr: addr.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "UDP peer address is not an IP socket",
                )
            })?,
            ecn: ecn_bits.map(|bits| EcnCodepoint::from_bits(bits as u8)),
            dst_ip,
            interface_index,
            original_destination: None,
            timestamp: None,
            truncated,
        };
        Ok(1)
    }

    /// The maximum amount of segments which can be transmitted if a platform
    /// supports Generic Send Offload (GSO).
    ///
    /// This is 1 if the platform doesn't support GSO. Subject to change if errors are detected
    /// while using GSO.
    #[inline]
    pub(crate) fn max_gso_segments(&self) -> usize {
        self.max_gso_segments.load(Ordering::Relaxed)
    }

    /// The number of segments to read when GRO is enabled. Used as a factor to
    /// compute the receive buffer size.
    ///
    /// Returns 1 if the platform doesn't support GRO.
    #[inline]
    pub(crate) fn gro_segments(&self) -> usize {
        let _ = self.may_fragment;
        // Receive coalescing stays disabled by default due to known Windows
        // provider/driver correctness issues.
        // TODO: Enable it once stride handling is verified across supported
        // providers and drivers.
        1
    }

    #[inline]
    pub(crate) fn may_fragment(&self) -> bool {
        self.may_fragment
    }

    pub(crate) fn capabilities(&self) -> SocketCapabilities {
        let ecn = self.ecn_v4_supported && self.ecn_v6_supported;
        SocketCapabilities {
            send_ecn: ecn,
            receive_ecn: ecn,
            send_source_ip: self.pktinfo_supported,
            receive_local_ip: self.pktinfo_supported,
            receive_interface: self.pktinfo_supported,
            receive_original_destination: false,
            receive_timestamp: false,
            receive_truncation: true,
        }
    }
}

fn send(
    socket: &UdpSockRef<'_>,
    transmit: &Transmit<'_>,
    ecn_v4_supported: bool,
    ecn_v6_supported: bool,
) -> io::Result<()> {
    // The portable message-header API does not expose the inner WSAMSG.
    let mut ctrl_buf = cmsg::Aligned([0; CMSG_LEN]);
    let daddr = SockAddr::from(transmit.destination);

    let mut data = WinSock::WSABUF {
        buf: transmit.contents.as_ptr() as *mut _,
        len: transmit.contents.len() as _,
    };

    let ctrl = WinSock::WSABUF {
        buf: ctrl_buf.0.as_mut_ptr(),
        len: ctrl_buf.0.len() as _,
    };

    let mut wsa_msg = WinSock::WSAMSG {
        name: daddr.as_ptr() as *mut _,
        namelen: daddr.len(),
        lpBuffers: &mut data,
        Control: ctrl,
        dwBufferCount: 1,
        dwFlags: 0,
    };

    // Add control messages (ECN and PKTINFO)
    // SAFETY: `wsa_msg.Control` points to the aligned, writable `ctrl_buf`,
    // which remains borrowed until the encoder is finished.
    let mut encoder = unsafe { cmsg::Encoder::new(&mut wsa_msg) };

    if let Some(ip) = transmit.src_ip {
        let ip = std::net::SocketAddr::new(ip, 0);
        let ip = SockAddr::from(ip);
        match ip.family() {
            WinSock::AF_INET => {
                // SAFETY: the checked address family proves that `ip` stores a
                // complete, aligned `SOCKADDR_IN` value.
                let src_ip = unsafe { ptr::read(ip.as_ptr() as *const WinSock::SOCKADDR_IN) };
                let pktinfo = WinSock::IN_PKTINFO {
                    ipi_addr: src_ip.sin_addr,
                    ipi_ifindex: 0,
                };
                encoder.push(WinSock::IPPROTO_IP, WinSock::IP_PKTINFO, pktinfo)?;
            }
            WinSock::AF_INET6 => {
                // SAFETY: the checked address family proves that `ip` stores a
                // complete, aligned `SOCKADDR_IN6` value.
                let src_ip = unsafe { ptr::read(ip.as_ptr() as *const WinSock::SOCKADDR_IN6) };
                // SAFETY: `src_ip` was copied from a fully initialized IPv6
                // socket address, including the anonymous scope-id field.
                let scope_id = unsafe { src_ip.Anonymous.sin6_scope_id };
                let pktinfo = WinSock::IN6_PKTINFO {
                    ipi6_addr: src_ip.sin6_addr,
                    ipi6_ifindex: scope_id,
                };
                encoder.push(WinSock::IPPROTO_IPV6, WinSock::IPV6_PKTINFO, pktinfo)?;
            }
            _ => {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
        }
    }

    // True for IPv4 or IPv4-Mapped IPv6
    let is_ipv4 = transmit.destination.is_ipv4()
        || matches!(transmit.destination.ip(), IpAddr::V6(addr) if addr.to_ipv4_mapped().is_some());

    if let Some(ecn) = transmit.ecn
        && ((is_ipv4 && ecn_v4_supported) || (!is_ipv4 && ecn_v6_supported))
    {
        // ECN is a C integer https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ecn
        let ecn = ecn as c_int;
        if is_ipv4 {
            encoder.push(WinSock::IPPROTO_IP, WinSock::IP_ECN, ecn)?;
        } else {
            encoder.push(WinSock::IPPROTO_IPV6, WinSock::IPV6_ECN, ecn)?;
        }
    }

    // Segment size is a u32 https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-wsasetudpsendmessagesize
    if let Some(segment_size) = transmit.effective_segment_size() {
        encoder.push(
            WinSock::IPPROTO_UDP,
            WinSock::UDP_SEND_MSG_SIZE,
            segment_size as u32,
        )?;
    }

    drop(encoder);

    let mut len = 0;
    // SAFETY: `wsa_msg` references live address, payload and finalized control
    // buffers; `len` is a valid writable result pointer.
    let rc = unsafe {
        WinSock::WSASendMsg(
            socket.0.as_raw_socket() as usize,
            &wsa_msg,
            0,
            &mut len,
            ptr::null_mut(),
            None,
        )
    };

    match rc {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

fn set_socket_option(
    socket: &impl AsRawSocket,
    level: i32,
    name: i32,
    value: u32,
) -> io::Result<()> {
    // SAFETY: the socket handle is valid and the value pointer is readable for
    // exactly the supplied length during this call.
    let rc = unsafe {
        WinSock::setsockopt(
            socket.as_raw_socket() as usize,
            level,
            name,
            &value as *const _ as _,
            size_of_val(&value) as _,
        )
    };

    match rc == 0 {
        true => Ok(()),
        false => Err(io::Error::last_os_error()),
    }
}

pub(crate) const BATCH_SIZE: usize = 1;
// Enough to store max(IP_PKTINFO + IP_ECN, IPV6_PKTINFO + IPV6_ECN) + max(UDP_SEND_MSG_SIZE, UDP_COALESCED_INFO) bytes (header + data) and some extra margin
const CMSG_LEN: usize = 128;
const OPTION_ON: u32 = 1;

static WSARECVMSG_PTR: LazyLock<WinSock::LPFN_WSARECVMSG> = LazyLock::new(|| {
    // SAFETY: this call passes constant address-family, type and protocol
    // values and returns either a socket handle or `INVALID_SOCKET`.
    let s = unsafe { WinSock::socket(WinSock::AF_INET as _, WinSock::SOCK_DGRAM as _, 0) };
    if s == WinSock::INVALID_SOCKET {
        debug!(
            "ignoring WSARecvMsg function pointer due to socket creation error: {}",
            io::Error::last_os_error()
        );
        return None;
    }

    // Detect if OS expose WSARecvMsg API based on
    // https://github.com/Azure/mio-uds-windows/blob/a3c97df82018086add96d8821edb4aa85ec1b42b/src/stdnet/ext.rs#L601
    let guid = WinSock::WSAID_WSARECVMSG;
    let mut wsa_recvmsg_ptr = None;
    let mut len = 0;

    // Safety: Option handles the NULL pointer with a None value
    let rc = unsafe {
        WinSock::WSAIoctl(
            s as _,
            WinSock::SIO_GET_EXTENSION_FUNCTION_POINTER,
            &guid as *const _ as *const _,
            size_of_val(&guid) as u32,
            &mut wsa_recvmsg_ptr as *mut _ as *mut _,
            size_of_val(&wsa_recvmsg_ptr) as u32,
            &mut len,
            ptr::null_mut(),
            None,
        )
    };

    if rc == -1 {
        debug!(
            "ignoring WSARecvMsg function pointer due to ioctl error: {}",
            io::Error::last_os_error()
        );
    } else if len as usize != size_of::<WinSock::LPFN_WSARECVMSG>() {
        debug!("ignoring WSARecvMsg function pointer due to pointer size mismatch");
        wsa_recvmsg_ptr = None;
    }

    // SAFETY: `s` was created successfully above and is closed exactly once.
    unsafe {
        WinSock::closesocket(s);
    }

    wsa_recvmsg_ptr
});

fn max_gso_segments(socket: &impl AsRawSocket) -> io::Result<usize> {
    const GSO_SIZE: c_uint = 1500;
    match set_socket_option(
        socket,
        WinSock::IPPROTO_UDP,
        WinSock::UDP_SEND_MSG_SIZE,
        GSO_SIZE,
    ) {
        Ok(()) => {
            // UDP_SEND_MSG_SIZE is socket-wide: leaving the probe value set
            // would split otherwise ordinary payloads larger than 1500 bytes.
            // Per-send segmentation is selected later through a control message.
            set_socket_option(socket, WinSock::IPPROTO_UDP, WinSock::UDP_SEND_MSG_SIZE, 0)?;
            // Empirically found on Windows 11 x64.
            Ok(512)
        }
        Err(_) => Ok(1),
    }
}
