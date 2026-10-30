use std::{
    ffi::{c_int, c_uint, c_void},
    io::{self, IoSliceMut},
    mem,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::windows::io::{AsRawSocket, AsSocket},
    ptr,
    sync::atomic::{AtomicUsize, Ordering},
};

use rama_net::socket::core::{SockAddr, SockAddrStorage, socklen_t};
use windows_sys::Win32::Networking::WinSock;

use super::{
    EcnCodepoint, PairedSocket, RecvMeta, SocketCapabilities, Transmit, UdpSockRef,
    cmsg::{self, CMsgHdr, control_payload_struct},
};

/// [`WinSock::IN_PKTINFO`] with its address as plain bytes, so that a payload has no
/// union field.
#[derive(Clone, Copy)]
#[repr(C)]
struct InPktinfo {
    addr: [u8; 4],
    ifindex: u32,
}

/// [`WinSock::IN6_PKTINFO`] with its address as plain bytes, so that a payload has no
/// union field.
#[derive(Clone, Copy)]
#[repr(C)]
struct In6Pktinfo {
    addr: [u8; 16],
    ifindex: u32,
}

const _: () = assert!(
    size_of::<InPktinfo>() == size_of::<WinSock::IN_PKTINFO>()
        && align_of::<InPktinfo>() == align_of::<WinSock::IN_PKTINFO>()
        && mem::offset_of!(InPktinfo, ifindex) == mem::offset_of!(WinSock::IN_PKTINFO, ipi_ifindex)
        && size_of::<In6Pktinfo>() == size_of::<WinSock::IN6_PKTINFO>()
        && align_of::<In6Pktinfo>() == align_of::<WinSock::IN6_PKTINFO>()
        && mem::offset_of!(In6Pktinfo, ifindex)
            == mem::offset_of!(WinSock::IN6_PKTINFO, ipi6_ifindex)
);

control_payload_struct! {
    InPktinfo => [u8; 4], u32;
    In6Pktinfo => [u8; 16], u32;
}

/// Packet-oriented UDP socket state for Windows.
///
/// Unlike a standard Windows UDP socket, this allows ECN bits to be read and written.
#[derive(Debug)]
pub(crate) struct UdpSocketState {
    max_gso_segments: AtomicUsize,
    may_fragment: bool,
    pktinfo_supported: bool,
    /// The handle of the socket this state was created for, to catch mismatches in debug builds.
    socket: WinSock::SOCKET,
    // Safety invariant: `None`, or the `WSAID_WSARECVMSG` entry point of the provider of the
    // socket with handle `socket`, as `SIO_GET_EXTENSION_FUNCTION_POINTER` returned it.
    wsa_recvmsg: WinSock::LPFN_WSARECVMSG,
    // Safety invariant: `None`, or the `WSAID_WSASENDMSG` entry point of the provider of the
    // socket with handle `socket`, as `SIO_GET_EXTENSION_FUNCTION_POINTER` returned it.
    wsa_sendmsg: WinSock::LPFN_WSASENDMSG,

    /// Whether the underlying Winsock provider supports IPv4 ECN socket options/control messages.
    ///
    /// Some environments (notably Wine/Proton) don't implement IP_RECVECN/IP_ECN.
    /// ECN is best-effort: when unsupported we continue without it.
    ecn_v4_supported: bool,

    /// Whether the underlying Winsock provider supports IPv6 ECN socket options/control messages.
    ecn_v6_supported: bool,

    /// The peer a connected socket is fixed to, read when it was wrapped.
    connected_peer: Option<SocketAddr>,
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
            let mut result: u32 = 0;
            let mut len = size_of_val(&result) as i32;
            // SAFETY: `getsockopt` writes at most `*optlen` bytes at `optval` and the written
            // size to `optlen`: the live locals `result` (an integer, valid for any bytes) and
            // `len`, its size. The handle is open for the borrow of `socket`.
            let rc = unsafe {
                WinSock::getsockopt(
                    socket.as_raw_socket() as _,
                    WinSock::IPPROTO_IPV6,
                    WinSock::IPV6_V6ONLY as _,
                    (&raw mut result).cast(),
                    &mut len,
                )
            };
            if rc == -1 {
                return Err(io::Error::last_os_error());
            }
            result != 0
        } else {
            true
        };
        let is_ipv4 = !is_ipv6 || !v6only;

        // Safety invariant of `wsa_recvmsg` and `wsa_sendmsg`: both are queried on this
        // socket, the one `recv` and `try_send` require by their `# Safety`.
        let wsa_recvmsg = query_wsa_recvmsg(&*socket)?;
        let wsa_sendmsg = query_wsa_sendmsg(&*socket)?;

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
            socket: socket.as_raw_socket() as WinSock::SOCKET,
            wsa_recvmsg,
            wsa_sendmsg,
            ecn_v4_supported,
            ecn_v6_supported,
            connected_peer: socket
                .peer_addr()
                .ok()
                .and_then(|address| address.as_socket()),
        })
    }

    /// Sends a [`Transmit`] on the given socket without any additional error handling.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `socket` is the open socket this state was created for.
    unsafe fn try_send(&self, socket: &UdpSockRef<'_>, transmit: &Transmit<'_>) -> io::Result<()> {
        self.debug_assert_socket(socket);
        // SAFETY: `send` needs `wsa_sendmsg` to be `None` or the `WSASendMsg` entry point of
        // the provider of the open `socket`: the field invariant ties it to the socket this
        // state was created for, which this function's contract makes `socket`.
        let result = unsafe {
            send(
                socket,
                transmit,
                self.wsa_sendmsg,
                self.ecn_v4_supported,
                self.ecn_v6_supported,
                self.connected_peer,
            )
        };
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

    /// Receives one datagram on the given socket.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `socket` is the open socket this state was created for.
    unsafe fn recv(
        &self,
        socket: &UdpSockRef<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        let _ = self.may_fragment;
        self.debug_assert_socket(socket);
        let Some(wsa_recvmsg) = self.wsa_recvmsg else {
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
        // SAFETY: `WSARecvMsg` without an overlapped structure or completion routine
        // completes before returning; it reads `wsa_msg` and writes at most `namelen` bytes at
        // `name`, the datagram into the `dwBufferCount` buffers, at most `Control.len` control
        // bytes, the updated lengths and flags, and the byte count at `len`. Those are the live
        // locals `source` (its own size), `data` (describing `bufs[0]`, exclusively borrowed
        // for its length), `ctrl_buf` (`CMSG_LEN` bytes) and `len`. The function is the
        // provider entry point of the socket this state was created for (field invariant),
        // which this function's contract makes `socket`, open for the call; it is called
        // through the signature Microsoft documents for it.
        let rc = unsafe {
            (wsa_recvmsg)(
                socket.0.as_raw_socket() as usize,
                &mut wsa_msg,
                &mut len,
                ptr::null_mut(),
                None,
            )
        };
        if rc == -1 {
            receive_failure(io::Error::last_os_error())?;
            truncated = true;
        }
        let control_truncated = wsa_msg.dwFlags & WinSock::MSG_CTRUNC != 0;
        truncated |= datagram_truncated(wsa_msg.dwFlags);

        let initialize_address = |addr_storage: *mut SockAddrStorage, len: *mut socklen_t| {
            // SAFETY: `try_init` passes a pointer to its own live, writable length, which
            // this writes once.
            unsafe { *len = size_of_val(&source) as _ };
            // SAFETY: `copy_nonoverlapping` needs `&source` readable and `addr_storage`
            // writable for one aligned `SOCKADDR_INET`, without overlap. `try_init` passes its
            // own `SockAddrStorage`, which the assertion below shows large and aligned enough;
            // `source` is a distinct local.
            unsafe { ptr::copy_nonoverlapping(&source, addr_storage.cast(), 1) };
            Ok(())
        };
        const _: () = assert!(
            size_of::<WinSock::SOCKADDR_INET>() <= size_of::<SockAddrStorage>()
                && align_of::<WinSock::SOCKADDR_INET>() <= align_of::<SockAddrStorage>()
        );
        // SAFETY: `try_init` needs the family and length it ends with to match the stored
        // address. The initializer stores all of `source`, which started zeroed and holds
        // what `WSARecvMsg` wrote: an `AF_INET` `SOCKADDR_IN` or `AF_INET6` `SOCKADDR_IN6`, or
        // family 0 when it wrote none. Its length covers either structure, and every byte up
        // to it is initialized.
        let (_, addr) = unsafe { SockAddr::try_init(initialize_address)? };
        let addr = addr.as_socket();

        // Decode control messages (PKTINFO and ECN)
        let mut ecn_bits = None;
        let mut dst_ip = None;
        let mut interface_index = None;
        let mut stride = len;

        // Control data past a truncation is not read.
        let cmsg_iter = (!control_truncated).then(|| {
            // SAFETY: `Iter::new` needs the control pointer aligned for `CMSGHDR` and its
            // first `Control.len` bytes initialized and unwritten while the iterator lives.
            // It is `ctrl_buf`: `cmsg::Aligned`, all `CMSG_LEN` bytes zero-initialized, a local
            // nothing writes after `WSARecvMsg` returned, which reports at most that length.
            unsafe { cmsg::Iter::new(&wsa_msg) }
        });
        for cmsg in cmsg_iter.into_iter().flatten() {
            const UDP_COALESCED_INFO: i32 = WinSock::UDP_COALESCED_INFO as i32;
            // [header (len)][data][padding(len + sizeof(data))] -> [header][data][padding]
            match (cmsg.cmsg_level, cmsg.cmsg_type) {
                (WinSock::IPPROTO_IP, WinSock::IP_PKTINFO) => {
                    // SAFETY: `InPktinfo` holds only integers and bytes, valid for any
                    // initialized bit pattern.
                    let pktinfo = unsafe { cmsg.decode::<InPktinfo>() }?;
                    // The address bytes are in network order.
                    dst_ip = Some(Ipv4Addr::from(pktinfo.addr).into());
                    interface_index = Some(pktinfo.ifindex);
                }
                (WinSock::IPPROTO_IPV6, WinSock::IPV6_PKTINFO) => {
                    // SAFETY: `In6Pktinfo` holds only integers and bytes, valid for any
                    // initialized bit pattern.
                    let pktinfo = unsafe { cmsg.decode::<In6Pktinfo>() }?;
                    dst_ip = Some(IpAddr::from(pktinfo.addr));
                    interface_index = Some(pktinfo.ifindex);
                }
                (WinSock::IPPROTO_IP, WinSock::IP_ECN)
                | (WinSock::IPPROTO_IPV6, WinSock::IPV6_ECN) => {
                    // ECN is a C integer https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ecn
                    // SAFETY: every bit pattern is a valid `c_int`.
                    ecn_bits = Some(unsafe { cmsg.decode::<c_int>() }?);
                }
                (WinSock::IPPROTO_UDP, UDP_COALESCED_INFO) => {
                    // Has type u32 (aka DWORD) per
                    // https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-udp-socket-options
                    // SAFETY: every bit pattern is a valid `u32`.
                    stride = unsafe { cmsg.decode::<u32>() }?;
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

    /// A handle-value check of the `recv`/`try_send` contract; handle values can be reused,
    /// so it proves nothing on its own.
    fn debug_assert_socket(&self, socket: &UdpSockRef<'_>) {
        debug_assert_eq!(
            socket.0.as_raw_socket() as WinSock::SOCKET,
            self.socket,
            "UDP socket state used with another socket"
        );
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

impl PairedSocket {
    pub(crate) fn recv(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        // SAFETY: `recv` needs the open socket the state was created for: `self.io`, by
        // the field invariant of `PairedSocket`, borrowed for the call.
        unsafe { self.state.recv(&(&self.io).into(), bufs, meta) }
    }

    pub(crate) fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        // SAFETY: `try_send` needs the open socket the state was created for: `self.io`, by
        // the field invariant of `PairedSocket`, borrowed for the call.
        unsafe { self.state.try_send(&(&self.io).into(), transmit) }
    }
}

/// # Safety
///
/// The caller must ensure that `wsa_sendmsg` is `None` or the `WSASendMsg` entry point of the
/// provider of `socket`, which is open.
unsafe fn send(
    socket: &UdpSockRef<'_>,
    transmit: &Transmit<'_>,
    wsa_sendmsg: WinSock::LPFN_WSASENDMSG,
    ecn_v4_supported: bool,
    ecn_v6_supported: bool,
    connected_peer: Option<SocketAddr>,
) -> io::Result<()> {
    let Some(wsa_sendmsg) = wsa_sendmsg else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "network stack does not support WSASendMsg function",
        ));
    };

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

    // A connected socket refuses an explicit destination; its peer needs none.
    let connected = super::is_connected_peer(connected_peer, transmit.destination);
    let mut wsa_msg = WinSock::WSAMSG {
        name: if connected {
            ptr::null_mut()
        } else {
            daddr.as_ptr() as *mut _
        },
        namelen: if connected { 0 } else { daddr.len() },
        lpBuffers: &mut data,
        Control: ctrl,
        dwBufferCount: 1,
        dwFlags: 0,
    };

    // Add control messages (ECN and PKTINFO)
    // SAFETY: `Encoder::new` needs the control pointer aligned for `CMSGHDR` and valid for
    // reads and writes of `Control.len` initialized bytes reachable only through the
    // encoder. It is `ctrl_buf`: `cmsg::Aligned`, all `CMSG_LEN` bytes zero-initialized, and
    // not otherwise touched while the encoder lives.
    let mut encoder = unsafe { cmsg::Encoder::new(&mut wsa_msg) };

    match transmit.src_ip {
        Some(IpAddr::V4(ip)) => {
            let pktinfo = InPktinfo {
                addr: ip.octets(),
                ifindex: 0,
            };
            encoder.push(WinSock::IPPROTO_IP, WinSock::IP_PKTINFO, pktinfo)?;
        }
        Some(IpAddr::V6(ip)) => {
            let pktinfo = In6Pktinfo {
                addr: ip.octets(),
                ifindex: transmit.src_interface.unwrap_or(0),
            };
            encoder.push(WinSock::IPPROTO_IPV6, WinSock::IPV6_PKTINFO, pktinfo)?;
        }
        None => {}
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
    // SAFETY: `WSASendMsg` without an overlapped structure or completion routine completes
    // before returning; it reads `wsa_msg`, the `namelen` bytes at `name`, the
    // `dwBufferCount` buffers and `Control.len` control bytes, and writes the byte count at
    // `len`. Those are `daddr` (or null with length 0), `data` (describing
    // `transmit.contents`), `ctrl_buf` with the length the dropped encoder stored (at most
    // `CMSG_LEN`), and the live local `len`. This function's contract makes the function the
    // provider entry point of the open `socket`; it is called through the signature
    // Microsoft documents for it.
    let rc = unsafe {
        (wsa_sendmsg)(
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

fn set_socket_option(socket: &impl AsSocket, level: i32, name: i32, value: u32) -> io::Result<()> {
    // SAFETY: `setsockopt` reads `optlen` bytes at `optval`: the live local `value`, with its
    // own size. The handle is open for the borrow of `socket` (`BorrowedSocket`).
    let rc = unsafe {
        WinSock::setsockopt(
            socket.as_socket().as_raw_socket() as usize,
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

fn query_wsa_recvmsg(socket: &impl AsSocket) -> io::Result<WinSock::LPFN_WSARECVMSG> {
    let function = query_extension_function(socket, &WinSock::WSAID_WSARECVMSG, "WSARecvMsg")?;
    // SAFETY: `transmute` needs equal sizes, checked at compile time, and a source valid at
    // the target type. `LPFN_WSARECVMSG` is an `Option` of an `extern "system" fn`, which std
    // guarantees has a pointer's size with null as `None`, so the non-null `function` becomes
    // `Some` of a non-null function pointer, all that its validity requires. Microsoft
    // documents the pointer `WSAID_WSARECVMSG` yields as an `LPFN_WSARECVMSG`, so later calls
    // use its real signature and ABI.
    Ok(unsafe { mem::transmute::<*mut c_void, WinSock::LPFN_WSARECVMSG>(function) })
}

fn query_wsa_sendmsg(socket: &impl AsSocket) -> io::Result<WinSock::LPFN_WSASENDMSG> {
    let function = query_extension_function(socket, &WinSock::WSAID_WSASENDMSG, "WSASendMsg")?;
    // SAFETY: as in `query_wsa_recvmsg`, for `WSAID_WSASENDMSG` and `LPFN_WSASENDMSG`.
    Ok(unsafe { mem::transmute::<*mut c_void, WinSock::LPFN_WSASENDMSG>(function) })
}

/// The non-null entry point `socket`'s provider returns for the extension function `guid`.
fn query_extension_function(
    socket: &impl AsSocket,
    guid: &windows_sys::core::GUID,
    name: &str,
) -> io::Result<*mut c_void> {
    let mut function: *mut c_void = ptr::null_mut();
    let mut len = 0;
    // SAFETY: `WSAIoctl` with `SIO_GET_EXTENSION_FUNCTION_POINTER`, no overlapped structure
    // and no completion routine completes before returning; it reads `cbInBuffer` bytes at
    // `lpvInBuffer` and writes at most `cbOutBuffer` bytes at `lpvOutBuffer` and the count at
    // `lpcbBytesReturned`. Those are the live `guid`, the local `function` (a raw pointer,
    // valid for any initialized bytes) and `len`, each with its own size. The handle is open
    // for the borrow of `socket` (`BorrowedSocket`).
    let rc = unsafe {
        WinSock::WSAIoctl(
            socket.as_socket().as_raw_socket() as _,
            WinSock::SIO_GET_EXTENSION_FUNCTION_POINTER,
            ptr::from_ref(guid).cast(),
            size_of_val(guid) as u32,
            (&raw mut function).cast(),
            size_of_val(&function) as u32,
            &mut len,
            ptr::null_mut(),
            None,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != size_of_val(&function) || function.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("network stack does not support {name} function"),
        ));
    }
    Ok(function)
}

fn max_gso_segments(socket: &impl AsSocket) -> io::Result<usize> {
    const GSO_SIZE: c_uint = 1500;
    match set_socket_option(
        socket,
        WinSock::IPPROTO_UDP,
        WinSock::UDP_SEND_MSG_SIZE,
        GSO_SIZE,
    ) {
        Ok(()) => {
            // UDP_SEND_MSG_SIZE is socket-wide. Reset the probe so ordinary
            // datagrams are not segmented unless a send requests it.
            set_socket_option(socket, WinSock::IPPROTO_UDP, WinSock::UDP_SEND_MSG_SIZE, 0)?;
            // Empirically found on Windows 11 x64.
            Ok(512)
        }
        Err(_) => Ok(1),
    }
}

/// Whether a received datagram is to be dropped as truncated: its payload did not
/// fit, or its control data did (which may have lost the coalesced segment size).
fn datagram_truncated(flags: u32) -> bool {
    flags & (WinSock::MSG_TRUNC | WinSock::MSG_PARTIAL | WinSock::MSG_CTRUNC) != 0
}

/// A failed `WSARecvMsg`: `Ok` when only the datagram was truncated.
fn receive_failure(error: io::Error) -> io::Result<()> {
    match error.raw_os_error() {
        Some(WinSock::WSAEMSGSIZE) => Ok(()),
        // An ICMP time-exceeded for an earlier send: like WSAECONNRESET it is about one
        // datagram, not the socket, but std leaves it uncategorized.
        Some(WinSock::WSAENETRESET) => Err(io::Error::new(io::ErrorKind::ConnectionReset, error)),
        _ => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_datagram_icmp_errors_read_as_resets() {
        for code in [WinSock::WSAECONNRESET, WinSock::WSAENETRESET] {
            let error = receive_failure(io::Error::from_raw_os_error(code)).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionReset, "{code}");
        }
        receive_failure(io::Error::from_raw_os_error(WinSock::WSAEMSGSIZE)).unwrap();
        let error =
            receive_failure(io::Error::from_raw_os_error(WinSock::WSAENOTSOCK)).unwrap_err();
        assert_ne!(error.kind(), io::ErrorKind::ConnectionReset);
    }

    /// Payload and control truncation both mark the datagram, so it is dropped
    /// without failing the socket.
    #[test]
    fn receive_flags_mark_payload_and_control_truncation() {
        assert!(!datagram_truncated(0));
        for flags in [
            WinSock::MSG_TRUNC,
            WinSock::MSG_PARTIAL,
            WinSock::MSG_CTRUNC,
            WinSock::MSG_CTRUNC | WinSock::MSG_TRUNC,
            WinSock::MSG_CTRUNC | WinSock::MSG_PARTIAL,
        ] {
            assert!(datagram_truncated(flags), "{flags:#x}");
        }
    }
}
