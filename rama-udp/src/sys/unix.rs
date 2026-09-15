#[cfg(not(any(
    target_vendor = "apple",
    target_os = "openbsd",
    target_os = "solaris",
    target_os = "illumos"
)))]
use std::ptr;
use std::{
    io::{self, IoSliceMut},
    mem::{self, MaybeUninit},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::AsRawFd,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use rama_net::socket::core::{SockAddr, SockRef};

use super::{EcnCodepoint, RecvMeta, Transmit, UdpSockRef, cmsg};

#[cfg(any(target_os = "linux", target_os = "android"))]
use super::linux::gso;

#[cfg(any(target_os = "linux", target_os = "android"))]
const IP_RECV_ORIGINAL_DESTINATION: libc::c_int = 20;
#[cfg(any(target_os = "linux", target_os = "android"))]
const IPV6_RECV_ORIGINAL_DESTINATION: libc::c_int = 74;

/// Tokio-compatible UDP socket with some useful specializations
///
/// Unlike a standard tokio UDP socket, this allows ECN bits to be read and written on some
/// platforms.
#[derive(Debug)]
pub(crate) struct UdpSocketState {
    max_gso_segments: AtomicUsize,
    gro_segments: usize,
    may_fragment: bool,
    send_ecn: bool,
    receive_ecn: bool,
    send_source_ip: bool,
    receive_local_ip: bool,
    receive_interface: bool,
    receive_original_destination: bool,
    receive_timestamp: bool,
    send_dscp_v4: u8,
    send_dscp_v6: u8,

    /// Cached `SO_SNDBUF`.
    #[cfg(target_vendor = "apple")]
    send_buffer_size: AtomicUsize,
}

impl UdpSocketState {
    pub(crate) fn new(
        sock: UdpSockRef<'_>,
        _receive_original_destination: bool,
    ) -> io::Result<Self> {
        let io = sock.0;
        let mut cmsg_platform_space = 0;
        #[cfg(not(any(target_os = "redox", target_os = "hurd")))]
        if cfg!(target_os = "linux")
            || cfg!(any(
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd"
            ))
            || cfg!(target_vendor = "apple")
            || cfg!(target_os = "android")
            || cfg!(any(target_os = "solaris", target_os = "illumos"))
        {
            cmsg_platform_space +=
                <libc::cmsghdr as cmsg::CMsgHdr>::cmsg_space(size_of::<libc::in6_pktinfo>());
        }

        if cmsg::LEN
            < <libc::cmsghdr as cmsg::CMsgHdr>::cmsg_space(size_of::<libc::c_int>())
                + cmsg_platform_space
            || align_of::<libc::cmsghdr>() > align_of::<cmsg::Aligned<[u8; 0]>>()
        {
            return Err(io::Error::other(
                "invalid UDP control-message buffer layout",
            ));
        }

        io.set_nonblocking(true)?;

        let addr = io.local_addr()?;
        let is_ipv4 = addr.family() == libc::AF_INET as libc::sa_family_t;
        let only_v6 = !is_ipv4 && io.only_v6()?;
        let supports_ipv4 = is_ipv4 || !only_v6;
        let supports_ipv6 = !is_ipv4;
        let send_dscp_v4 = if supports_ipv4 {
            get_socket_option(&*io, libc::IPPROTO_IP, libc::IP_TOS).unwrap_or_default() as u8
                & !0b11
        } else {
            0
        };
        #[cfg(not(any(target_os = "redox", target_os = "hurd")))]
        let send_dscp_v6 = if supports_ipv6 {
            get_socket_option(&*io, libc::IPPROTO_IPV6, libc::IPV6_TCLASS).unwrap_or_default() as u8
                & !0b11
        } else {
            0
        };
        #[cfg(any(target_os = "redox", target_os = "hurd"))]
        let send_dscp_v6 = 0;

        let mut ecn_v4 = !supports_ipv4;
        let mut ecn_v6 = !supports_ipv6;
        let mut local_ip_v4 = !supports_ipv4;
        let mut local_ip_v6 = !supports_ipv6;
        let mut interface_v6 = !supports_ipv6;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let timestamp;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let timestamp = false;

        // mac and ios do not support IP_RECVTOS on dual-stack sockets :(
        // older macos versions also don't have the flag and will error out if we don't ignore it
        #[cfg(not(any(
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly",
            target_os = "hurd",
            target_os = "solaris",
            target_os = "illumos"
        )))]
        if supports_ipv4 {
            ecn_v4 = set_socket_option(&*io, libc::IPPROTO_IP, libc::IP_RECVTOS, OPTION_ON).is_ok();
        }

        let mut may_fragment = cfg!(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd",
            target_vendor = "apple"
        )));
        #[cfg_attr(
            not(any(target_os = "linux", target_os = "android")),
            expect(unused_mut)
        )]
        let mut gro_segments = 1;

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // Forbid IPv4 fragmentation. Set even for IPv6 to account for IPv6 mapped IPv4 addresses.
            // Set `may_fragment` to `true` if this option is not supported on the platform.
            may_fragment |= !set_socket_option_supported(
                &*io,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                libc::IP_PMTUDISC_PROBE,
            );

            if supports_ipv4 {
                let pktinfo =
                    set_socket_option(&*io, libc::IPPROTO_IP, libc::IP_PKTINFO, OPTION_ON).is_ok();
                local_ip_v4 = pktinfo;
            }
            if supports_ipv6 {
                // Set `may_fragment` to `true` if this option is not supported on the platform.
                may_fragment |= !set_socket_option_supported(
                    &*io,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MTU_DISCOVER,
                    libc::IPV6_PMTUDISC_PROBE,
                );
            }

            if set_socket_option(&*io, libc::SOL_UDP, libc::UDP_GRO, OPTION_ON).is_ok() {
                // As defined in net/ipv4/udp_offload.c
                // #define UDP_GRO_CNT_MAX 64
                //
                // NOTE: this MUST be set to UDP_GRO_CNT_MAX to ensure that the receive buffer size
                // (get_max_udp_payload_size() * gro_segments()) is large enough to hold the largest GRO
                // list the kernel might potentially produce. See
                // https://github.com/quinn-rs/quinn/pull/1354.
                gro_segments = 64
            }

            timestamp =
                set_socket_option(&*io, libc::SOL_SOCKET, libc::SO_TIMESTAMPNS, OPTION_ON).is_ok();
        }
        #[cfg(any(target_os = "freebsd", target_vendor = "apple"))]
        {
            if supports_ipv4 {
                // Set `may_fragment` to `true` if this option is not supported on the platform.
                may_fragment |= !set_socket_option_supported(
                    &*io,
                    libc::IPPROTO_IP,
                    libc::IP_DONTFRAG,
                    OPTION_ON,
                );
            }
        }
        #[cfg(any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_vendor = "apple",
            target_os = "solaris",
            target_os = "illumos"
        ))]
        // IP_RECVDSTADDR == IP_SENDSRCADDR on FreeBSD
        // macOS uses only IP_RECVDSTADDR, no IP_SENDSRCADDR on macOS (the same on Solaris)
        // macOS also supports IP_PKTINFO
        {
            if supports_ipv4 {
                local_ip_v4 =
                    set_socket_option(&*io, libc::IPPROTO_IP, libc::IP_RECVDSTADDR, OPTION_ON)
                        .is_ok();
            }
        }

        // Options standardized in RFC 3542
        #[cfg(not(target_os = "redox"))]
        if supports_ipv6 {
            let pktinfo =
                set_socket_option(&*io, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, OPTION_ON)
                    .is_ok();
            local_ip_v6 = pktinfo;
            interface_v6 = pktinfo;
            ecn_v6 = set_socket_option(&*io, libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS, OPTION_ON)
                .is_ok();
            // Linux's IP_PMTUDISC_PROBE allows us to operate under interface MTU rather than the
            // kernel's path MTU guess, but actually disabling fragmentation requires this too. See
            // __ip6_append_data in ip6_output.c.
            // Set `may_fragment` to `true` if this option is not supported on the platform.
            may_fragment |= !set_socket_option_supported(
                &*io,
                libc::IPPROTO_IPV6,
                libc::IPV6_DONTFRAG,
                OPTION_ON,
            );
        }

        // Enlarge SO_SNDBUF to a safe minimum.
        #[cfg(target_vendor = "apple")]
        if io
            .send_buffer_size()
            .is_ok_and(|cur| cur < Self::MIN_SAFE_SNDBUF)
        {
            drop(io.set_send_buffer_size(Self::MIN_SAFE_SNDBUF));
        }

        let interface_v4 = if cfg!(any(target_os = "linux", target_os = "android")) {
            local_ip_v4
        } else {
            !supports_ipv4
        };
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let original_destination = if _receive_original_destination {
            let v4 = !supports_ipv4
                || set_socket_option(
                    &*io,
                    libc::IPPROTO_IP,
                    IP_RECV_ORIGINAL_DESTINATION,
                    OPTION_ON,
                )
                .is_ok();
            let v6 = !supports_ipv6
                || set_socket_option(
                    &*io,
                    libc::IPPROTO_IPV6,
                    IPV6_RECV_ORIGINAL_DESTINATION,
                    OPTION_ON,
                )
                .is_ok();
            v4 && v6
        } else {
            false
        };
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let original_destination = false;

        Ok(Self {
            max_gso_segments: AtomicUsize::new(gso::max_gso_segments(&*io)),
            gro_segments,
            may_fragment,
            send_ecn: cfg!(not(any(
                target_os = "hurd",
                target_os = "netbsd",
                target_os = "redox"
            ))),
            receive_ecn: ecn_v4 && ecn_v6,
            send_source_ip: cfg!(any(
                target_os = "linux",
                target_os = "android",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_vendor = "apple",
                target_os = "solaris",
                target_os = "illumos"
            )),
            receive_local_ip: local_ip_v4 && local_ip_v6,
            receive_interface: interface_v4 && interface_v6,
            receive_original_destination: original_destination,
            receive_timestamp: timestamp,
            send_dscp_v4,
            send_dscp_v6,
            #[cfg(target_vendor = "apple")]
            send_buffer_size: AtomicUsize::new(io.send_buffer_size().unwrap_or(usize::MAX)),
        })
    }

    /// Sends a [`Transmit`] on the given socket without any additional error handling
    pub(crate) fn try_send(
        &self,
        socket: &UdpSockRef<'_>,
        transmit: &Transmit<'_>,
    ) -> io::Result<()> {
        send(self, &socket.0, transmit)
    }

    #[cfg(not(any(
        target_vendor = "apple",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "redox",
        target_os = "hurd",
        target_os = "solaris",
        target_os = "illumos"
    )))]
    pub(crate) fn recv(
        &self,
        socket: &UdpSockRef<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        let _ = self.gro_segments;
        recv_via_recvmmsg(&socket.0, bufs, meta)
    }

    #[cfg(any(
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "redox",
        target_os = "hurd",
        target_os = "solaris",
        target_os = "illumos",
        target_vendor = "apple"
    ))]
    pub(crate) fn recv(
        &self,
        socket: &UdpSockRef<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        let _ = self.gro_segments;
        recv_single(&socket.0, bufs, meta)
    }

    /// Maximum number of segments to transmit if Generic Send Offload (GSO) is enabled
    ///
    /// This is 1 if the platform doesn't support GSO.
    ///
    /// Subject to change if errors are detected while using GSO.
    #[inline]
    pub(crate) fn max_gso_segments(&self) -> usize {
        self.max_gso_segments.load(Ordering::Relaxed)
    }

    /// The number of segments to read when GRO is enabled
    ///
    /// Used as a factor to compute the receive buffer size.
    ///
    /// Returns 1 if the platform doesn't support GRO.
    #[inline]
    pub(crate) fn gro_segments(&self) -> usize {
        self.gro_segments
    }

    /// Whether transmitted datagrams might get fragmented by the IP layer
    ///
    /// Returns `false` on targets which employ e.g. the `IPV6_DONTFRAG` socket option.
    #[inline]
    pub(crate) fn may_fragment(&self) -> bool {
        self.may_fragment
    }

    pub(crate) fn capabilities(&self) -> super::SocketCapabilities {
        super::SocketCapabilities {
            send_ecn: self.send_ecn,
            receive_ecn: self.receive_ecn,
            send_source_ip: self.send_source_ip,
            receive_local_ip: self.receive_local_ip,
            receive_interface: self.receive_interface,
            receive_original_destination: self.receive_original_destination,
            receive_timestamp: self.receive_timestamp,
            receive_truncation: true,
        }
    }

    /// Smallest `SO_SNDBUF` that mitigates <https://feedbackassistant.apple.com/feedback/23671230>:
    /// On macOS, a non-blocking SOCK_DGRAM `sendmsg`/`sendmsg_x` call with ancillary data returns
    /// `EWOULDBLOCK` when the payload length is at or just under `SO_SNDBUF`.
    #[cfg(target_vendor = "apple")]
    const MIN_SAFE_SNDBUF: usize = 65535 + cmsg::LEN;

    /// Safety net returning `EMSGSIZE` for payload sizes in the bug's region.
    #[cfg(target_vendor = "apple")]
    pub(crate) fn check_send_buffer_limit(
        &self,
        resid: usize,
        hdr: &impl cmsg::MsgHdr,
    ) -> io::Result<()> {
        let needed = resid.saturating_add(hdr.control_len());
        let sndbuf = self.send_buffer_size.load(Ordering::Relaxed);
        if needed > sndbuf {
            crate::log::debug!("EMSGSIZE for {needed}-byte send: exceeds SO_SNDBUF ({sndbuf})");
            return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
        }
        Ok(())
    }
}

#[cfg(not(any(target_vendor = "apple", target_os = "openbsd", target_os = "netbsd")))]
fn send(state: &UdpSocketState, io: &SockRef<'_>, transmit: &Transmit<'_>) -> io::Result<()> {
    let _ = state;
    #[cfg(target_os = "freebsd")]
    let encode_src_ip = {
        let addr = io.local_addr()?;
        let is_ipv4 = addr.family() == libc::AF_INET as libc::sa_family_t;
        if is_ipv4 {
            match addr.as_socket_ipv4() {
                Some(socket) if socket.ip() != &Ipv4Addr::UNSPECIFIED => {
                    if transmit
                        .src_ip
                        .is_some_and(|source| source != IpAddr::V4(*socket.ip()))
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "selected source IP differs from the bound FreeBSD address",
                        ));
                    }
                    false
                }
                _ => true,
            }
        } else {
            true
        }
    };
    #[cfg(not(target_os = "freebsd"))]
    let encode_src_ip = true;
    // SAFETY: all-zero is a valid empty `msghdr` and `iovec`; `prepare_msg`
    // initializes the fields used by `sendmsg` before the call.
    let mut msg_hdr: libc::msghdr = unsafe { mem::zeroed() };
    // SAFETY: see the comment above; a zeroed `iovec` represents an empty
    // buffer until `prepare_msg` fills it.
    let mut iovec: libc::iovec = unsafe { mem::zeroed() };
    let mut cmsgs = cmsg::Aligned([0u8; cmsg::LEN]);
    let dst_addr = SockAddr::from(transmit.destination);
    prepare_msg(
        state,
        transmit,
        &dst_addr,
        &mut msg_hdr,
        &mut iovec,
        &mut cmsgs,
        encode_src_ip,
    )?;

    loop {
        // SAFETY: `prepare_msg` initialized every pointer and length consumed
        // by `sendmsg`, and all referenced values remain alive for this call.
        let n = unsafe { libc::sendmsg(io.as_raw_fd(), &msg_hdr, 0) };

        if n >= 0 {
            return Ok(());
        }

        let e = io::Error::last_os_error();
        match e.kind() {
            // Retry the transmission
            io::ErrorKind::Interrupted => {}
            io::ErrorKind::WouldBlock => return Err(e),
            _ => {
                // Some network adapters and drivers do not support GSO. Unfortunately, Linux
                // offers no easy way for us to detect this short of an EIO or sometimes EINVAL
                // when we try to actually send datagrams using it.
                #[cfg(any(target_os = "linux", target_os = "android"))]
                if transmit.effective_segment_size().is_some()
                    && let Some(libc::EIO | libc::EINVAL) = e.raw_os_error()
                {
                    // Prevent new transmits from being scheduled using GSO. Existing GSO transmits
                    // may already be in the pipeline, so we need to tolerate additional failures.
                    if state.max_gso_segments() > 1 {
                        crate::log::info!(
                            "`libc::sendmsg` failed with {e}; halting segmentation offload"
                        );
                        state.max_gso_segments.store(1, Ordering::Relaxed);
                    }
                }

                return Err(e);
            }
        }
    }
}

// NOTE: Apple provides private `sendmsg_x` and `recvmsg_x` batching APIs.
// We leave them disabled because their private ABI can change; revisit if
// they can be used with acceptable compatibility risk.
#[cfg(any(target_os = "openbsd", target_os = "netbsd", target_vendor = "apple"))]
fn send(state: &UdpSocketState, io: &SockRef<'_>, transmit: &Transmit<'_>) -> io::Result<()> {
    send_single(state, io, transmit)
}

#[cfg(any(target_os = "openbsd", target_os = "netbsd", target_vendor = "apple"))]
pub(crate) fn send_single(
    state: &UdpSocketState,
    io: &SockRef<'_>,
    transmit: &Transmit<'_>,
) -> io::Result<()> {
    // SAFETY: all-zero is a valid empty `msghdr`; `prepare_msg` initializes
    // every field consumed by `sendmsg`.
    let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
    // SAFETY: all-zero is a valid empty `iovec`; `prepare_msg` fills its base
    // pointer and length before the system call.
    let mut iov: libc::iovec = unsafe { mem::zeroed() };
    let mut ctrl = cmsg::Aligned([0u8; cmsg::LEN]);
    let addr = SockAddr::from(transmit.destination);
    prepare_msg(
        state,
        transmit,
        &addr,
        &mut hdr,
        &mut iov,
        &mut ctrl,
        cfg!(target_vendor = "apple") || cfg!(target_os = "openbsd") || cfg!(target_os = "netbsd"),
    )?;
    #[cfg(target_vendor = "apple")]
    state.check_send_buffer_limit(transmit.contents.len(), &hdr)?;
    // SAFETY: `prepare_msg` initialized every pointer and length consumed by
    // `sendmsg`, and all referenced values outlive the call.
    retry_if_interrupted(|| unsafe { libc::sendmsg(io.as_raw_fd(), &hdr, 0) })?;
    Ok(())
}

/// Receive using the batched `recvmmsg` syscall
#[cfg(not(any(
    target_vendor = "apple",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "redox",
    target_os = "hurd",
    target_os = "solaris",
    target_os = "illumos"
)))]
fn recv_via_recvmmsg(
    io: &SockRef<'_>,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
) -> io::Result<usize> {
    // The kernel may initialize only the active sockaddr prefix, so zero the
    // remaining storage before `decode_recv` materializes the whole value.
    let mut names = [MaybeUninit::<libc::sockaddr_storage>::zeroed(); BATCH_SIZE];
    let mut ctrls = [cmsg::Aligned(MaybeUninit::<[u8; cmsg::LEN]>::uninit()); BATCH_SIZE];
    // SAFETY: all-zero is a valid empty array of `mmsghdr` values;
    // `prepare_recv` initializes every entry passed to `recvmmsg`.
    let mut hdrs = unsafe { mem::zeroed::<[libc::mmsghdr; BATCH_SIZE]>() };
    let max_msg_count = bufs.len().min(BATCH_SIZE);
    for i in 0..max_msg_count {
        prepare_recv(
            &mut bufs[i],
            &mut names[i],
            &mut ctrls[i],
            &mut hdrs[i].msg_hdr,
        );
    }
    let msg_count = retry_if_interrupted(|| {
        // SAFETY: each submitted header contains live writable address,
        // payload and control buffers with matching lengths.
        unsafe {
            libc::recvmmsg(
                io.as_raw_fd(),
                hdrs.as_mut_ptr(),
                bufs.len().min(BATCH_SIZE) as _,
                RECV_FLAGS as _,
                ptr::null_mut::<libc::timespec>(),
            ) as isize
        }
    })?;
    for i in 0..(msg_count as usize) {
        let original_len = hdrs[i].msg_len as usize;
        let copied_len = original_len.min(bufs[i].len());
        // `recvmmsg` has already consumed the whole batch. If kernel metadata
        // is malformed, fail the call instead of silently returning a prefix.
        meta[i] = decode_recv(
            &names[i],
            &hdrs[i].msg_hdr,
            copied_len,
            original_len,
            hdrs[i].msg_hdr.msg_flags & libc::MSG_TRUNC != 0,
        )?;
    }
    Ok(msg_count as usize)
}

#[cfg(any(
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "redox",
    target_os = "hurd",
    target_os = "solaris",
    target_os = "illumos",
    target_vendor = "apple"
))]
pub(crate) fn recv_single(
    io: &SockRef<'_>,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
) -> io::Result<usize> {
    // The kernel may initialize only the active sockaddr prefix.
    let mut name = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut ctrl = cmsg::Aligned(MaybeUninit::<[u8; cmsg::LEN]>::uninit());
    // SAFETY: all-zero is a valid empty `msghdr`; `prepare_recv` initializes
    // every field consumed by `recvmsg`.
    let mut hdr = unsafe { mem::zeroed::<libc::msghdr>() };
    prepare_recv(&mut bufs[0], &mut name, &mut ctrl, &mut hdr);
    let n = loop {
        // SAFETY: `prepare_recv` supplied writable buffers and matching lengths;
        // they and the header remain alive for the duration of the call.
        let n = unsafe { libc::recvmsg(io.as_raw_fd(), &mut hdr, RECV_FLAGS) };

        if n >= 0 {
            break n;
        }

        let e = io::Error::last_os_error();
        match e.kind() {
            // Retry receiving
            io::ErrorKind::Interrupted => {}
            _ => return Err(e),
        }
    };
    let original_len = n as usize;
    meta[0] = decode_recv(
        &name,
        &hdr,
        original_len.min(bufs[0].len()),
        original_len,
        hdr.msg_flags & libc::MSG_TRUNC != 0,
    )?;
    Ok(1)
}

fn prepare_msg(
    state: &UdpSocketState,
    transmit: &Transmit<'_>,
    dst_addr: &SockAddr,
    hdr: &mut libc::msghdr,
    iov: &mut libc::iovec,
    ctrl: &mut cmsg::Aligned<[u8; cmsg::LEN]>,
    encode_src_ip: bool,
) -> io::Result<()> {
    let _ = encode_src_ip;
    iov.iov_base = transmit.contents.as_ptr() as *const _ as *mut _;
    iov.iov_len = transmit.contents.len();

    // POSIX declares this pointer mutable even though sendmsg does not modify it.
    let name = dst_addr.as_ptr() as *mut libc::c_void;
    let namelen = dst_addr.len();
    hdr.msg_name = name as *mut _;
    hdr.msg_namelen = namelen;
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;

    hdr.msg_control = ctrl.0.as_mut_ptr() as _;
    hdr.msg_controllen = cmsg::LEN as _;
    // SAFETY: `hdr` now points at the aligned, writable `ctrl` buffer, which
    // remains borrowed until the encoder is finished.
    let mut encoder = unsafe { cmsg::Encoder::new(hdr) };
    // True for IPv4 or IPv4-Mapped IPv6
    let is_ipv4 = transmit.destination.is_ipv4()
        || matches!(transmit.destination.ip(), IpAddr::V6(addr) if addr.to_ipv4_mapped().is_some());
    if let Some(ecn) = transmit.ecn {
        if is_ipv4 {
            #[cfg(not(target_os = "netbsd"))]
            {
                let traffic_class = state.send_dscp_v4 | ecn.bits();
                encoder.push(libc::IPPROTO_IP, libc::IP_TOS, traffic_class as IpTosTy)?;
            }
        } else {
            #[cfg(not(target_os = "redox"))]
            {
                let traffic_class = state.send_dscp_v6 | ecn.bits();
                encoder.push(
                    libc::IPPROTO_IPV6,
                    libc::IPV6_TCLASS,
                    libc::c_int::from(traffic_class),
                )?;
            }
        }
    }

    if let Some(segment_size) = transmit.effective_segment_size() {
        gso::set_segment_size(&mut encoder, segment_size as u16)?;
    }

    if let Some(ip) = &transmit.src_ip {
        match ip {
            IpAddr::V4(v4) => {
                #[cfg(any(target_os = "linux", target_os = "android"))]
                {
                    let pktinfo = libc::in_pktinfo {
                        ipi_ifindex: 0,
                        ipi_spec_dst: libc::in_addr {
                            s_addr: u32::from_ne_bytes(v4.octets()),
                        },
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    };
                    encoder.push(libc::IPPROTO_IP, libc::IP_PKTINFO, pktinfo)?;
                }
                #[cfg(any(
                    target_os = "freebsd",
                    target_os = "openbsd",
                    target_os = "netbsd",
                    target_vendor = "apple",
                    target_os = "solaris",
                    target_os = "illumos"
                ))]
                {
                    if encode_src_ip {
                        let addr = libc::in_addr {
                            s_addr: u32::from_ne_bytes(v4.octets()),
                        };
                        encoder.push(libc::IPPROTO_IP, libc::IP_RECVDSTADDR, addr)?;
                    }
                }
            }
            #[cfg(any(target_os = "redox", target_os = "hurd"))]
            IpAddr::V6(_) => {}
            #[cfg(not(any(target_os = "redox", target_os = "hurd")))]
            IpAddr::V6(v6) => {
                let pktinfo = libc::in6_pktinfo {
                    ipi6_ifindex: 0,
                    ipi6_addr: libc::in6_addr {
                        s6_addr: v6.octets(),
                    },
                };
                encoder.push(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, pktinfo)?;
            }
        }
    }

    drop(encoder);
    Ok(())
}

fn prepare_recv(
    buf: &mut IoSliceMut<'_>,
    name: &mut MaybeUninit<libc::sockaddr_storage>,
    ctrl: &mut cmsg::Aligned<MaybeUninit<[u8; cmsg::LEN]>>,
    hdr: &mut libc::msghdr,
) {
    hdr.msg_name = name.as_mut_ptr() as _;
    hdr.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
    hdr.msg_iov = buf as *mut IoSliceMut<'_> as *mut libc::iovec;
    hdr.msg_iovlen = 1;
    hdr.msg_control = ctrl.0.as_mut_ptr() as _;
    hdr.msg_controllen = cmsg::LEN as _;
    hdr.msg_flags = 0;
}

pub(crate) fn decode_recv<M: cmsg::MsgHdr<ControlMessage = libc::cmsghdr>>(
    name: &MaybeUninit<libc::sockaddr_storage>,
    hdr: &M,
    len: usize,
    original_len: usize,
    truncated: bool,
) -> io::Result<RecvMeta> {
    // SAFETY: receive callers create `name` with `MaybeUninit::zeroed`, so the
    // complete storage is initialized even if the kernel writes only a prefix.
    let name = unsafe { name.assume_init() };
    let mut ctrl = ControlMetadata {
        ecn_bits: None,
        dst_ip: None,
        interface_index: None,
        original_destination: None,
        // In the absence of an explicit UDP_GRO control message this is one
        // datagram, even when `len` is only a truncated prefix.
        stride: original_len,
        timestamp: None,
    };

    // SAFETY: the receive syscall initialized `hdr`'s reported control-message
    // region, and its backing buffer remains alive while this function runs.
    let cmsg_iter = unsafe { cmsg::Iter::new(hdr) };
    for cmsg in cmsg_iter {
        // SAFETY: `cmsg` was yielded from the live native buffer walked by
        // `cmsg_iter`.
        unsafe { ctrl.decode(cmsg)? };
    }

    Ok(RecvMeta {
        len,
        original_len,
        stride: ctrl.stride,
        addr: decode_socket_addr(&name)?,
        ecn: ctrl.ecn_bits.map(EcnCodepoint::from_bits),
        dst_ip: ctrl.dst_ip,
        interface_index: ctrl.interface_index,
        original_destination: ctrl.original_destination,
        timestamp: ctrl.timestamp,
        truncated: truncated || original_len > len,
    })
}

/// Metadata decoded from control messages
struct ControlMetadata {
    ecn_bits: Option<u8>,
    dst_ip: Option<IpAddr>,
    interface_index: Option<u32>,
    original_destination: Option<SocketAddr>,
    stride: usize,
    timestamp: Option<Duration>,
}

impl ControlMetadata {
    /// Decodes a control message and updates the metadata state
    ///
    /// # Safety
    ///
    /// `cmsg` must come from a live native control-message buffer.
    unsafe fn decode(&mut self, cmsg: &libc::cmsghdr) -> io::Result<()> {
        match (cmsg.cmsg_level, cmsg.cmsg_type) {
            (libc::IPPROTO_IP, libc::IP_TOS) => {
                // SAFETY: required by this function's contract.
                self.ecn_bits = Some(unsafe { cmsg::decode::<u8, libc::cmsghdr>(cmsg) }?);
            }
            // FreeBSD uses IP_RECVTOS here, and we can be liberal because cmsgs are opt-in.
            #[cfg(not(any(
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly",
                target_os = "hurd",
                target_os = "solaris",
                target_os = "illumos"
            )))]
            (libc::IPPROTO_IP, libc::IP_RECVTOS) => {
                // SAFETY: required by this function's contract.
                self.ecn_bits = Some(unsafe { cmsg::decode::<u8, libc::cmsghdr>(cmsg) }?);
            }
            #[cfg(not(target_os = "redox",))]
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) => {
                // Temporary hack around broken macos ABI. Remove once upstream fixes it.
                // https://bugreport.apple.com/web/?problemID=48761855
                let byte_sized = cfg!(target_vendor = "apple")
                    && cmsg::CMsgHdr::len(cmsg)
                        == <libc::cmsghdr as cmsg::CMsgHdr>::cmsg_len(size_of::<u8>());
                if byte_sized {
                    // SAFETY: required by this function's contract.
                    self.ecn_bits = Some(unsafe { cmsg::decode::<u8, libc::cmsghdr>(cmsg) }?);
                } else {
                    // SAFETY: required by this function's contract.
                    self.ecn_bits =
                        Some(unsafe { cmsg::decode::<libc::c_int, libc::cmsghdr>(cmsg) }? as u8);
                }
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                // SAFETY: required by this function's contract.
                let pktinfo = unsafe { cmsg::decode::<libc::in_pktinfo, libc::cmsghdr>(cmsg) }?;
                self.dst_ip = Some(IpAddr::V4(Ipv4Addr::from(
                    pktinfo.ipi_addr.s_addr.to_ne_bytes(),
                )));
                self.interface_index = Some(pktinfo.ipi_ifindex as u32);
            }
            #[cfg(any(
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_vendor = "apple"
            ))]
            (libc::IPPROTO_IP, libc::IP_RECVDSTADDR) => {
                // SAFETY: required by this function's contract.
                let in_addr = unsafe { cmsg::decode::<libc::in_addr, libc::cmsghdr>(cmsg) }?;
                self.dst_ip = Some(IpAddr::V4(Ipv4Addr::from(in_addr.s_addr.to_ne_bytes())));
            }
            #[cfg(not(any(target_os = "redox", target_os = "hurd")))]
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                // SAFETY: required by this function's contract.
                let pktinfo = unsafe { cmsg::decode::<libc::in6_pktinfo, libc::cmsghdr>(cmsg) }?;
                self.dst_ip = Some(IpAddr::V6(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr)));
                #[cfg(target_os = "android")]
                {
                    self.interface_index = u32::try_from(pktinfo.ipi6_ifindex).ok();
                }
                #[cfg(not(target_os = "android"))]
                {
                    self.interface_index = Some(pktinfo.ipi6_ifindex);
                }
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            (libc::IPPROTO_IP, IP_RECV_ORIGINAL_DESTINATION) => {
                // SAFETY: required by this function's contract.
                let addr = unsafe { cmsg::decode::<libc::sockaddr_in, libc::cmsghdr>(cmsg) }?;
                self.original_destination = Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
                    u16::from_be(addr.sin_port),
                )));
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            (libc::IPPROTO_IPV6, IPV6_RECV_ORIGINAL_DESTINATION) => {
                // SAFETY: required by this function's contract.
                let addr = unsafe { cmsg::decode::<libc::sockaddr_in6, libc::cmsghdr>(cmsg) }?;
                self.original_destination = Some(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(addr.sin6_addr.s6_addr),
                    u16::from_be(addr.sin6_port),
                    addr.sin6_flowinfo,
                    addr.sin6_scope_id,
                )));
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            (libc::SOL_UDP, libc::UDP_GRO) => {
                // SAFETY: required by this function's contract.
                self.stride = unsafe { cmsg::decode::<libc::c_int, libc::cmsghdr>(cmsg) }? as usize;
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            (libc::SOL_SOCKET, libc::SCM_TIMESTAMPNS) => {
                // SAFETY: required by this function's contract.
                let ts = unsafe { cmsg::decode::<libc::timespec, libc::cmsghdr>(cmsg) }?;
                let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
                let nsecs = u32::try_from(ts.tv_nsec).unwrap_or(0);
                self.timestamp = Some(Duration::new(secs, nsecs));
            }
            _ => {}
        }
        Ok(())
    }
}

/// Decodes a `sockaddr_storage` into a `SocketAddr`
pub(crate) fn decode_socket_addr(name: &libc::sockaddr_storage) -> io::Result<SocketAddr> {
    match libc::c_int::from(name.ss_family) {
        libc::AF_INET => {
            // Safety: if the ss_family field is AF_INET then storage must be a sockaddr_in.
            let addr: &libc::sockaddr_in =
                unsafe { &*(name as *const _ as *const libc::sockaddr_in) };
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(addr.sin_port),
            )))
        }
        libc::AF_INET6 => {
            // Safety: if the ss_family field is AF_INET6 then storage must be a sockaddr_in6.
            let addr: &libc::sockaddr_in6 =
                unsafe { &*(name as *const _ as *const libc::sockaddr_in6) };
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(addr.sin6_addr.s6_addr),
                u16::from_be(addr.sin6_port),
                addr.sin6_flowinfo,
                addr.sin6_scope_id,
            )))
        }
        f => Err(io::Error::other(format!(
            "expected AF_INET or AF_INET6, got {f}"
        ))),
    }
}

#[cfg(not(target_vendor = "apple"))]
// Chosen somewhat arbitrarily; might benefit from additional tuning.
pub(crate) const BATCH_SIZE: usize = 32;

#[cfg(target_vendor = "apple")]
pub(crate) const BATCH_SIZE: usize = 1;

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod gso {
    use super::*;

    pub(super) fn max_gso_segments(_socket: &impl AsRawFd) -> usize {
        1
    }

    pub(super) fn set_segment_size(
        _encoder: &mut cmsg::Encoder<'_, libc::msghdr>,
        _segment_size: u16,
    ) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "freebsd")]
type IpTosTy = libc::c_uchar;
#[cfg(not(any(target_os = "freebsd", target_os = "netbsd")))]
pub(crate) type IpTosTy = libc::c_int;

/// Returns whether the given socket option is supported on the current platform
///
/// These controls are optimizations, not socket-construction requirements. Any
/// failure is reflected by the socket capability snapshot instead of making an
/// otherwise usable UDP socket fail to bind.
fn set_socket_option_supported(
    socket: &impl AsRawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> bool {
    set_socket_option(socket, level, name, value).is_ok()
}

pub(crate) fn set_socket_option(
    socket: &impl AsRawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    // SAFETY: the file descriptor belongs to `socket`; the value pointer is
    // valid for the supplied length and remains alive for the call.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
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

fn get_socket_option(
    socket: &impl AsRawFd,
    level: libc::c_int,
    name: libc::c_int,
) -> io::Result<libc::c_int> {
    let mut value = 0;
    let mut length = size_of_val(&value) as libc::socklen_t;
    // SAFETY: the file descriptor belongs to `socket`; both output pointers are
    // valid, writable and paired with their correct lengths.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            level,
            name,
            &mut value as *mut _ as _,
            &mut length,
        )
    };

    match rc == 0 {
        true => Ok(value),
        false => Err(io::Error::last_os_error()),
    }
}

const OPTION_ON: libc::c_int = 1;

// Linux returns the full datagram length when MSG_TRUNC is supplied. BSD
// implementations instead use the output flag to report truncation and can
// echo an input MSG_TRUNC flag even for a complete datagram.
#[cfg(any(target_os = "linux", target_os = "android"))]
const RECV_FLAGS: libc::c_int = libc::MSG_TRUNC;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const RECV_FLAGS: libc::c_int = 0;

/// Calls `f` in a loop, retrying on `EINTR`
///
/// Returns the non-negative result or the first non-`EINTR` error.
pub(crate) fn retry_if_interrupted(mut f: impl FnMut() -> isize) -> io::Result<isize> {
    loop {
        let n = f();
        if n >= 0 {
            return Ok(n);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Native storage for one address family, written through the same layout
    /// the kernel uses when it fills `msg_name`.
    fn storage_v4(addr: Ipv4Addr, port: u16) -> libc::sockaddr_storage {
        // SAFETY: all-zero is a valid `sockaddr_storage`, whose fields are
        // integers and address bytes.
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        // SAFETY: `sockaddr_storage` is defined to be large enough and
        // sufficiently aligned for any address family, `sockaddr_in` included.
        let sin = unsafe { &mut *(&raw mut storage).cast::<libc::sockaddr_in>() };
        sin.sin_family = libc::AF_INET as _;
        sin.sin_port = port.to_be();
        sin.sin_addr.s_addr = u32::from_ne_bytes(addr.octets());
        storage
    }

    fn storage_v6(
        addr: Ipv6Addr,
        port: u16,
        flowinfo: u32,
        scope_id: u32,
    ) -> libc::sockaddr_storage {
        // SAFETY: as in `storage_v4`.
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        // SAFETY: `sockaddr_storage` is also aligned and sized for
        // `sockaddr_in6`.
        let sin6 = unsafe { &mut *(&raw mut storage).cast::<libc::sockaddr_in6>() };
        sin6.sin6_family = libc::AF_INET6 as _;
        sin6.sin6_port = port.to_be();
        sin6.sin6_addr.s6_addr = addr.octets();
        sin6.sin6_flowinfo = flowinfo;
        sin6.sin6_scope_id = scope_id;
        storage
    }

    /// Reinterpret storage written by [`storage_v4`] as the `sockaddr_in`
    /// payload the kernel puts in an original-destination control message.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn sockaddr_in_payload(storage: &libc::sockaddr_storage) -> libc::sockaddr_in {
        // SAFETY: `storage_v4` wrote a complete `sockaddr_in` into storage that
        // is aligned and large enough for one.
        unsafe { *(&raw const *storage).cast::<libc::sockaddr_in>() }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn sockaddr_in6_payload(storage: &libc::sockaddr_storage) -> libc::sockaddr_in6 {
        // SAFETY: as above, for the storage written by `storage_v6`.
        unsafe { *(&raw const *storage).cast::<libc::sockaddr_in6>() }
    }

    /// Encode control messages into `control` and decode them the way a receive
    /// does, so the platform's own `cmsghdr` layout and chain walk are what is
    /// under test rather than a hand-rolled stand-in.
    fn decode_with(
        control: &mut cmsg::Aligned<[u8; cmsg::LEN]>,
        name: libc::sockaddr_storage,
        len: usize,
        original_len: usize,
        push: impl FnOnce(&mut cmsg::Encoder<'_, libc::msghdr>),
    ) -> io::Result<RecvMeta> {
        // SAFETY: all-zero is a valid empty `msghdr`; the control pointer and
        // length written below describe `control`, which outlives this call.
        let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
        hdr.msg_control = control.0.as_mut_ptr().cast();
        hdr.msg_controllen = cmsg::LEN as _;
        {
            // SAFETY: `hdr`'s control buffer is `control`: aligned for
            // `cmsghdr`, writable for its whole reported length, and passed to
            // no system call while the encoder lives.
            let mut encoder = unsafe { cmsg::Encoder::new(&mut hdr) };
            push(&mut encoder);
        }
        decode_recv(&MaybeUninit::new(name), &hdr, len, original_len, false)
    }

    fn loopback_name() -> libc::sockaddr_storage {
        storage_v4(Ipv4Addr::LOCALHOST, 443)
    }

    /// A port is carried in network order and an address as its four octets, so
    /// a peer that is not a palindrome in either would survive a byte-order
    /// mistake in only one direction.
    #[test]
    fn the_peer_address_decodes_from_native_v4_storage() {
        let addr = decode_socket_addr(&storage_v4(Ipv4Addr::new(192, 0, 2, 7), 0x1234)).unwrap();
        assert_eq!(
            addr,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 7), 0x1234))
        );
    }

    /// The v6 form carries two more fields, and a scope identifier is what makes
    /// a link-local reply reach the right interface.
    #[test]
    fn the_peer_address_decodes_from_native_v6_storage() {
        let ip: Ipv6Addr = "2001:db8::7".parse().unwrap();
        let addr = decode_socket_addr(&storage_v6(ip, 0x1234, 7, 9)).unwrap();
        assert_eq!(addr, SocketAddr::V6(SocketAddrV6::new(ip, 0x1234, 7, 9)));
    }

    #[test]
    fn an_address_family_that_is_not_ip_is_rejected() {
        // SAFETY: all-zero is a valid `sockaddr_storage`.
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        storage.ss_family = libc::AF_UNIX as _;
        let error = decode_socket_addr(&storage).unwrap_err();
        assert!(
            error.to_string().contains(&libc::AF_UNIX.to_string()),
            "the refusal names the family it got: {error}"
        );
    }

    /// Without a segmentation control message the read is one datagram, and
    /// every optional piece of metadata stays absent rather than defaulting to
    /// a value a caller could mistake for one the kernel reported.
    #[test]
    fn a_receive_without_control_messages_reports_one_whole_datagram() {
        let mut control = cmsg::Aligned([0; cmsg::LEN]);
        let meta = decode_with(&mut control, loopback_name(), 1200, 1200, |_| {}).unwrap();

        assert_eq!(meta.len, 1200);
        assert_eq!(meta.stride, 1200);
        assert!(!meta.truncated);
        assert_eq!(meta.ecn, None);
        assert_eq!(meta.dst_ip, None);
        assert_eq!(meta.interface_index, None);
        assert_eq!(meta.original_destination, None);
        assert_eq!(meta.timestamp, None);
    }

    /// Truncation is inferred from the lengths even when the receive call did
    /// not flag it, and the stride stays the datagram's original length so a
    /// truncated entry is never mistaken for several segments.
    #[test]
    fn a_datagram_longer_than_the_buffer_is_reported_as_truncated() {
        let mut control = cmsg::Aligned([0; cmsg::LEN]);
        let meta = decode_with(&mut control, loopback_name(), 512, 1200, |_| {}).unwrap();

        assert!(meta.truncated);
        assert_eq!(meta.len, 512);
        assert_eq!(meta.original_len, 1200);
        assert_eq!(meta.stride, 1200);
    }

    #[test]
    fn the_ecn_codepoint_decodes_from_the_v4_traffic_class() {
        let mut control = cmsg::Aligned([0; cmsg::LEN]);
        let meta = decode_with(&mut control, loopback_name(), 1, 1, |encoder| {
            encoder
                .push(libc::IPPROTO_IP, libc::IP_TOS, 0b10_u8)
                .unwrap();
        })
        .unwrap();

        assert_eq!(meta.ecn, Some(EcnCodepoint::Ect0));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn the_v4_packet_info_control_message_reports_the_local_address_and_interface() {
        let mut control = cmsg::Aligned([0; cmsg::LEN]);
        // SAFETY: all-zero is a valid `in_pktinfo`, whose fields are an index
        // and two addresses.
        let mut pktinfo: libc::in_pktinfo = unsafe { mem::zeroed() };
        pktinfo.ipi_ifindex = 3;
        pktinfo.ipi_addr.s_addr = u32::from_ne_bytes([198, 51, 100, 5]);

        let meta = decode_with(&mut control, loopback_name(), 1, 1, |encoder| {
            encoder
                .push(libc::IPPROTO_IP, libc::IP_PKTINFO, pktinfo)
                .unwrap();
        })
        .unwrap();

        assert_eq!(
            meta.dst_ip,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)))
        );
        assert_eq!(meta.interface_index, Some(3));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn the_v6_packet_info_control_message_reports_the_local_address_and_interface() {
        let mut control = cmsg::Aligned([0; cmsg::LEN]);
        let local: Ipv6Addr = "2001:db8::5".parse().unwrap();
        // SAFETY: all-zero is a valid `in6_pktinfo`.
        let mut pktinfo: libc::in6_pktinfo = unsafe { mem::zeroed() };
        pktinfo.ipi6_addr.s6_addr = local.octets();
        pktinfo.ipi6_ifindex = 4;

        let meta = decode_with(&mut control, loopback_name(), 1, 1, |encoder| {
            encoder
                .push(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, pktinfo)
                .unwrap();
        })
        .unwrap();

        assert_eq!(meta.dst_ip, Some(IpAddr::V6(local)));
        assert_eq!(meta.interface_index, Some(4));
    }

    /// The transparent-proxy path: `IP_RECVORIGDSTADDR` is how a redirected
    /// datagram still names the address the client aimed at, so both the
    /// address and the network-order port have to survive.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn the_v4_original_destination_control_message_decodes_its_address_and_port() {
        let mut control = cmsg::Aligned([0; cmsg::LEN]);
        let original = sockaddr_in_payload(&storage_v4(Ipv4Addr::new(203, 0, 113, 9), 8443));

        let meta = decode_with(&mut control, loopback_name(), 1, 1, |encoder| {
            encoder
                .push(libc::IPPROTO_IP, IP_RECV_ORIGINAL_DESTINATION, original)
                .unwrap();
        })
        .unwrap();

        assert_eq!(
            meta.original_destination,
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(203, 0, 113, 9),
                8443
            )))
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn the_v6_original_destination_control_message_decodes_its_address_and_port() {
        let mut control = cmsg::Aligned([0; cmsg::LEN]);
        let ip: Ipv6Addr = "2001:db8::9".parse().unwrap();
        let original = sockaddr_in6_payload(&storage_v6(ip, 8443, 3, 5));

        let meta = decode_with(&mut control, loopback_name(), 1, 1, |encoder| {
            encoder
                .push(libc::IPPROTO_IPV6, IPV6_RECV_ORIGINAL_DESTINATION, original)
                .unwrap();
        })
        .unwrap();

        assert_eq!(
            meta.original_destination,
            Some(SocketAddr::V6(SocketAddrV6::new(ip, 8443, 3, 5)))
        );
    }

    /// A coalesced read carries its segment size in a control message, which is
    /// what splits the buffer back into datagrams. Without it the whole read
    /// would be handed on as a single oversized datagram.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_gro_control_message_reports_the_segment_size_of_a_coalesced_read() {
        let mut control = cmsg::Aligned([0; cmsg::LEN]);
        let meta = decode_with(&mut control, loopback_name(), 4000, 4000, |encoder| {
            encoder
                .push(libc::SOL_UDP, libc::UDP_GRO, 1200 as libc::c_int)
                .unwrap();
        })
        .unwrap();

        assert_eq!(meta.stride, 1200);
        assert_eq!(meta.len, 4000);
        assert!(!meta.truncated);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_timestamp_control_message_decodes_seconds_and_nanoseconds() {
        let mut control = cmsg::Aligned([0; cmsg::LEN]);
        // SAFETY: all-zero is a valid `timespec`, whose two fields are integers.
        let mut ts: libc::timespec = unsafe { mem::zeroed() };
        ts.tv_sec = 1_700_000_000;
        ts.tv_nsec = 123_456_789;

        let meta = decode_with(&mut control, loopback_name(), 1, 1, |encoder| {
            encoder
                .push(libc::SOL_SOCKET, libc::SCM_TIMESTAMPNS, ts)
                .unwrap();
        })
        .unwrap();

        assert_eq!(
            meta.timestamp,
            Some(Duration::new(1_700_000_000, 123_456_789))
        );
    }

    /// A kernel puts several control messages in one buffer, and each is found
    /// by walking the chain from the one before it. Mixed payload sizes make
    /// that walk depend on the platform's own alignment padding, so a single
    /// receive carrying all three has to yield all three.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn every_control_message_in_one_chain_is_decoded() {
        let mut control = cmsg::Aligned([0; cmsg::LEN]);
        // SAFETY: all-zero is a valid `in_pktinfo`.
        let mut pktinfo: libc::in_pktinfo = unsafe { mem::zeroed() };
        pktinfo.ipi_ifindex = 11;
        pktinfo.ipi_addr.s_addr = u32::from_ne_bytes([198, 51, 100, 5]);

        let meta = decode_with(&mut control, loopback_name(), 2400, 2400, |encoder| {
            // One byte, then a struct, then an int: each following entry starts
            // at the padded offset the previous one's length rounds up to.
            encoder
                .push(libc::IPPROTO_IP, libc::IP_TOS, 0b11_u8)
                .unwrap();
            encoder
                .push(libc::IPPROTO_IP, libc::IP_PKTINFO, pktinfo)
                .unwrap();
            encoder
                .push(libc::SOL_UDP, libc::UDP_GRO, 1200 as libc::c_int)
                .unwrap();
        })
        .unwrap();

        assert_eq!(meta.ecn, Some(EcnCodepoint::Ce));
        assert_eq!(
            meta.dst_ip,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)))
        );
        assert_eq!(meta.interface_index, Some(11));
        assert_eq!(meta.stride, 1200);
    }

    /// A payload too short for the type its level and type name is refused
    /// rather than read past its end, and the refusal reaches the caller of the
    /// receive instead of yielding partly decoded metadata.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_control_message_whose_payload_is_too_short_for_its_type_is_rejected() {
        let mut control = cmsg::Aligned([0; cmsg::LEN]);
        let error = decode_with(&mut control, loopback_name(), 1, 1, |encoder| {
            // `UDP_GRO` carries a `c_int`; one byte must not be read as one.
            encoder.push(libc::SOL_UDP, libc::UDP_GRO, 0_u8).unwrap();
        })
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
