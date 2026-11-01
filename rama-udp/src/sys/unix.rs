use std::{
    io::{self, IoSliceMut},
    mem::{self, MaybeUninit},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsFd, AsRawFd},
    ptr,
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
    /// The peer a connected socket is fixed to, read when it was wrapped.
    connected_peer: Option<SocketAddr>,

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
            max_gso_segments: AtomicUsize::new(gso::max_gso_segments(&*io)?),
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
            connected_peer: io.peer_addr().ok().and_then(|address| address.as_socket()),
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
    // SAFETY: `mem::zeroed` needs all-zero bytes to be a valid `msghdr`: its fields are
    // integers and raw pointers (null), plus padding.
    let mut msg_hdr: libc::msghdr = unsafe { mem::zeroed() };
    // SAFETY: as above, for `iovec`: a raw pointer and an integer.
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
        // SAFETY: `sendmsg(2)` reads the name, iovec array, payload and control bytes that
        // `msg_hdr` describes. `prepare_msg` returned `Ok`, so by its safety-usable invariant
        // each pointer refers to `dst_addr`, `iovec`, `transmit.contents` or `cmsgs` with a
        // matching length; all are live locals or borrows not written during the call. The
        // descriptor is borrowed from `io` for the call.
        let n = unsafe { libc::sendmsg(io.as_raw_fd(), &raw const msg_hdr, 0) };

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
    // SAFETY: `mem::zeroed` needs all-zero bytes to be a valid `msghdr`: its fields are
    // integers and raw pointers (null), plus padding.
    let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
    // SAFETY: as above, for `iovec`: a raw pointer and an integer.
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
    // SAFETY: `sendmsg(2)` reads the name, iovec array, payload and control bytes that `hdr`
    // describes. `prepare_msg` returned `Ok`, so by its safety-usable invariant each pointer
    // refers to `addr`, `iov`, `transmit.contents` or `ctrl` with a matching length; all are
    // live locals or borrows not written during the call. The descriptor is borrowed from
    // `io` for the call.
    retry_if_interrupted(|| unsafe { libc::sendmsg(io.as_raw_fd(), &raw const hdr, 0) })?;
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
    let receive = |hdrs: &mut [libc::mmsghdr; BATCH_SIZE], count: usize| {
        let count = count.min(hdrs.len());
        // SAFETY: `recvmmsg(2)` writes into the `count` headers at `hdrs` and into the
        // name, payload and control buffers each describes, for the lengths it gives. `count`
        // is within `hdrs`. By `recv_via_recvmmsg_with`'s `# Safety` each of those headers was
        // just set up by `prepare_recv`, whose safety-usable invariant points it at live,
        // exclusively borrowed storage of those lengths. A null timeout waits for nothing.
        // The descriptor is borrowed from `io` for the call.
        unsafe {
            libc::recvmmsg(
                io.as_raw_fd(),
                hdrs.as_mut_ptr(),
                count as _,
                RECV_FLAGS as _,
                ptr::null_mut::<libc::timespec>(),
            ) as isize
        }
    };
    // SAFETY: `recv_via_recvmmsg_with` needs `receive` to return at most `count` and to leave
    // each reported header as a successful `recvmmsg(2)` does, which it does by being that
    // call: per recvmmsg(2) and recvmsg(2) it returns how many headers it filled, and in each
    // writes only received bytes through `msg_name` and the control pointer and sets
    // `msg_controllen` to at most the supplied length, leaving the pointers unchanged.
    unsafe { recv_via_recvmmsg_with(bufs, meta, receive) }
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
/// Receive a batch through `receive`, retrying on `EINTR`, and decode what it reports.
///
/// # Safety
///
/// The caller must ensure that whenever `receive(hdrs, count)` returns `n >= 0`, `n` is at
/// most `count` and each of the first `n` headers is left as a successful `recvmmsg(2)`
/// leaves it: its control pointer unchanged, `msg_controllen` at most its prepared value,
/// and nothing but initialized bytes written through `msg_name` or the control pointer.
///
/// Each call of `receive` gets `count <= BATCH_SIZE`, and the first `count` headers, with
/// `msg_len` zeroed, are set up by [`prepare_recv`] for the buffer of the same index right
/// before it.
unsafe fn recv_via_recvmmsg_with(
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
    mut receive: impl FnMut(&mut [libc::mmsghdr; BATCH_SIZE], usize) -> isize,
) -> io::Result<usize> {
    // The kernel may initialize only the active sockaddr prefix, so zero the
    // remaining storage before `decode_recv` reads the whole value.
    let mut names = [MaybeUninit::<libc::sockaddr_storage>::zeroed(); BATCH_SIZE];
    // The kernel writes each control header and its `cmsg_len` bytes but counts the alignment
    // padding after them in `msg_controllen` without writing it, so zero that too.
    let mut ctrls = [cmsg::Aligned(MaybeUninit::<[u8; cmsg::LEN]>::zeroed()); BATCH_SIZE];
    // SAFETY: `mem::zeroed` needs all-zero bytes to be a valid `[mmsghdr; BATCH_SIZE]`: each
    // `mmsghdr` holds a `msghdr` (integers and null raw pointers, plus padding) and an integer.
    let mut hdrs = unsafe { mem::zeroed::<[libc::mmsghdr; BATCH_SIZE]>() };
    let max_msg_count = bufs.len().min(BATCH_SIZE);
    // Every attempt submits freshly prepared headers: an interrupted call may have left any
    // field, so nothing from it carries over.
    let msg_count = retry_if_interrupted(|| {
        for i in 0..max_msg_count {
            prepare_recv(
                &mut bufs[i],
                &mut names[i],
                &mut ctrls[i],
                &mut hdrs[i].msg_hdr,
            );
            hdrs[i].msg_len = 0;
        }
        receive(&mut hdrs, max_msg_count)
    })?;
    for i in 0..(msg_count as usize) {
        let original_len = hdrs[i].msg_len as usize;
        let copied_len = original_len.min(bufs[i].len());
        // `recvmmsg` has already consumed the whole batch. If kernel metadata
        // is malformed, fail the call instead of silently returning a prefix.
        // SAFETY: `decode_recv` needs `names[i]` initialized and the control buffer of
        // `hdrs[i]` to meet `cmsg::Iter::new`'s contract. `names[i]` and `ctrls[i]` started
        // zeroed and, by this function's contract, `receive` wrote only initialized bytes into
        // them, so all their bytes are initialized. The control pointer is still `ctrls[i]`
        // (aligned for `cmsghdr`: `cmsg::Aligned`) and `msg_controllen <= cmsg::LEN` by the
        // same contract; `ctrls[i]` is a live local that nothing writes during the call.
        meta[i] = unsafe {
            decode_recv(
                &names[i],
                &hdrs[i].msg_hdr,
                copied_len,
                original_len,
                hdrs[i].msg_hdr.msg_flags,
            )
        }?;
    }
    Ok(msg_count as usize)
}

#[cfg(any(
    test,
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
    let receive = |hdr: &mut libc::msghdr| {
        // SAFETY: `recvmsg(2)` writes into the name, payload and control buffers `hdr`
        // describes, for the lengths it gives. By `recv_single_with`'s `# Safety` `hdr` was
        // just set up by `prepare_recv`, whose safety-usable invariant points it at live,
        // exclusively borrowed storage of those lengths. The descriptor is borrowed from `io`
        // for the call.
        unsafe { libc::recvmsg(io.as_raw_fd(), hdr, RECV_FLAGS) }
    };
    // SAFETY: `recv_single_with` needs `receive` to leave `hdr` as a successful `recvmsg(2)`
    // does whenever it returns `n >= 0`, which it does by being that call: per recvmsg(2) it
    // writes only received bytes through `msg_name` and the control pointer and sets
    // `msg_controllen` to at most the supplied length, leaving the pointers unchanged.
    unsafe { recv_single_with(bufs, meta, receive) }
}

#[cfg(any(
    test,
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "redox",
    target_os = "hurd",
    target_os = "solaris",
    target_os = "illumos",
    target_vendor = "apple"
))]
/// Receive one datagram through `receive`, retrying on `EINTR`, and decode what it reports.
///
/// # Safety
///
/// The caller must ensure that whenever `receive(hdr)` returns `n >= 0`, `hdr` is left as a
/// successful `recvmsg(2)` leaves it: its control pointer unchanged, `msg_controllen` at most
/// its prepared value, and nothing but initialized bytes written through `msg_name` or the
/// control pointer.
///
/// Each call of `receive` gets a header set up by [`prepare_recv`] for `bufs[0]` right
/// before it.
unsafe fn recv_single_with(
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
    mut receive: impl FnMut(&mut libc::msghdr) -> isize,
) -> io::Result<usize> {
    // The kernel may initialize only the active sockaddr prefix.
    let mut name = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    // Zeroed: `msg_controllen` also counts alignment padding the kernel does not write.
    let mut ctrl = cmsg::Aligned(MaybeUninit::<[u8; cmsg::LEN]>::zeroed());
    // SAFETY: `mem::zeroed` needs all-zero bytes to be a valid `msghdr`: its fields are
    // integers and raw pointers (null), plus padding.
    let mut hdr = unsafe { mem::zeroed::<libc::msghdr>() };
    let n = retry_if_interrupted(|| {
        prepare_recv(&mut bufs[0], &mut name, &mut ctrl, &mut hdr);
        receive(&mut hdr)
    })?;
    let original_len = n as usize;
    // SAFETY: `decode_recv` needs `name` initialized and `hdr`'s control buffer to meet
    // `cmsg::Iter::new`'s contract. `name` and `ctrl` started zeroed and, by this function's
    // contract, `receive` wrote only initialized bytes into them, so all their bytes are
    // initialized. The control pointer is still `ctrl` (aligned for `cmsghdr`:
    // `cmsg::Aligned`) and `msg_controllen <= cmsg::LEN` by the same contract; `ctrl` is a
    // live local that nothing writes during the call.
    meta[0] = unsafe {
        decode_recv(
            &name,
            &hdr,
            original_len.min(bufs[0].len()),
            original_len,
            hdr.msg_flags,
        )
    }?;
    Ok(1)
}

/// Describe `transmit` in `hdr` for `sendmsg(2)`.
///
/// # Safety-usable invariant
///
/// On `Ok`, `hdr`'s name is null with length 0 or `dst_addr` with its length, its iovec
/// array is `iov` (one entry, describing `transmit.contents`), and its control buffer is null
/// with length 0 or `ctrl` with a length of at most `cmsg::LEN`.
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
    iov.iov_base = transmit.contents.as_ptr().cast_mut().cast();
    iov.iov_len = transmit.contents.len();

    if super::is_connected_peer(state.connected_peer, transmit.destination) {
        hdr.msg_name = ptr::null_mut();
        hdr.msg_namelen = 0;
    } else {
        // POSIX declares this pointer mutable even though sendmsg does not modify it.
        hdr.msg_name = dst_addr.as_ptr().cast_mut().cast();
        hdr.msg_namelen = dst_addr.len();
    }
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;

    hdr.msg_control = ctrl.0.as_mut_ptr().cast();
    hdr.msg_controllen = cmsg::LEN as _;
    // SAFETY: `Encoder::new` needs the control pointer aligned for `cmsghdr` and valid for
    // reads and writes of `msg_controllen` initialized bytes reachable only through the
    // encoder. It is `ctrl`: `cmsg::Aligned`, `cmsg::LEN` initialized bytes, exclusively
    // borrowed by this function and not otherwise touched while the encoder lives.
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
                // Bionic declares the index signed.
                #[cfg(target_os = "android")]
                let ipi6_ifindex = transmit
                    .src_interface
                    .and_then(|index| i32::try_from(index).ok())
                    .unwrap_or(0);
                #[cfg(not(target_os = "android"))]
                let ipi6_ifindex = transmit.src_interface.unwrap_or(0);
                let pktinfo = libc::in6_pktinfo {
                    ipi6_ifindex,
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

/// Point `hdr` at the storage one receive fills.
///
/// # Safety-usable invariant
///
/// Afterwards `hdr`'s name is `name` (`size_of::<sockaddr_storage>()` bytes), its iovec array
/// is `buf` alone (std guarantees `IoSliceMut` is ABI compatible with `iovec` on Unix), its
/// control buffer is `ctrl` (`cmsg::LEN` bytes), and `msg_flags` is 0. Each pointer is derived
/// from the exclusive borrow passed in.
fn prepare_recv(
    buf: &mut IoSliceMut<'_>,
    name: &mut MaybeUninit<libc::sockaddr_storage>,
    ctrl: &mut cmsg::Aligned<MaybeUninit<[u8; cmsg::LEN]>>,
    hdr: &mut libc::msghdr,
) {
    hdr.msg_name = name.as_mut_ptr().cast();
    hdr.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
    hdr.msg_iov = ptr::from_mut(buf).cast::<libc::iovec>();
    hdr.msg_iovlen = 1;
    hdr.msg_control = ctrl.0.as_mut_ptr().cast();
    hdr.msg_controllen = cmsg::LEN as _;
    hdr.msg_flags = 0;
}

/// Decode the metadata one receive reported.
///
/// # Safety
///
/// The caller must ensure that every byte of `name` is initialized, and that `hdr`'s control
/// buffer meets the [`cmsg::Iter::new`] contract for the duration of this call.
unsafe fn decode_recv<M: cmsg::MsgHdr<ControlMessage = libc::cmsghdr>>(
    name: &MaybeUninit<libc::sockaddr_storage>,
    hdr: &M,
    len: usize,
    original_len: usize,
    flags: libc::c_int,
) -> io::Result<RecvMeta> {
    // Control data that did not fit may have lost the segment size of a coalesced
    // read, so the entry is reported truncated (and dropped) rather than mis-split.
    let control_truncated = flags & libc::MSG_CTRUNC != 0;
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

    if !control_truncated {
        // SAFETY: `Iter::new`'s contract is this function's, and the iterator does not
        // outlive this call.
        let cmsg_iter = unsafe { cmsg::Iter::new(hdr) };
        for cmsg in cmsg_iter {
            ctrl.decode(cmsg)?;
        }
    }

    // SAFETY: `decode_socket_addr` needs every byte of `name` initialized, as this
    // function's contract requires.
    let addr = unsafe { decode_socket_addr(name) }?;

    Ok(RecvMeta {
        len,
        original_len,
        stride: ctrl.stride,
        addr,
        ecn: ctrl.ecn_bits.map(EcnCodepoint::from_bits),
        dst_ip: ctrl.dst_ip,
        interface_index: ctrl.interface_index,
        original_destination: ctrl.original_destination,
        timestamp: ctrl.timestamp,
        truncated: control_truncated || flags & libc::MSG_TRUNC != 0 || original_len > len,
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
    fn decode(&mut self, cmsg: cmsg::CMsg<'_, libc::cmsghdr>) -> io::Result<()> {
        match (cmsg.cmsg_level, cmsg.cmsg_type) {
            (libc::IPPROTO_IP, libc::IP_TOS) => {
                // SAFETY: every bit pattern is a valid `u8`.
                self.ecn_bits = Some(unsafe { cmsg.decode::<u8>() }?);
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
                // SAFETY: every bit pattern is a valid `u8`.
                self.ecn_bits = Some(unsafe { cmsg.decode::<u8>() }?);
            }
            #[cfg(not(target_os = "redox",))]
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) => {
                // Temporary hack around broken macos ABI. Remove once upstream fixes it.
                // https://bugreport.apple.com/web/?problemID=48761855
                let byte_sized = cfg!(target_vendor = "apple")
                    && cmsg.len() == <libc::cmsghdr as cmsg::CMsgHdr>::cmsg_len(size_of::<u8>());
                if byte_sized {
                    // SAFETY: every bit pattern is a valid `u8`.
                    self.ecn_bits = Some(unsafe { cmsg.decode::<u8>() }?);
                } else {
                    // SAFETY: every bit pattern is a valid `c_int`.
                    self.ecn_bits = Some(unsafe { cmsg.decode::<libc::c_int>() }? as u8);
                }
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                // SAFETY: `in_pktinfo` holds only integers, valid for any bit pattern.
                let pktinfo = unsafe { cmsg.decode::<libc::in_pktinfo>() }?;
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
                // SAFETY: `in_addr` holds only integers, valid for any bit pattern.
                let in_addr = unsafe { cmsg.decode::<libc::in_addr>() }?;
                self.dst_ip = Some(IpAddr::V4(Ipv4Addr::from(in_addr.s_addr.to_ne_bytes())));
            }
            #[cfg(not(any(target_os = "redox", target_os = "hurd")))]
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                // SAFETY: `in6_pktinfo` holds only integers, valid for any bit pattern.
                let pktinfo = unsafe { cmsg.decode::<libc::in6_pktinfo>() }?;
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
                // SAFETY: `sockaddr_in` holds only integers, valid for any bit pattern.
                let addr = unsafe { cmsg.decode::<libc::sockaddr_in>() }?;
                self.original_destination = Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
                    u16::from_be(addr.sin_port),
                )));
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            (libc::IPPROTO_IPV6, IPV6_RECV_ORIGINAL_DESTINATION) => {
                // SAFETY: `sockaddr_in6` holds only integers, valid for any bit pattern.
                let addr = unsafe { cmsg.decode::<libc::sockaddr_in6>() }?;
                self.original_destination = Some(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(addr.sin6_addr.s6_addr),
                    u16::from_be(addr.sin6_port),
                    addr.sin6_flowinfo,
                    addr.sin6_scope_id,
                )));
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            (libc::SOL_UDP, libc::UDP_GRO) => {
                // SAFETY: every bit pattern is a valid `c_int`.
                self.stride = unsafe { cmsg.decode::<libc::c_int>() }? as usize;
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            (libc::SOL_SOCKET, libc::SCM_TIMESTAMPNS) => {
                // SAFETY: `timespec` holds only integers, valid for any bit pattern.
                let ts = unsafe { cmsg.decode::<libc::timespec>() }?;
                let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
                let nsecs = u32::try_from(ts.tv_nsec).unwrap_or(0);
                self.timestamp = Some(Duration::new(secs, nsecs));
            }
            _ => {}
        }
        Ok(())
    }
}

// POSIX defines `sockaddr_storage` as large enough and aligned for every supported address
// structure; `decode_socket_addr` reads the two it decodes in place.
const _: () = assert!(
    size_of::<libc::sockaddr_in>() <= size_of::<libc::sockaddr_storage>()
        && align_of::<libc::sockaddr_in>() <= align_of::<libc::sockaddr_storage>()
        && size_of::<libc::sockaddr_in6>() <= size_of::<libc::sockaddr_storage>()
        && align_of::<libc::sockaddr_in6>() <= align_of::<libc::sockaddr_storage>()
);

/// Decodes a `sockaddr_storage` into a `SocketAddr`
///
/// # Safety
///
/// The caller must ensure that every byte of `name` is initialized. (libc declares the
/// storage's filler fields as possibly uninitialized, so a valid value does not imply this.)
unsafe fn decode_socket_addr(name: &MaybeUninit<libc::sockaddr_storage>) -> io::Result<SocketAddr> {
    let storage = name.as_ptr();
    // SAFETY: the place read `(*storage).ss_family` needs `storage` aligned and dereferenceable
    // for the field, and the field initialized: `storage` comes from the reference `name`,
    // and this function's contract makes its bytes initialized.
    let family = unsafe { (*storage).ss_family };
    match libc::c_int::from(family) {
        libc::AF_INET => {
            // SAFETY: `read` needs `storage` aligned for and valid for reads of a `sockaddr_in`
            // whose bytes form a valid value. The assertion above puts one inside the storage
            // at its alignment; this function's contract makes those bytes initialized, and a
            // `sockaddr_in` holds only integer fields.
            let addr = unsafe { storage.cast::<libc::sockaddr_in>().read() };
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(addr.sin_port),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: as above, for `sockaddr_in6`, whose fields are integers and the
            // byte array of `in6_addr`.
            let addr = unsafe { storage.cast::<libc::sockaddr_in6>().read() };
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

    pub(super) fn max_gso_segments(_socket: &impl AsFd) -> io::Result<usize> {
        Ok(1)
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
    socket: &impl AsFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> bool {
    set_socket_option(socket, level, name, value).is_ok()
}

pub(crate) fn set_socket_option(
    socket: &impl AsFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    // SAFETY: `setsockopt(2)` reads `option_len` bytes at `option_value`: here the live local
    // `value`, with its own size. The descriptor is open for the borrow of `socket`
    // (`BorrowedFd`). An option the kernel rejects for this size fails without access.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_fd().as_raw_fd(),
            level,
            name,
            (&raw const value).cast(),
            size_of_val(&value) as _,
        )
    };

    match rc == 0 {
        true => Ok(()),
        false => Err(io::Error::last_os_error()),
    }
}

fn get_socket_option(
    socket: &impl AsFd,
    level: libc::c_int,
    name: libc::c_int,
) -> io::Result<libc::c_int> {
    let mut value = 0;
    let mut length = size_of_val(&value) as libc::socklen_t;
    // SAFETY: `getsockopt(2)` writes at most `*option_len` bytes at `option_value` and the
    // written size to `option_len`: here the live locals `value` (an integer, valid for any
    // bytes) and `length`, its size. The descriptor is open for the borrow of `socket`
    // (`BorrowedFd`).
    let rc = unsafe {
        libc::getsockopt(
            socket.as_fd().as_raw_fd(),
            level,
            name,
            (&raw mut value).cast(),
            &raw mut length,
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
    use std::net::UdpSocket;

    use super::*;

    /// RFC 9298 §3 and QUIC's path-MTU discovery need the kernel to set DF on IPv4; the
    /// capability flag only says the option was accepted, so read back what it holds.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_vendor = "apple"
    ))]
    #[test]
    fn ipv4_sockets_never_fragment_in_the_kernel() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let state = UdpSocketState::new((&socket).into(), false).unwrap();
        assert!(!state.may_fragment());
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert_eq!(
            get_socket_option(&socket, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER).unwrap(),
            libc::IP_PMTUDISC_PROBE
        );
        #[cfg(any(target_os = "freebsd", target_vendor = "apple"))]
        assert_eq!(
            get_socket_option(&socket, libc::IPPROTO_IP, libc::IP_DONTFRAG).unwrap(),
            1
        );
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    #[test]
    fn interrupted_single_receive_restores_all_buffer_capacities() {
        let mut bytes = [0_u8; 8];
        let mut bufs = [IoSliceMut::new(&mut bytes)];
        let mut meta = [RecvMeta::default()];
        let mut attempts = 0;
        let receive = |hdr: &mut libc::msghdr| {
            attempts += 1;
            assert_eq!(
                hdr.msg_namelen as usize,
                size_of::<libc::sockaddr_storage>()
            );
            assert_eq!(cmsg::MsgHdr::control_len(hdr), cmsg::LEN);
            assert_eq!(hdr.msg_flags, 0);
            assert_eq!(hdr.msg_iovlen, 1);
            if attempts == 1 {
                hdr.msg_namelen = 0;
                hdr.msg_controllen = 0;
                hdr.msg_flags = libc::MSG_TRUNC;
                hdr.msg_iovlen = 0;
                #[cfg(target_vendor = "apple")]
                // SAFETY: the platform exposes a live thread-local errno slot.
                let errno = unsafe { libc::__error() };
                #[cfg(target_os = "linux")]
                // SAFETY: the platform exposes a live thread-local errno slot.
                let errno = unsafe { libc::__errno_location() };
                // SAFETY: the slot returned by libc belongs to the current thread.
                unsafe { *errno = libc::EINTR };
                return -1;
            }
            assert_eq!(attempts, 2);
            // SAFETY: `write` needs `msg_name` aligned and valid for writes of one
            // `sockaddr_storage`: `recv_single_with` documents that `prepare_recv` set it up,
            // which points it at that much exclusively borrowed storage.
            unsafe {
                hdr.msg_name
                    .cast::<libc::sockaddr_storage>()
                    .write(storage_v4(Ipv4Addr::LOCALHOST, 1234));
            }
            hdr.msg_controllen = 0;
            1
        };
        // SAFETY: on success `receive` writes a zero-initialized `sockaddr_storage` with its
        // fields set through `msg_name`, leaves the control pointer alone and reports no
        // control bytes, as a successful `recvmsg` may.
        let result = unsafe { recv_single_with(&mut bufs, &mut meta, receive) }.unwrap();
        assert_eq!(result, 1);
        assert_eq!(attempts, 2);
        assert_eq!(meta[0].len, 1);
        assert!(!meta[0].truncated);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn interrupted_batch_receive_restores_every_header() {
        let mut first = [0_u8; 8];
        let mut second = [0_u8; 8];
        let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
        let mut meta = [RecvMeta::default(); 2];
        let mut attempts = 0;
        let receive = |hdrs: &mut [libc::mmsghdr; BATCH_SIZE], count: usize| {
            attempts += 1;
            assert_eq!(count, 2);
            for entry in &mut hdrs[..count] {
                let hdr = &mut entry.msg_hdr;
                assert_eq!(
                    hdr.msg_namelen as usize,
                    size_of::<libc::sockaddr_storage>()
                );
                assert_eq!(cmsg::MsgHdr::control_len(hdr), cmsg::LEN);
                assert_eq!(hdr.msg_flags, 0);
                assert_eq!(hdr.msg_iovlen, 1);
                assert_eq!(entry.msg_len, 0);
            }
            if attempts == 1 {
                for entry in &mut hdrs[..count] {
                    entry.msg_hdr.msg_namelen = 0;
                    entry.msg_hdr.msg_controllen = 0;
                    entry.msg_hdr.msg_flags = libc::MSG_TRUNC | libc::MSG_CTRUNC;
                    entry.msg_hdr.msg_iovlen = 0;
                    entry.msg_len = 9_999;
                }
                // SAFETY: the platform exposes a live thread-local errno slot.
                let errno = unsafe { libc::__errno_location() };
                // SAFETY: the slot returned by libc belongs to the current thread.
                unsafe { *errno = libc::EINTR };
                return -1;
            }
            assert_eq!(attempts, 2);
            // SAFETY: `write` needs `msg_name` aligned and valid for writes of one
            // `sockaddr_storage`: `recv_via_recvmmsg_with` documents that `prepare_recv` set
            // up the header, which points it at that much exclusively borrowed storage.
            unsafe {
                hdrs[0]
                    .msg_hdr
                    .msg_name
                    .cast::<libc::sockaddr_storage>()
                    .write(storage_v4(Ipv4Addr::LOCALHOST, 1234));
            }
            hdrs[0].msg_hdr.msg_controllen = 0;
            hdrs[0].msg_len = 1;
            1
        };
        // SAFETY: on success `receive` reports one header, into which it writes a
        // zero-initialized `sockaddr_storage` with its fields set through `msg_name`, leaving
        // the control pointer alone and reporting no control bytes, as `recvmmsg` may.
        let result = unsafe { recv_via_recvmmsg_with(&mut bufs, &mut meta, receive) }.unwrap();
        assert_eq!(result, 1);
        assert_eq!(attempts, 2);
        assert_eq!(meta[0].len, 1);
        assert!(!meta[0].truncated);
    }

    #[test]
    fn single_receive_reports_truncation_then_would_block() {
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        sender
            .send_to(&[7; 32], receiver.local_addr().unwrap())
            .unwrap();
        let mut bytes = [0; 8];
        let mut bufs = [IoSliceMut::new(&mut bytes)];
        let mut meta = [RecvMeta::default()];
        let socket = SockRef::from(&receiver);
        assert_eq!(recv_single(&socket, &mut bufs, &mut meta).unwrap(), 1);
        assert_eq!(meta[0].len, 8);
        assert!(meta[0].truncated);
        assert_eq!(&*bufs[0], &[7; 8]);
        receiver.set_nonblocking(true).unwrap();
        assert_eq!(
            recv_single(&socket, &mut bufs, &mut meta)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        receiver.set_nonblocking(false).unwrap();
        sender
            .send_to(&[9; 3], receiver.local_addr().unwrap())
            .unwrap();
        assert_eq!(recv_single(&socket, &mut bufs, &mut meta).unwrap(), 1);
        assert_eq!(meta[0].len, 3);
        assert!(!meta[0].truncated);
        assert_eq!(&bufs[0][..3], &[9; 3]);
    }

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
        decode_with_flags(control, name, len, original_len, 0, push)
    }

    /// [`decode_with`], for a receive that reported `flags`.
    fn decode_with_flags(
        control: &mut cmsg::Aligned<[u8; cmsg::LEN]>,
        name: libc::sockaddr_storage,
        len: usize,
        original_len: usize,
        flags: libc::c_int,
        push: impl FnOnce(&mut cmsg::Encoder<'_, libc::msghdr>),
    ) -> io::Result<RecvMeta> {
        // SAFETY: all-zero is a valid empty `msghdr`; the control pointer and
        // length written below describe `control`, which outlives this call.
        let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
        hdr.msg_control = control.0.as_mut_ptr().cast();
        hdr.msg_controllen = cmsg::LEN as _;
        {
            // SAFETY: `hdr`'s control buffer is `control`: aligned for `cmsghdr`
            // (`cmsg::Aligned`), `cmsg::LEN` initialized bytes, and reached only through
            // the encoder while it lives.
            let mut encoder = unsafe { cmsg::Encoder::new(&mut hdr) };
            push(&mut encoder);
        }
        let name = MaybeUninit::new(name);
        // SAFETY: `decode_recv` needs `name` initialized and `hdr`'s control buffer to meet
        // `cmsg::Iter::new`'s contract. `name` is a zeroed `sockaddr_storage` with fields
        // written, and libc declares every one of its bytes as a field, so the copies kept
        // them all. The control pointer is `control`: `cmsg::Aligned`, all `cmsg::LEN` bytes
        // initialized, and not written during the call.
        unsafe { decode_recv(&name, &hdr, len, original_len, flags) }
    }

    /// Decode `storage`, built by [`storage_v4`] or [`storage_v6`] or zeroed.
    fn decode_storage(storage: libc::sockaddr_storage) -> io::Result<SocketAddr> {
        let storage = MaybeUninit::new(storage);
        // SAFETY: `decode_socket_addr` needs every byte initialized: the storage started
        // zeroed, only fields were written, and libc declares every byte of it as a field,
        // so the copies kept them all.
        unsafe { decode_socket_addr(&storage) }
    }

    /// Control messages the kernel cut short describe the datagram only in part, so the entry
    /// is reported truncated, and none of them is read: not even a malformed one fails the
    /// receive, which would end the socket over one peer's datagram.
    #[test]
    fn cut_short_control_messages_truncate_the_entry_instead_of_failing() {
        for malformed in [false, true] {
            let push = |encoder: &mut cmsg::Encoder<'_, libc::msghdr>| {
                if malformed {
                    encoder
                        .push(libc::IPPROTO_IP, libc::IP_TOS, [2_u8; 3])
                        .unwrap();
                } else {
                    encoder.push(libc::IPPROTO_IP, libc::IP_TOS, 2_u8).unwrap();
                }
            };
            let mut control = cmsg::Aligned([0; cmsg::LEN]);
            let complete = decode_with(&mut control, loopback_name(), 100, 100, push);
            assert_eq!(complete.is_err(), malformed);
            let mut control = cmsg::Aligned([0; cmsg::LEN]);
            let meta = decode_with_flags(
                &mut control,
                loopback_name(),
                100,
                100,
                libc::MSG_CTRUNC,
                push,
            )
            .unwrap();
            assert!(meta.truncated, "malformed: {malformed}");
            assert_eq!(meta.ecn, None, "malformed: {malformed}");
        }
    }

    fn loopback_name() -> libc::sockaddr_storage {
        storage_v4(Ipv4Addr::LOCALHOST, 443)
    }

    /// A port is carried in network order and an address as its four octets, so
    /// a peer that is not a palindrome in either would survive a byte-order
    /// mistake in only one direction.
    #[test]
    fn the_peer_address_decodes_from_native_v4_storage() {
        let addr = decode_storage(storage_v4(Ipv4Addr::new(192, 0, 2, 7), 0x1234)).unwrap();
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
        let addr = decode_storage(storage_v6(ip, 0x1234, 7, 9)).unwrap();
        assert_eq!(addr, SocketAddr::V6(SocketAddrV6::new(ip, 0x1234, 7, 9)));
    }

    #[test]
    fn an_address_family_that_is_not_ip_is_rejected() {
        // SAFETY: all-zero is a valid `sockaddr_storage`.
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        storage.ss_family = libc::AF_UNIX as _;
        let error = decode_storage(storage).unwrap_err();
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

    /// BSD kernels can report truncation through the flag alone, with a length
    /// that already matches the copied prefix.
    #[test]
    fn the_truncation_flag_alone_marks_a_datagram_truncated() {
        let mut control = cmsg::Aligned([0; cmsg::LEN]);
        let meta = decode_with_flags(&mut control, loopback_name(), 8, 8, libc::MSG_TRUNC, |_| {})
            .unwrap();

        assert!(meta.truncated);
        assert_eq!(meta.len, 8);
    }

    /// A control message the kernel could not fit is gone, and with it perhaps
    /// the segment size that splits a coalesced read: the whole entry is marked
    /// truncated so it is dropped, never handed on as one datagram nor failing
    /// the socket.
    #[test]
    fn a_receive_whose_control_data_was_truncated_is_marked_truncated() {
        let mut control = cmsg::Aligned([0; cmsg::LEN]);
        let meta = decode_with_flags(
            &mut control,
            loopback_name(),
            4000,
            4000,
            libc::MSG_CTRUNC,
            |encoder| {
                encoder
                    .push(libc::IPPROTO_IP, libc::IP_TOS, 0b10_u8)
                    .unwrap();
            },
        )
        .unwrap();

        assert!(meta.truncated);
        assert_eq!(meta.stride, 4000);
        assert_eq!(
            meta.ecn, None,
            "control data past a truncation is not trusted"
        );
    }

    /// The single-message receive reports a datagram longer than its buffer
    /// as truncated rather than dropping it, and an empty queue afterwards
    /// ends the call with `WouldBlock` instead of retrying on stale flags.
    #[test]
    fn the_single_message_receive_reports_truncation_and_then_would_block() {
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        // Block instead of polling, since loopback delivery can be asynchronous.
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        sender
            .send_to(&[7; 16], receiver.local_addr().unwrap())
            .unwrap();

        let socket = SockRef::from(&receiver);
        let mut buffer = [0; 8];
        let mut meta = [RecvMeta::default()];
        let received =
            recv_single(&socket, &mut [IoSliceMut::new(&mut buffer)], &mut meta).unwrap();
        assert_eq!(received, 1);
        assert!(meta[0].truncated);
        assert_eq!(meta[0].len, buffer.len());
        assert_eq!(buffer, [7; 8]);
        assert_eq!(meta[0].addr, sender.local_addr().unwrap());

        receiver.set_nonblocking(true).unwrap();
        let error =
            recv_single(&socket, &mut [IoSliceMut::new(&mut buffer)], &mut meta).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
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
