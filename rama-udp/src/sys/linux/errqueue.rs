//! The socket error queue (`IP_RECVERR`, `IPV6_RECVERR`, `MSG_ERRQUEUE`, see ip(7)), on only
//! while a receiver drains it: queued reports are charged to the socket's receive buffer.

use std::{
    io,
    mem::{self, MaybeUninit},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsFd, AsRawFd},
    sync::atomic::{AtomicBool, Ordering},
};

use parking_lot::Mutex;
use rama_net::{
    address::ip::IntoCanonicalIpAddr as _,
    ip::icmp::{IcmpErrorKind, IcmpErrorReport},
    socket::core::SockRef,
};

use crate::sys::{
    cmsg,
    imp::{decode_socket_addr, retry_if_interrupted, set_socket_option},
};

/// Receives in a row one data receive absorbs before it yields instead.
pub(crate) const ABSORBED_PER_RECEIVE: usize = 32;

// An entry carries its error and the receive metadata the socket enables (ip(7)).
const CONTROL_LEN: usize = 512;

/// `struct sock_extended_err` and its IPv4 offender, as `ip_recv_error` writes them.
#[derive(Clone, Copy)]
#[repr(C)]
struct ErrorV4 {
    ee: libc::sock_extended_err,
    offender: libc::sockaddr_in,
}

/// `struct sock_extended_err` and its IPv6 offender, as `ipv6_recv_error` writes them.
#[derive(Clone, Copy)]
#[repr(C)]
struct ErrorV6 {
    ee: libc::sock_extended_err,
    offender: libc::sockaddr_in6,
}

const ERROR_V4_LEN: usize = size_of::<ErrorV4>();

const ERROR_V6_LEN: usize = size_of::<ErrorV6>();

// The kernel writes each pair as one unpadded payload of these sizes; others never decode.
const _: () = assert!(
    ERROR_V4_LEN == 32
        && ERROR_V6_LEN == 44
        && ERROR_V4_LEN == size_of::<libc::sock_extended_err>() + size_of::<libc::sockaddr_in>()
        && ERROR_V6_LEN == size_of::<libc::sock_extended_err>() + size_of::<libc::sockaddr_in6>()
);

/// An IP family whose error-queue option a socket carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

/// Which error-queue options are on, and how many receivers hold them on.
#[derive(Debug, Default)]
struct Holders {
    receivers: usize,
    v4: bool,
    v6: bool,
}

impl Holders {
    fn on(&mut self, family: Family) -> &mut bool {
        match family {
            Family::V4 => &mut self.v4,
            Family::V6 => &mut self.v6,
        }
    }

    fn any_on(&self) -> bool {
        self.v4 || self.v6
    }

    /// Turn off every option that is on, keeping the ones the kernel refused to turn off.
    fn turn_off(&mut self, set: &mut impl FnMut(Family, bool) -> io::Result<()>) {
        for family in [Family::V4, Family::V6] {
            if *self.on(family) {
                match set(family, false) {
                    Ok(()) => *self.on(family) = false,
                    Err(error) => {
                        crate::log::warn!("udp socket error queue stays on: {error}");
                    }
                }
            }
        }
    }
}

/// The error-queue options of a socket, on while receivers hold them.
#[derive(Debug, Default)]
pub(crate) struct IcmpReports {
    holders: Mutex<Holders>,
    active: AtomicBool,
}

impl IcmpReports {
    /// Whether an error-queue option may be on, so a send or receive can fail with an
    /// ICMP error about an earlier datagram.
    pub(crate) fn active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// Hold the error queue of `socket` on for one more receiver.
    pub(crate) fn acquire(&self, socket: &impl AsFd) -> io::Result<()> {
        let families = families(socket)?;
        self.acquire_with(families, |family, on| set_option(socket, family, on))
    }

    /// Release one receiver's hold; the last one turns the error queue off.
    pub(crate) fn release(&self, socket: &impl AsFd) {
        let cleared = self.release_with(|family, on| set_option(socket, family, on));
        if cleared {
            // The purged queue's pending error goes too.
            drop(SockRef::from(socket).take_error());
        }
    }

    fn acquire_with(
        &self,
        families: &[Family],
        mut set: impl FnMut(Family, bool) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut holders = self.holders.lock();
        if holders.receivers == 0 {
            // Absorbing before an option is on is harmless; after would miss a receive.
            self.active.store(true, Ordering::Release);
            for &family in families {
                if let Err(error) = set(family, true) {
                    holders.turn_off(&mut set);
                    self.active.store(holders.any_on(), Ordering::Release);
                    return Err(error);
                }
                *holders.on(family) = true;
            }
        }
        holders.receivers += 1;
        Ok(())
    }

    /// Whether the last receiver left with every option off.
    fn release_with(&self, mut set: impl FnMut(Family, bool) -> io::Result<()>) -> bool {
        let mut holders = self.holders.lock();
        holders.receivers = holders.receivers.saturating_sub(1);
        if holders.receivers > 0 {
            return false;
        }
        holders.turn_off(&mut set);
        let on = holders.any_on();
        // Cleared only once off: an option still on keeps failing calls with its errors.
        self.active.store(on, Ordering::Release);
        !on
    }
}

/// The families whose error-queue option `socket` carries.
fn families(socket: &impl AsFd) -> io::Result<&'static [Family]> {
    let socket = SockRef::from(socket);
    if socket.local_addr()?.is_ipv4() {
        return Ok(&[Family::V4]);
    }
    Ok(match socket.only_v6()? {
        true => &[Family::V6],
        false => &[Family::V4, Family::V6],
    })
}

fn set_option(socket: &impl AsFd, family: Family, on: bool) -> io::Result<()> {
    let (level, name) = match family {
        Family::V4 => (libc::IPPROTO_IP, libc::IP_RECVERR),
        Family::V6 => (libc::IPPROTO_IPV6, libc::IPV6_RECVERR),
    };
    set_socket_option(socket, level, name, libc::c_int::from(on))
}

/// Whether `error` is one an ICMP error sets on the socket (`icmp_err_convert`,
/// `icmpv6_err_convert`): with the queue on, the call it fails concerns an earlier datagram.
pub(crate) fn is_queued_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(
            libc::ECONNREFUSED
                | libc::EHOSTUNREACH
                | libc::ENETUNREACH
                | libc::EHOSTDOWN
                | libc::ENONET
                | libc::ENOPROTOOPT
                | libc::EOPNOTSUPP
                | libc::EACCES
                | libc::EMSGSIZE
                | libc::EPROTO
        )
    )
}

/// Take the next report from the error queue of `socket`: `WouldBlock` once it is empty.
///
/// An entry without an ICMP or local error (another origin, or control data cut short) is
/// consumed and skipped; after a run of those the call ends with `Interrupted`.
pub(crate) fn recv(socket: &impl AsFd) -> io::Result<IcmpErrorReport> {
    let fd = socket.as_fd().as_raw_fd();
    for _ in 0..ABSORBED_PER_RECEIVE {
        let mut name = MaybeUninit::<libc::sockaddr_storage>::zeroed();
        let mut ctrl = cmsg::Aligned(MaybeUninit::<[u8; CONTROL_LEN]>::zeroed());
        // SAFETY: all-zero is a valid `msghdr`: integers, null pointers and padding.
        let mut hdr = unsafe { mem::zeroed::<libc::msghdr>() };
        hdr.msg_name = name.as_mut_ptr().cast();
        hdr.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
        hdr.msg_control = ctrl.0.as_mut_ptr().cast();
        hdr.msg_controllen = CONTROL_LEN as _;
        // No iovec: the quoted datagram is discarded. `MSG_ERRQUEUE` never blocks.
        // SAFETY: `recvmsg(2)` reads and writes `*msg`, the local `hdr` the closure borrows
        // exclusively, and writes at most `msg_namelen` bytes to `name` and `msg_controllen`
        // to `ctrl`, live locals of those sizes; the zeroed `msg_iov`/`msg_iovlen` describe
        // no buffer. `fd` is open for the borrow of `socket`.
        retry_if_interrupted(|| unsafe { libc::recvmsg(fd, &raw mut hdr, libc::MSG_ERRQUEUE) })?;
        if hdr.msg_flags & libc::MSG_CTRUNC != 0 {
            continue;
        }
        // SAFETY: every byte of `name` is initialized: zeroed, then written only by `recvmsg`.
        let destination = unsafe { decode_socket_addr(&name) }.ok();
        // The kernel wrote `hdr` back: point it at `ctrl` again, within its length.
        hdr.msg_control = ctrl.0.as_mut_ptr().cast();
        hdr.msg_controllen = hdr.msg_controllen.min(CONTROL_LEN as _);
        // SAFETY: `Iter::new` needs the control pointer null or aligned for `cmsghdr`, and its
        // first `msg_controllen` bytes in one live allocation, initialized and unwritten while
        // `hdr` is borrowed. The two lines above make them a prefix of `ctrl`:
        // `cmsg::Aligned`, zeroed, written only by `recvmsg`, and untouched in this statement.
        let report = unsafe { cmsg::Iter::new(&hdr) }.find_map(decode);
        if let Some(report) = report {
            return Ok(match destination {
                Some(destination) => {
                    report.with_destination(destination.into_canonical_ip_addr().into())
                }
                None => report,
            });
        }
    }
    // A run of skipped entries: let the caller yield before it drains further.
    Err(io::ErrorKind::Interrupted.into())
}

/// The report one control message carries, when it is an ICMP or local error.
fn decode(cmsg: cmsg::CMsg<'_, libc::cmsghdr>) -> Option<IcmpErrorReport> {
    match (cmsg.cmsg_level, cmsg.cmsg_type) {
        (libc::IPPROTO_IP, libc::IP_RECVERR) => {
            // SAFETY: every initialized bit pattern is a valid `ErrorV4`: libc declares its
            // fields as integers and integer arrays.
            let error = unsafe { cmsg.decode::<ErrorV4>() }.ok()?;
            decode_v4(error)
        }
        (libc::IPPROTO_IPV6, libc::IPV6_RECVERR) => {
            // SAFETY: as above, for `ErrorV6`.
            let error = unsafe { cmsg.decode::<ErrorV6>() }.ok()?;
            decode_v6(error)
        }
        _ => None,
    }
}

fn decode_v4(error: ErrorV4) -> Option<IcmpErrorReport> {
    let reporter = (libc::c_int::from(error.offender.sin_family) == libc::AF_INET)
        .then(|| IpAddr::V4(Ipv4Addr::from(error.offender.sin_addr.s_addr.to_ne_bytes())));
    report(error.ee, reporter)
}

fn decode_v6(error: ErrorV6) -> Option<IcmpErrorReport> {
    let reporter = (libc::c_int::from(error.offender.sin6_family) == libc::AF_INET6).then(|| {
        IpAddr::V6(Ipv6Addr::from(error.offender.sin6_addr.s6_addr)).into_canonical_ip_addr()
    });
    report(error.ee, reporter)
}

fn report(ee: libc::sock_extended_err, reporter: Option<IpAddr>) -> Option<IcmpErrorReport> {
    let report = match ee.ee_origin {
        libc::SO_EE_ORIGIN_ICMP => IcmpErrorReport::icmpv4(ee.ee_type, ee.ee_code, ee.ee_info),
        libc::SO_EE_ORIGIN_ICMP6 => IcmpErrorReport::icmpv6(ee.ee_type, ee.ee_code, ee.ee_info),
        libc::SO_EE_ORIGIN_LOCAL => IcmpErrorReport::local(
            (ee.ee_errno == libc::EMSGSIZE as u32)
                .then_some(IcmpErrorKind::PacketTooBig { mtu: ee.ee_info }),
        ),
        // ip(7): "Unknown values should be ignored."
        _ => return None,
    };
    Some(match reporter {
        Some(reporter) => report.with_reporter(reporter),
        None => report,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        net::{Ipv4Addr, UdpSocket},
    };

    use rama_net::{
        ip::icmp::IcmpErrorOrigin,
        socket::{core::Socket, opts::Domain},
    };

    use super::*;
    use crate::sys::{cmsg::control_payload_struct, imp::get_socket_option};

    control_payload_struct! {
        libc::sock_extended_err => u32, u8, u8, u8, u8, u32, u32;
        ErrorV4 => libc::sock_extended_err, libc::sockaddr_in;
        ErrorV6 => libc::sock_extended_err, libc::sockaddr_in6;
    }

    fn sock_err(origin: u8, errno: i32, icmp: (u8, u8), info: u32) -> libc::sock_extended_err {
        // SAFETY: all-zero is a valid `sock_extended_err`, whose fields are integers.
        let mut ee: libc::sock_extended_err = unsafe { mem::zeroed() };
        ee.ee_errno = errno as u32;
        ee.ee_origin = origin;
        ee.ee_type = icmp.0;
        ee.ee_code = icmp.1;
        ee.ee_info = info;
        ee
    }

    fn payload_v4(ee: libc::sock_extended_err, offender: Option<Ipv4Addr>) -> ErrorV4 {
        // SAFETY: all-zero is a valid `sockaddr_in` (`AF_UNSPEC`), whose fields are integers.
        let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
        if let Some(ip) = offender {
            sin.sin_family = libc::AF_INET as _;
            sin.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
        }
        ErrorV4 { ee, offender: sin }
    }

    fn payload_v6(ee: libc::sock_extended_err, offender: Option<Ipv6Addr>) -> ErrorV6 {
        // SAFETY: all-zero is a valid `sockaddr_in6` (`AF_UNSPEC`), whose fields are integers.
        let mut sin6: libc::sockaddr_in6 = unsafe { mem::zeroed() };
        if let Some(ip) = offender {
            sin6.sin6_family = libc::AF_INET6 as _;
            sin6.sin6_addr.s6_addr = ip.octets();
        }
        ErrorV6 { ee, offender: sin6 }
    }

    /// Decode the one control message `push` encodes, through the native chain walk.
    fn decode_pushed(
        push: impl FnOnce(&mut cmsg::Encoder<'_, libc::msghdr>) -> io::Result<()>,
    ) -> Option<IcmpErrorReport> {
        let mut control = cmsg::Aligned([0u8; cmsg::LEN]);
        // SAFETY: all-zero is a valid `msghdr`: integers, null pointers and padding.
        let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
        hdr.msg_control = control.0.as_mut_ptr().cast();
        hdr.msg_controllen = cmsg::LEN as _;
        {
            // SAFETY: the two lines above make `hdr`'s control buffer all of `control`:
            // `cmsg::Aligned`, initialized, and reached only through the encoder in this block.
            let mut encoder = unsafe { cmsg::Encoder::new(&mut hdr) };
            push(&mut encoder).unwrap();
        }
        // The encoder wrote `hdr` back: point it at `control` again, within its length.
        hdr.msg_control = control.0.as_mut_ptr().cast();
        hdr.msg_controllen = hdr.msg_controllen.min(cmsg::LEN as _);
        // SAFETY: the two lines above make the control bytes a prefix of `control`:
        // `cmsg::Aligned`, initialized, and not written while `hdr` is borrowed.
        unsafe { cmsg::Iter::new(&hdr) }.find_map(decode)
    }

    #[test]
    fn an_icmp_error_names_its_reporter() {
        let ee = sock_err(libc::SO_EE_ORIGIN_ICMP, libc::ECONNREFUSED, (3, 3), 0);
        let reporter = Ipv4Addr::new(192, 0, 2, 7);
        let report = decode_pushed(|encoder| {
            encoder.push(
                libc::IPPROTO_IP,
                libc::IP_RECVERR,
                payload_v4(ee, Some(reporter)),
            )
        })
        .unwrap();
        assert_eq!(
            report.origin(),
            IcmpErrorOrigin::Icmpv4 {
                icmp_type: 3,
                code: 3
            }
        );
        assert_eq!(report.kind(), Some(IcmpErrorKind::PortUnreachable));
        assert_eq!(report.reporter(), Some(reporter.into()));
    }

    /// A dual-stack socket gets an IPv4 router's error with a v4-mapped offender.
    #[test]
    fn a_v4_mapped_offender_reads_as_ipv4() {
        let ee = sock_err(libc::SO_EE_ORIGIN_ICMP, libc::EMSGSIZE, (3, 4), 1400);
        let reporter = Ipv4Addr::new(198, 51, 100, 1);
        let report = decode_pushed(|encoder| {
            encoder.push(
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVERR,
                payload_v6(ee, Some(reporter.to_ipv6_mapped())),
            )
        })
        .unwrap();
        assert_eq!(
            report.origin(),
            IcmpErrorOrigin::Icmpv4 {
                icmp_type: 3,
                code: 4
            }
        );
        assert_eq!(
            report.kind(),
            Some(IcmpErrorKind::PacketTooBig { mtu: 1400 })
        );
        assert_eq!(report.reporter(), Some(reporter.into()));
    }

    #[test]
    fn an_unknown_offender_family_leaves_no_reporter() {
        let ee = sock_err(libc::SO_EE_ORIGIN_ICMP6, libc::EHOSTUNREACH, (3, 0), 0);
        let report = decode_pushed(|encoder| {
            encoder.push(libc::IPPROTO_IPV6, libc::IPV6_RECVERR, payload_v6(ee, None))
        })
        .unwrap();
        assert_eq!(
            report.origin(),
            IcmpErrorOrigin::Icmpv6 {
                icmp_type: 3,
                code: 0
            }
        );
        assert_eq!(report.kind(), Some(IcmpErrorKind::HopLimitExceeded));
        assert_eq!(report.reporter(), None);
    }

    /// A local refusal carries no ICMP type or code; only `EMSGSIZE` names a kind.
    #[test]
    fn a_local_error_reports_the_link_mtu() {
        for (errno, kind) in [
            (
                libc::EMSGSIZE,
                Some(IcmpErrorKind::PacketTooBig { mtu: 1280 }),
            ),
            (libc::ENOBUFS, None),
        ] {
            let ee = sock_err(libc::SO_EE_ORIGIN_LOCAL, errno, (0, 0), 1280);
            let report = decode_pushed(|encoder| {
                encoder.push(libc::IPPROTO_IP, libc::IP_RECVERR, payload_v4(ee, None))
            })
            .unwrap();
            assert_eq!(report.origin(), IcmpErrorOrigin::Local);
            assert_eq!(report.kind(), kind, "{errno}");
            assert_eq!(report.reporter(), None);
        }
    }

    /// Entries that carry no ICMP or local error decode to nothing rather than failing.
    #[test]
    fn other_and_malformed_entries_decode_to_nothing() {
        let icmp = sock_err(libc::SO_EE_ORIGIN_ICMP, libc::ECONNREFUSED, (3, 3), 0);
        let timestamping = sock_err(libc::SO_EE_ORIGIN_TXSTATUS, libc::ENOMSG, (0, 0), 0);
        assert!(
            decode_pushed(|encoder| {
                encoder.push(
                    libc::IPPROTO_IP,
                    libc::IP_RECVERR,
                    payload_v4(timestamping, None),
                )
            })
            .is_none(),
            "unknown origin"
        );
        // An ICMP error cut one byte short.
        let mut short = [0u8; ERROR_V4_LEN - 1];
        short[mem::offset_of!(libc::sock_extended_err, ee_origin)] = libc::SO_EE_ORIGIN_ICMP;
        assert!(
            decode_pushed(|encoder| encoder.push(libc::IPPROTO_IP, libc::IP_RECVERR, short))
                .is_none(),
            "truncated payload"
        );
        assert!(
            decode_pushed(|encoder| {
                encoder.push(libc::IPPROTO_IP, libc::IP_RECVERR, payload_v6(icmp, None))
            })
            .is_none(),
            "payload of the other family"
        );
        assert!(
            decode_pushed(|encoder| {
                encoder.push(libc::IPPROTO_IP, libc::IP_PKTINFO, payload_v4(icmp, None))
            })
            .is_none(),
            "another message type"
        );
        assert!(
            decode_pushed(|encoder| {
                encoder.push(libc::IPPROTO_IPV6, libc::IP_RECVERR, payload_v4(icmp, None))
            })
            .is_none(),
            "another level"
        );
    }

    /// Records the option changes it is asked for, refusing the ones listed.
    struct Options {
        calls: RefCell<Vec<(Family, bool)>>,
        refuse: Vec<(Family, bool)>,
    }

    impl Options {
        fn refusing(refuse: &[(Family, bool)]) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                refuse: refuse.to_vec(),
            }
        }

        fn set(&self, family: Family, on: bool) -> io::Result<()> {
            self.calls.borrow_mut().push((family, on));
            match self.refuse.contains(&(family, on)) {
                true => Err(io::ErrorKind::PermissionDenied.into()),
                false => Ok(()),
            }
        }

        fn take(&self) -> Vec<(Family, bool)> {
            self.calls.take()
        }
    }

    const DUAL: &[Family] = &[Family::V4, Family::V6];

    #[test]
    fn options_go_on_with_the_first_receiver_and_off_with_the_last() {
        let reports = IcmpReports::default();
        let options = Options::refusing(&[]);
        let set = |family, on| options.set(family, on);
        reports.acquire_with(DUAL, set).unwrap();
        reports.acquire_with(DUAL, set).unwrap();
        assert_eq!(options.take(), [(Family::V4, true), (Family::V6, true)]);
        assert!(reports.active());
        assert!(!reports.release_with(set));
        assert!(options.take().is_empty() && reports.active());
        assert!(reports.release_with(set));
        assert_eq!(options.take(), [(Family::V4, false), (Family::V6, false)]);
        assert!(!reports.active());
    }

    /// A family that fails to turn on rolls back exactly the ones already on.
    #[test]
    fn a_refused_family_rolls_back_the_other() {
        let reports = IcmpReports::default();
        let options = Options::refusing(&[(Family::V6, true)]);
        reports
            .acquire_with(DUAL, |family, on| options.set(family, on))
            .unwrap_err();
        assert_eq!(
            options.take(),
            [(Family::V4, true), (Family::V6, true), (Family::V4, false)]
        );
        assert!(!reports.active());
        assert_eq!(reports.holders.lock().receivers, 0);

        let options = Options::refusing(&[(Family::V4, true)]);
        reports
            .acquire_with(DUAL, |family, on| options.set(family, on))
            .unwrap_err();
        assert_eq!(
            options.take(),
            [(Family::V4, true)],
            "nothing on, nothing undone"
        );
        assert!(!reports.active());
    }

    /// An option the kernel will not turn off keeps absorbing its errors.
    #[test]
    fn an_option_left_on_keeps_the_socket_active() {
        let reports = IcmpReports::default();
        let options = Options::refusing(&[(Family::V6, true), (Family::V4, false)]);
        reports
            .acquire_with(DUAL, |family, on| options.set(family, on))
            .unwrap_err();
        assert!(reports.active(), "IPv4 stays on");

        let reports = IcmpReports::default();
        let options = Options::refusing(&[(Family::V6, false)]);
        let set = |family, on| options.set(family, on);
        reports.acquire_with(DUAL, set).unwrap();
        assert!(!reports.release_with(set));
        assert!(reports.active(), "IPv6 stays on");
        let options = Options::refusing(&[]);
        assert!(reports.release_with(|family, on| options.set(family, on)));
        assert_eq!(options.take(), [(Family::V6, false)], "only what stayed on");
        assert!(!reports.active());
    }

    fn option_on(socket: &impl AsFd, family: Family) -> bool {
        let (level, name) = match family {
            Family::V4 => (libc::IPPROTO_IP, libc::IP_RECVERR),
            Family::V6 => (libc::IPPROTO_IPV6, libc::IPV6_RECVERR),
        };
        get_socket_option(socket, level, name).unwrap() != 0
    }

    /// Each socket gets the option of every family it carries, and only those.
    #[test]
    fn a_socket_enables_the_families_it_carries() {
        let v4 = UdpSocket::bind("127.0.0.1:0").unwrap();
        let v6_only = Socket::new(Domain::IPv6.into(), libc::SOCK_DGRAM.into(), None).unwrap();
        v6_only.set_only_v6(true).unwrap();
        v6_only
            .bind(&"[::1]:0".parse::<std::net::SocketAddr>().unwrap().into())
            .unwrap();
        let dual = Socket::new(Domain::IPv6.into(), libc::SOCK_DGRAM.into(), None).unwrap();
        dual.set_only_v6(false).unwrap();
        dual.bind(&"[::]:0".parse::<std::net::SocketAddr>().unwrap().into())
            .unwrap();

        let reports = IcmpReports::default();
        reports.acquire(&v4).unwrap();
        assert!(option_on(&v4, Family::V4));
        reports.release(&v4);
        assert!(!option_on(&v4, Family::V4) && !reports.active());

        let reports = IcmpReports::default();
        reports.acquire(&v6_only).unwrap();
        assert!(option_on(&v6_only, Family::V6));
        assert!(!option_on(&v6_only, Family::V4));
        reports.release(&v6_only);
        assert!(!option_on(&v6_only, Family::V6) && !reports.active());

        let reports = IcmpReports::default();
        reports.acquire(&dual).unwrap();
        assert!(option_on(&dual, Family::V4) && option_on(&dual, Family::V6));
        reports.release(&dual);
        assert!(!option_on(&dual, Family::V4) && !option_on(&dual, Family::V6));
        assert!(!reports.active());
    }
}
