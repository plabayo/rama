use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use rama_utils::str::smol_str::SmolStr;

use super::{HardwareAddress, Interface, InterfaceAddress, InterfaceFlags};
use crate::address::ip::ipnet::IpNet;

#[cfg(any(target_os = "linux", target_os = "android"))]
const LINK_FAMILY: libc::c_int = libc::AF_PACKET;
#[cfg(target_vendor = "apple")]
const LINK_FAMILY: libc::c_int = libc::AF_LINK;

pub(super) fn interfaces() -> io::Result<Vec<Interface>> {
    let list = IfAddrs::load()?;
    let mut out = Vec::new();

    let mut cursor = list.head;
    while !cursor.is_null() {
        // SAFETY: `cursor` is a live node of the linked list owned by `list`.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;

        if entry.ifa_name.is_null() {
            continue;
        }
        // SAFETY: `ifa_name` is a NUL-terminated C string owned by the list.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }.to_string_lossy();
        if name.is_empty() {
            continue;
        }

        let pos = ensure_interface(&mut out, name.as_ref(), entry.ifa_flags);
        let Some(interface) = out.get_mut(pos) else {
            continue;
        };

        match sockaddr_family(entry.ifa_addr) {
            Some(libc::AF_INET) => {
                if let Some(addr) = read_v4(entry.ifa_addr) {
                    let address = IpAddr::V4(addr);
                    let prefix = netmask_prefix(entry.ifa_netmask, address);
                    interface
                        .addresses
                        .push(InterfaceAddress::new(address, prefix, None));
                }
            }
            Some(libc::AF_INET6) => {
                if let Some((addr, scope_id)) = read_v6(entry.ifa_addr) {
                    let address = IpAddr::V6(addr);
                    let prefix = netmask_prefix(entry.ifa_netmask, address);
                    interface.addresses.push(InterfaceAddress::new(
                        address,
                        prefix,
                        Some(scope_id),
                    ));
                }
            }
            Some(LINK_FAMILY) => {
                let (hw_address, index) = read_link(entry.ifa_addr);
                if interface.hw_address.is_none() {
                    interface.hw_address = hw_address;
                }
                if interface.index.is_none() {
                    interface.index = index;
                }
            }
            _ => {}
        }
    }

    for interface in &mut out {
        if interface.index.is_none() {
            interface.index = name_to_index(interface.name.as_str());
        }
    }

    Ok(out)
}

/// Owns the list allocated by `getifaddrs`, freeing it on drop so an unwind
/// mid-parse cannot leak it.
struct IfAddrs {
    head: *mut libc::ifaddrs,
}

impl IfAddrs {
    fn load() -> io::Result<Self> {
        let mut head = ptr::null_mut();
        sys_getifaddrs(&mut head)?;
        Ok(Self { head })
    }
}

impl Drop for IfAddrs {
    fn drop(&mut self) {
        if !self.head.is_null() {
            sys_freeifaddrs(self.head);
        }
    }
}

fn sys_getifaddrs(out: &mut *mut libc::ifaddrs) -> io::Result<()> {
    #[cfg(target_os = "android")]
    {
        android::getifaddrs(out)
    }

    #[cfg(not(target_os = "android"))]
    {
        // SAFETY: `out` is a valid out-pointer for `getifaddrs` to store the list head in.
        if unsafe { libc::getifaddrs(out) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

fn sys_freeifaddrs(list: *mut libc::ifaddrs) {
    #[cfg(target_os = "android")]
    {
        android::freeifaddrs(list);
    }

    #[cfg(not(target_os = "android"))]
    {
        // SAFETY: `list` was allocated by a successful `getifaddrs` call.
        unsafe { libc::freeifaddrs(list) }
    }
}

/// bionic only exports `getifaddrs`/`freeifaddrs` from API level 24: resolve
/// them at runtime so builds targeting older API levels keep linking, and
/// report `Unsupported` when running on a device without them.
#[cfg(target_os = "android")]
mod android {
    use std::ffi::CStr;
    use std::io;
    use std::mem;

    fn resolve(name: &CStr) -> Option<*mut libc::c_void> {
        // SAFETY: RTLD_DEFAULT with a NUL-terminated symbol name is a valid dlsym query.
        let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
        (!sym.is_null()).then_some(sym)
    }

    pub(super) fn getifaddrs(out: &mut *mut libc::ifaddrs) -> io::Result<()> {
        let Some(sym) = resolve(c"getifaddrs") else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "getifaddrs requires android api level 24+",
            ));
        };
        // SAFETY: the symbol was resolved from the running libc and has the
        // posix `getifaddrs` signature.
        let getifaddrs = unsafe {
            mem::transmute::<
                *mut libc::c_void,
                unsafe extern "C" fn(*mut *mut libc::ifaddrs) -> libc::c_int,
            >(sym)
        };
        // SAFETY: `out` is a valid out-pointer for the list head.
        if unsafe { getifaddrs(out) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn freeifaddrs(list: *mut libc::ifaddrs) {
        let Some(sym) = resolve(c"freeifaddrs") else {
            return;
        };
        // SAFETY: the symbol was resolved from the running libc and has the
        // posix `freeifaddrs` signature.
        let freeifaddrs = unsafe {
            mem::transmute::<*mut libc::c_void, unsafe extern "C" fn(*mut libc::ifaddrs)>(sym)
        };
        // SAFETY: `list` was allocated by a successful `getifaddrs` call.
        unsafe { freeifaddrs(list) }
    }
}

fn ensure_interface(out: &mut Vec<Interface>, name: &str, raw_flags: libc::c_uint) -> usize {
    if let Some(pos) = out.iter().position(|interface| interface.name == name) {
        pos
    } else {
        out.push(Interface {
            name: SmolStr::new(name),
            index: None,
            flags: interface_flags(raw_flags),
            hw_address: None,
            description: None,
            addresses: Vec::new(),
        });
        out.len() - 1
    }
}

fn interface_flags(raw: libc::c_uint) -> InterfaceFlags {
    let mut flags = InterfaceFlags::empty();
    for (iff, flag) in [
        (libc::IFF_UP, InterfaceFlags::UP),
        (libc::IFF_RUNNING, InterfaceFlags::RUNNING),
        (libc::IFF_LOOPBACK, InterfaceFlags::LOOPBACK),
        (libc::IFF_POINTOPOINT, InterfaceFlags::POINT_TO_POINT),
        (libc::IFF_BROADCAST, InterfaceFlags::BROADCAST),
        (libc::IFF_MULTICAST, InterfaceFlags::MULTICAST),
    ] {
        if raw & (iff as libc::c_uint) != 0 {
            flags |= flag;
        }
    }
    flags
}

fn sockaddr_family(sa: *const libc::sockaddr) -> Option<libc::c_int> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: `sa` is non-null and points at a kernel-provided sockaddr,
    // whose family field is always present.
    let family = unsafe { (*sa).sa_family };
    Some(libc::c_int::from(family))
}

/// Copy up to `wanted` bytes of the sockaddr behind `sa` into zeroed storage.
///
/// On apple platforms the kernel-reported `sa_len` clamps the copy: routing
/// sockaddrs (netmasks in particular) are routinely shorter than the full
/// struct, and the zero-filled tail is semantically correct for masks.
fn copy_sockaddr(sa: *const libc::sockaddr, wanted: usize) -> Option<libc::sockaddr_storage> {
    if sa.is_null() {
        return None;
    }

    // SAFETY: `sockaddr_storage` is a plain old data buffer, zero-initializing it is valid.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };

    let len = reported_sockaddr_len(sa, wanted).min(mem::size_of::<libc::sockaddr_storage>());
    // SAFETY: `sa` points at a kernel-provided sockaddr of at least `len` bytes
    // (clamped to the kernel-reported `sa_len` on platforms that have it), and
    // `storage` is a writable buffer of at least `len` bytes.
    unsafe { ptr::copy_nonoverlapping(sa.cast::<u8>(), (&raw mut storage).cast::<u8>(), len) };

    Some(storage)
}

#[cfg(target_vendor = "apple")]
fn reported_sockaddr_len(sa: *const libc::sockaddr, wanted: usize) -> usize {
    // SAFETY: every sockaddr on apple platforms begins with an `sa_len` byte.
    let len = usize::from(unsafe { (*sa).sa_len });
    len.min(wanted)
}

#[cfg(not(target_vendor = "apple"))]
fn reported_sockaddr_len(_sa: *const libc::sockaddr, wanted: usize) -> usize {
    wanted
}

fn read_v4(sa: *const libc::sockaddr) -> Option<Ipv4Addr> {
    let storage = copy_sockaddr(sa, mem::size_of::<libc::sockaddr_in>())?;
    // SAFETY: `storage` is a fully-initialized (zero-padded) buffer at least as
    // large as `sockaddr_in`; `read_unaligned` because `sockaddr_storage` does
    // not guarantee alignment for `sockaddr_in`.
    let addr: libc::sockaddr_in = unsafe { ptr::read_unaligned((&raw const storage).cast()) };
    Some(Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)))
}

/// Read an IPv6 address and its zone (scope id) from a sockaddr.
fn read_v6(sa: *const libc::sockaddr) -> Option<(Ipv6Addr, u32)> {
    let storage = copy_sockaddr(sa, mem::size_of::<libc::sockaddr_in6>())?;
    // SAFETY: `storage` is a fully-initialized (zero-padded) buffer at least as
    // large as `sockaddr_in6`; `read_unaligned` because `sockaddr_storage` does
    // not guarantee alignment for `sockaddr_in6`.
    let addr: libc::sockaddr_in6 = unsafe { ptr::read_unaligned((&raw const storage).cast()) };
    Some((Ipv6Addr::from(addr.sin6_addr.s6_addr), addr.sin6_scope_id))
}

/// Prefix length of `address`'s network per the given netmask sockaddr.
///
/// The mask is read with the family of the assigned address: netmask
/// sockaddrs frequently carry a zero/garbage family of their own. Zero and
/// non-contiguous masks yield `None`.
fn netmask_prefix(mask: *const libc::sockaddr, address: IpAddr) -> Option<u8> {
    let mask_addr = match address {
        IpAddr::V4(_) => IpAddr::V4(read_v4(mask)?),
        IpAddr::V6(_) => IpAddr::V6(read_v6(mask)?.0),
    };
    let prefix = IpNet::with_netmask(address, mask_addr).ok()?.prefix_len();
    (prefix > 0).then_some(prefix)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_link(sa: *const libc::sockaddr) -> (Option<HardwareAddress>, Option<u32>) {
    let Some(storage) = copy_sockaddr(sa, mem::size_of::<libc::sockaddr_ll>()) else {
        return (None, None);
    };
    // SAFETY: `storage` is a fully-initialized buffer at least as large as
    // `sockaddr_ll`; `read_unaligned` since alignment is not guaranteed.
    let link: libc::sockaddr_ll = unsafe { ptr::read_unaligned((&raw const storage).cast()) };

    let hw_address = link
        .sll_addr
        .get(..usize::from(link.sll_halen))
        .and_then(HardwareAddress::try_new);
    let index = u32::try_from(link.sll_ifindex)
        .ok()
        .filter(|index| *index != 0);
    (hw_address, index)
}

#[cfg(target_vendor = "apple")]
fn read_link(sa: *const libc::sockaddr) -> (Option<HardwareAddress>, Option<u32>) {
    let Some(storage) = copy_sockaddr(sa, mem::size_of::<libc::sockaddr_dl>()) else {
        return (None, None);
    };
    // SAFETY: `storage` is a fully-initialized buffer at least as large as
    // `sockaddr_dl`; `read_unaligned` since alignment is not guaranteed.
    let link: libc::sockaddr_dl = unsafe { ptr::read_unaligned((&raw const storage).cast()) };

    let index = (link.sdl_index != 0).then(|| u32::from(link.sdl_index));

    // The link-layer payload (interface name + address) at `sdl_data` routinely
    // extends beyond the struct's declared 12 bytes: read it from the original
    // allocation, bounds-checked against the kernel-reported `sdl_len`, never
    // through the copied-out fixed-size field.
    let name_len = usize::from(link.sdl_nlen);
    let addr_len = usize::from(link.sdl_alen);
    let start = mem::offset_of!(libc::sockaddr_dl, sdl_data) + name_len;
    if addr_len == 0
        || addr_len > HardwareAddress::MAX_LEN
        || start + addr_len > usize::from(link.sdl_len)
    {
        return (None, index);
    }

    let mut bytes = [0u8; HardwareAddress::MAX_LEN];
    let src = sa.cast::<u8>().wrapping_add(start);
    // SAFETY: `start + addr_len <= sdl_len`, the kernel-reported length of the
    // allocation behind `sa`, so the read stays in bounds.
    unsafe { ptr::copy_nonoverlapping(src, bytes.as_mut_ptr(), addr_len) };

    (
        bytes.get(..addr_len).and_then(HardwareAddress::try_new),
        index,
    )
}

fn name_to_index(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    // SAFETY: `name` is a valid NUL-terminated C string.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_sockaddr(octets: [u8; 4]) -> libc::sockaddr_in {
        // SAFETY: all-zero `sockaddr_in` is a valid POD value for a test fixture.
        let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
        #[cfg(target_vendor = "apple")]
        {
            sin.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
        }
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_addr = libc::in_addr {
            s_addr: u32::from_be_bytes(octets).to_be(),
        };
        sin
    }

    fn v6_sockaddr(addr: Ipv6Addr) -> libc::sockaddr_in6 {
        // SAFETY: all-zero `sockaddr_in6` is a valid POD value for a test fixture.
        let mut sin6: libc::sockaddr_in6 = unsafe { mem::zeroed() };
        #[cfg(target_vendor = "apple")]
        {
            sin6.sin6_len = mem::size_of::<libc::sockaddr_in6>() as u8;
        }
        sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        sin6.sin6_addr = libc::in6_addr {
            s6_addr: addr.octets(),
        };
        sin6
    }

    #[test]
    fn read_v4_roundtrip() {
        let sin = v4_sockaddr([192, 168, 1, 7]);
        assert_eq!(
            read_v4(ptr::from_ref(&sin).cast()),
            Some(Ipv4Addr::new(192, 168, 1, 7))
        );
    }

    #[test]
    fn read_v6_roundtrip() {
        let ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0);
        let sin6 = v6_sockaddr(ip);
        assert_eq!(read_v6(ptr::from_ref(&sin6).cast()), Some((ip, 0)));

        let mut scoped = v6_sockaddr(ip);
        scoped.sin6_scope_id = 7;
        assert_eq!(read_v6(ptr::from_ref(&scoped).cast()), Some((ip, 7)));
    }

    #[test]
    fn read_from_null_sockaddr() {
        assert_eq!(read_v4(ptr::null()), None);
        assert_eq!(read_v6(ptr::null()), None);
        assert_eq!(sockaddr_family(ptr::null()), None);
    }

    #[test]
    fn netmask_prefix_contiguous_v4() {
        let mask = v4_sockaddr([255, 255, 255, 0]);
        let address: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        assert_eq!(
            netmask_prefix(ptr::from_ref(&mask).cast(), address),
            Some(24)
        );
    }

    #[test]
    fn netmask_prefix_contiguous_v6() {
        let mask = v6_sockaddr(Ipv6Addr::from([
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0,
        ]));
        let address: IpAddr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into();
        assert_eq!(
            netmask_prefix(ptr::from_ref(&mask).cast(), address),
            Some(64)
        );
    }

    #[test]
    fn netmask_prefix_rejects_non_contiguous_and_zero_masks() {
        let address: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();

        let mask = v4_sockaddr([255, 0, 255, 0]);
        assert_eq!(netmask_prefix(ptr::from_ref(&mask).cast(), address), None);

        let mask = v4_sockaddr([0, 0, 0, 0]);
        assert_eq!(netmask_prefix(ptr::from_ref(&mask).cast(), address), None);

        assert_eq!(netmask_prefix(ptr::null(), address), None);
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn netmask_prefix_clamps_to_reported_sa_len() {
        // a /64 netmask as the kernel reports it: `sa_len` covers only the
        // first 8 mask bytes; anything beyond must not be interpreted.
        // SAFETY: all-zero `sockaddr_in6` is a valid POD value for a test fixture.
        let mut mask: libc::sockaddr_in6 = unsafe { mem::zeroed() };
        mask.sin6_len = 16; // 8 header bytes + 8 mask bytes
        mask.sin6_addr = libc::in6_addr {
            s6_addr: [0xff; 16],
        };

        let address: IpAddr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into();
        assert_eq!(
            netmask_prefix(ptr::from_ref(&mask).cast(), address),
            Some(64)
        );
    }

    #[test]
    fn ensure_interface_groups_by_name() {
        let mut out = Vec::new();
        let up = libc::IFF_UP as libc::c_uint;

        assert_eq!(ensure_interface(&mut out, "eth0", up), 0);
        assert_eq!(ensure_interface(&mut out, "eth0", 0), 0);
        assert_eq!(out.len(), 1);
        // flags come from the first entry seen for the interface
        assert_eq!(out[0].flags, InterfaceFlags::UP);

        assert_eq!(ensure_interface(&mut out, "eth1", 0), 1);
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].name.as_str(), "eth1");
    }

    #[cfg(not(miri))]
    #[test]
    fn name_to_index_resolves_loopback() {
        assert_eq!(name_to_index("definitely-not-an-interface-9999"), None);

        #[cfg(target_vendor = "apple")]
        let loopback = "lo0";
        #[cfg(not(target_vendor = "apple"))]
        let loopback = "lo";
        let index = name_to_index(loopback);
        assert!(index.is_some_and(|index| index > 0), "index: {index:?}");
    }

    #[test]
    fn interface_flags_mapping() {
        let raw = (libc::IFF_UP | libc::IFF_RUNNING | libc::IFF_MULTICAST) as libc::c_uint;
        let flags = interface_flags(raw);
        assert_eq!(
            flags,
            InterfaceFlags::UP | InterfaceFlags::RUNNING | InterfaceFlags::MULTICAST
        );

        // every mapped bit, on its own and combined
        for (iff, flag) in [
            (libc::IFF_UP, InterfaceFlags::UP),
            (libc::IFF_RUNNING, InterfaceFlags::RUNNING),
            (libc::IFF_LOOPBACK, InterfaceFlags::LOOPBACK),
            (libc::IFF_POINTOPOINT, InterfaceFlags::POINT_TO_POINT),
            (libc::IFF_BROADCAST, InterfaceFlags::BROADCAST),
            (libc::IFF_MULTICAST, InterfaceFlags::MULTICAST),
        ] {
            assert_eq!(interface_flags(iff as libc::c_uint), flag);
        }
        let all = (libc::IFF_UP
            | libc::IFF_RUNNING
            | libc::IFF_LOOPBACK
            | libc::IFF_POINTOPOINT
            | libc::IFF_BROADCAST
            | libc::IFF_MULTICAST) as libc::c_uint;
        assert_eq!(interface_flags(all), InterfaceFlags::all());

        assert_eq!(interface_flags(0), InterfaceFlags::empty());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn read_link_extracts_mac_and_index() {
        const MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0x0d, 0xee, 0xff];
        // SAFETY: all-zero `sockaddr_ll` is a valid POD value for a test fixture.
        let mut link: libc::sockaddr_ll = unsafe { mem::zeroed() };
        link.sll_family = libc::AF_PACKET as libc::c_ushort;
        link.sll_ifindex = 3;
        link.sll_halen = MAC.len() as libc::c_uchar;
        link.sll_addr[..MAC.len()].copy_from_slice(&MAC);

        let (hw_address, index) = read_link(ptr::from_ref(&link).cast());
        assert_eq!(index, Some(3));
        assert_eq!(hw_address.unwrap().as_bytes(), &MAC);

        // an oversized (e.g. infiniband) hardware address is not truncated
        link.sll_halen = 20;
        let (hw_address, index) = read_link(ptr::from_ref(&link).cast());
        assert_eq!(index, Some(3));
        assert!(hw_address.is_none());
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn read_link_extracts_mac_beyond_declared_sdl_data() {
        const NAME: &[u8] = b"bridge100"; // long enough to push the MAC past sdl_data[12]
        const MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0x0d, 0xee, 0xff];
        let data_offset = mem::offset_of!(libc::sockaddr_dl, sdl_data);
        let total = data_offset + NAME.len() + MAC.len();

        let mut buf = [0u8; 64];
        assert!(total <= buf.len());

        // SAFETY: all-zero `sockaddr_dl` is a valid POD value for a test fixture.
        let mut link: libc::sockaddr_dl = unsafe { mem::zeroed() };
        link.sdl_len = total as libc::c_uchar;
        link.sdl_family = libc::AF_LINK as libc::c_uchar;
        link.sdl_index = 7;
        link.sdl_nlen = NAME.len() as libc::c_uchar;
        link.sdl_alen = MAC.len() as libc::c_uchar;
        // SAFETY: `buf` is 64 bytes, large enough for a `sockaddr_dl` header.
        unsafe { ptr::write_unaligned(buf.as_mut_ptr().cast::<libc::sockaddr_dl>(), link) };
        buf[data_offset..data_offset + NAME.len()].copy_from_slice(NAME);
        buf[data_offset + NAME.len()..total].copy_from_slice(&MAC);

        let (hw_address, index) = read_link(buf.as_ptr().cast());
        assert_eq!(index, Some(7));
        assert_eq!(hw_address.unwrap().as_bytes(), &MAC);

        // a truncated sdl_len must not yield (partial) address bytes
        // SAFETY: all-zero `sockaddr_dl` is a valid POD value for a test fixture.
        let mut short: libc::sockaddr_dl = unsafe { mem::zeroed() };
        short.sdl_len = (total - 3) as libc::c_uchar;
        short.sdl_index = 7;
        short.sdl_nlen = NAME.len() as libc::c_uchar;
        short.sdl_alen = MAC.len() as libc::c_uchar;
        // SAFETY: `buf` is 64 bytes, large enough for a `sockaddr_dl` header.
        unsafe { ptr::write_unaligned(buf.as_mut_ptr().cast::<libc::sockaddr_dl>(), short) };

        let (hw_address, index) = read_link(buf.as_ptr().cast());
        assert_eq!(index, Some(7));
        assert!(hw_address.is_none());

        // an oversized link-layer address is not truncated
        // SAFETY: all-zero `sockaddr_dl` is a valid POD value for a test fixture.
        let mut oversized: libc::sockaddr_dl = unsafe { mem::zeroed() };
        oversized.sdl_len = 60;
        oversized.sdl_index = 7;
        oversized.sdl_nlen = NAME.len() as libc::c_uchar;
        oversized.sdl_alen = 9;
        // SAFETY: `buf` is 64 bytes, large enough for a `sockaddr_dl` header.
        unsafe { ptr::write_unaligned(buf.as_mut_ptr().cast::<libc::sockaddr_dl>(), oversized) };

        let (hw_address, index) = read_link(buf.as_ptr().cast());
        assert_eq!(index, Some(7));
        assert!(hw_address.is_none());

        // exactly 8 address bytes (the maximum) are accepted
        const WIDE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        // SAFETY: all-zero `sockaddr_dl` is a valid POD value for a test fixture.
        let mut max: libc::sockaddr_dl = unsafe { mem::zeroed() };
        max.sdl_len = (data_offset + NAME.len() + WIDE.len()) as libc::c_uchar;
        max.sdl_index = 7;
        max.sdl_nlen = NAME.len() as libc::c_uchar;
        max.sdl_alen = WIDE.len() as libc::c_uchar;
        // SAFETY: `buf` is 64 bytes, large enough for a `sockaddr_dl` header.
        unsafe { ptr::write_unaligned(buf.as_mut_ptr().cast::<libc::sockaddr_dl>(), max) };
        buf[data_offset + NAME.len()..data_offset + NAME.len() + WIDE.len()].copy_from_slice(&WIDE);

        let (hw_address, index) = read_link(buf.as_ptr().cast());
        assert_eq!(index, Some(7));
        assert_eq!(hw_address.unwrap().as_bytes(), &WIDE);
    }
}
