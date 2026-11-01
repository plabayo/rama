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

    // List contract, cited by the sockaddr reads below. getifaddrs(3): every
    // node is an initialized `ifaddrs`; `ifa_name` is NUL-terminated;
    // `ifa_addr` is null or a sockaddr whose `sa_family` gives its format, and
    // `ifa_netmask` is null or the netmask of `ifa_addr` in that same format.
    // On linux and android that format is `sockaddr_in`, `sockaddr_in6` or
    // `sockaddr_ll` (packet(7)), fully readable. On apple `<sys/socket.h>`
    // defines `sa_len` (byte 0) as the total length, so each sockaddr is
    // readable for its `sa_len` bytes. All of it stays live and unmodified
    // until `list` is dropped at the end of this function.
    let mut cursor = list.head;
    while !cursor.is_null() {
        // SAFETY: `cursor` is non-null and is `list.head` or an `ifa_next` of
        // a node of the list `list` owns (`IfAddrs::head` invariant), so by
        // the list contract it is an aligned, initialized `ifaddrs` that no
        // one mutates or frees while `entry` (one iteration) is in use.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;

        if entry.ifa_name.is_null() {
            continue;
        }
        // SAFETY: `ifa_name` is non-null and, by the list contract, a
        // NUL-terminated string in the list, unmodified while `list` lives;
        // the borrow (`name`) ends with this iteration.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }.to_string_lossy();
        if name.is_empty() {
            continue;
        }

        let pos = ensure_interface(&mut out, name.as_ref(), entry.ifa_flags);
        let Some(interface) = out.get_mut(pos) else {
            continue;
        };

        // SAFETY: `ifa_addr` is null or, by the list contract, a sockaddr
        // readable for at least its family header.
        match unsafe { sockaddr_family(entry.ifa_addr) } {
            Some(libc::AF_INET) => {
                // SAFETY: by the list contract an `AF_INET` `ifa_addr` is a
                // readable `sockaddr_in` (apple: readable for its `sa_len`),
                // which is the `read_v4` contract.
                if let Some(addr) = unsafe { read_v4(entry.ifa_addr) } {
                    let address = IpAddr::V4(addr);
                    // SAFETY: by the list contract `ifa_netmask` is null or in
                    // the `AF_INET` format of `ifa_addr`, as `netmask_prefix`
                    // requires for an IPv4 `address`.
                    let prefix = unsafe { netmask_prefix(entry.ifa_netmask, address) };
                    interface
                        .addresses
                        .push(InterfaceAddress::new(address, prefix, None));
                }
            }
            Some(libc::AF_INET6) => {
                // SAFETY: by the list contract an `AF_INET6` `ifa_addr` is a
                // readable `sockaddr_in6` (apple: readable for its `sa_len`).
                if let Some((addr, scope_id)) = unsafe { read_v6(entry.ifa_addr) } {
                    let address = IpAddr::V6(addr);
                    // SAFETY: as for IPv4, with the `AF_INET6` format.
                    let prefix = unsafe { netmask_prefix(entry.ifa_netmask, address) };
                    interface.addresses.push(InterfaceAddress::new(
                        address,
                        prefix,
                        Some(scope_id),
                    ));
                }
            }
            Some(LINK_FAMILY) => {
                // SAFETY: by the list contract a `LINK_FAMILY` `ifa_addr` is a
                // readable `sockaddr_ll` (linux, android) or a `sockaddr_dl`
                // readable for its `sa_len` bytes (apple).
                let (hw_address, index) = unsafe { read_link(entry.ifa_addr) };
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
    // Safety invariant: `head` is null or the head of a list returned by a
    // successful `sys_getifaddrs` that has not been freed; `IfAddrs` owns it.
    head: *mut libc::ifaddrs,
}

impl IfAddrs {
    fn load() -> io::Result<Self> {
        let mut head = ptr::null_mut();
        sys_getifaddrs(&mut head)?;
        // Upholds the `head` invariant: `head` is null or was just returned by
        // a successful `sys_getifaddrs`.
        Ok(Self { head })
    }
}

impl Drop for IfAddrs {
    fn drop(&mut self) {
        if !self.head.is_null() {
            // SAFETY: by the `head` invariant the list came from a successful
            // `sys_getifaddrs` and is not yet freed; `drop` runs once and no
            // pointer into the list outlives `self`.
            unsafe { sys_freeifaddrs(self.head) };
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
        // SAFETY: getifaddrs(3) only writes the list head to `*out`, which
        // `&mut` makes a live, aligned, writable `*mut ifaddrs`.
        if unsafe { libc::getifaddrs(out) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// Free a list returned by [`sys_getifaddrs`].
///
/// # Safety
///
/// The caller must pass a non-null `list` returned by a successful
/// [`sys_getifaddrs`] that has not been freed. The list is freed by this call:
/// the caller must not use `list` or any pointer into its nodes afterwards.
unsafe fn sys_freeifaddrs(list: *mut libc::ifaddrs) {
    #[cfg(target_os = "android")]
    {
        // SAFETY: this function's contract is `android::freeifaddrs`'s.
        unsafe { android::freeifaddrs(list) };
    }

    #[cfg(not(target_os = "android"))]
    {
        // SAFETY: freeifaddrs(3) frees a list from getifaddrs(3); the caller
        // passes such a list, not yet freed and no longer used.
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
        // SAFETY: dlsym(3) with `RTLD_DEFAULT` and a NUL-terminated name (a
        // live `&CStr`) only looks the symbol up; it reads no other memory.
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
        // SAFETY: `transmute` from a data pointer to a same-sized fn pointer
        // (size equality is compile-checked). `sym` is non-null and is the
        // address dlsym(3) returned for `getifaddrs`, which bionic's
        // `<ifaddrs.h>` declares as `int getifaddrs(struct ifaddrs**)`: the
        // declared type, with the C ABI.
        let getifaddrs = unsafe {
            mem::transmute::<
                *mut libc::c_void,
                unsafe extern "C" fn(*mut *mut libc::ifaddrs) -> libc::c_int,
            >(sym)
        };
        // SAFETY: getifaddrs(3) only writes the list head to `*out`, a live,
        // aligned, writable `*mut ifaddrs` (`&mut`).
        if unsafe { getifaddrs(out) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Free a list returned by [`getifaddrs`]; leaks it when the symbol is
    /// missing.
    ///
    /// # Safety
    ///
    /// Same contract as [`super::sys_freeifaddrs`].
    pub(super) unsafe fn freeifaddrs(list: *mut libc::ifaddrs) {
        let Some(sym) = resolve(c"freeifaddrs") else {
            return;
        };
        // SAFETY: as in `getifaddrs`: `sym` is the non-null dlsym(3) address
        // of `freeifaddrs`, declared `void freeifaddrs(struct ifaddrs*)` by
        // bionic's `<ifaddrs.h>`.
        let freeifaddrs = unsafe {
            mem::transmute::<*mut libc::c_void, unsafe extern "C" fn(*mut libc::ifaddrs)>(sym)
        };
        // SAFETY: freeifaddrs(3) frees a getifaddrs(3) list; the caller passes
        // such a list, not yet freed and no longer used.
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

/// The address family of the sockaddr behind `sa`, or `None` when null.
///
/// # Safety
///
/// The caller must ensure that `sa` is null or points to a sockaddr whose
/// bytes up to and including its `sa_family` field are initialized and
/// readable for the duration of the call. No alignment is required.
unsafe fn sockaddr_family(sa: *const libc::sockaddr) -> Option<libc::c_int> {
    if sa.is_null() {
        return None;
    }
    let field = sa
        .cast::<u8>()
        .wrapping_add(mem::offset_of!(libc::sockaddr, sa_family));
    // SAFETY: `read_unaligned` needs `field` readable and initialized for a
    // `sa_family_t`, without alignment: `field` addresses the `sa_family`
    // bytes of `*sa`, which the caller guarantees for non-null `sa`.
    let family = unsafe { field.cast::<libc::sa_family_t>().read_unaligned() };
    Some(libc::c_int::from(family))
}

/// Byte copy of a sockaddr, as large as `sockaddr_storage`.
type SockaddrBytes = [u8; mem::size_of::<libc::sockaddr_storage>()];

/// Copy up to `wanted` bytes of the sockaddr behind `sa` into zeroed storage.
///
/// On apple platforms the kernel-reported `sa_len` clamps the copy: routing
/// sockaddrs (netmasks in particular) are routinely shorter than the full
/// struct, and the zero-filled tail is semantically correct for masks.
///
/// # Safety
///
/// The caller must ensure that `sa` is null or points to a sockaddr whose
/// first `n` bytes are initialized and readable, and not written by anyone,
/// for the duration of the call. `n` is `wanted` on targets without `sa_len`;
/// on apple it is `max(1, min(sa_len, wanted))`, `sa_len` being byte 0.
/// No alignment is required.
unsafe fn copy_sockaddr(sa: *const libc::sockaddr, wanted: usize) -> Option<SockaddrBytes> {
    if sa.is_null() {
        return None;
    }

    let mut storage: SockaddrBytes = [0; mem::size_of::<libc::sockaddr_storage>()];
    // SAFETY: `sa` is non-null and its byte 0 is readable (this function's
    // contract), as `reported_sockaddr_len` requires.
    let len = unsafe { reported_sockaddr_len(sa, wanted) }.min(storage.len());
    // SAFETY: `copy_nonoverlapping` needs `sa` readable and `storage` writable
    // for `len` bytes, without overlap. `len <= n` of this function's contract
    // (`reported_sockaddr_len` postcondition), so `sa` is readable for it;
    // `len <= storage.len()` by the `min`; `storage` is a local, so it cannot
    // overlap `*sa`. u8 copies need no alignment. The copied bytes are
    // initialized, as `[u8]` requires.
    unsafe { ptr::copy_nonoverlapping(sa.cast::<u8>(), storage.as_mut_ptr(), len) };

    Some(storage)
}

/// The number of bytes of `sa` that [`copy_sockaddr`] may read.
///
/// # Safety
///
/// The caller must ensure that `sa` is non-null and its byte 0 (`sa_len`) is
/// initialized and readable for the duration of the call.
///
/// Returns `min(sa_len, wanted)`.
#[cfg(target_vendor = "apple")]
unsafe fn reported_sockaddr_len(sa: *const libc::sockaddr, wanted: usize) -> usize {
    const { assert!(mem::offset_of!(libc::sockaddr, sa_len) == 0) };
    // SAFETY: `read` needs `sa` readable, aligned and initialized for one u8:
    // `sa_len` is byte 0 (const assert above), which the caller guarantees,
    // and a u8 has alignment 1.
    let len = usize::from(unsafe { sa.cast::<u8>().read() });
    len.min(wanted)
}

/// The number of bytes of `sa` that [`copy_sockaddr`] may read.
///
/// # Safety
///
/// None on these targets; `unsafe` keeps one signature with the apple variant.
///
/// Returns `wanted`: these targets have no `sa_len`.
#[cfg(not(target_vendor = "apple"))]
unsafe fn reported_sockaddr_len(_sa: *const libc::sockaddr, wanted: usize) -> usize {
    wanted
}

/// Read an IPv4 address from a sockaddr.
///
/// # Safety
///
/// The [`copy_sockaddr`] contract with `wanted = size_of::<sockaddr_in>()`.
unsafe fn read_v4(sa: *const libc::sockaddr) -> Option<Ipv4Addr> {
    // SAFETY: this function's contract is `copy_sockaddr`'s for this `wanted`.
    let storage = unsafe { copy_sockaddr(sa, mem::size_of::<libc::sockaddr_in>()) }?;
    let addr: libc::sockaddr_in = read_from_storage(&storage);
    Some(Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)))
}

/// Read an IPv6 address and its zone (scope id) from a sockaddr.
///
/// # Safety
///
/// The [`copy_sockaddr`] contract with `wanted = size_of::<sockaddr_in6>()`.
unsafe fn read_v6(sa: *const libc::sockaddr) -> Option<(Ipv6Addr, u32)> {
    // SAFETY: this function's contract is `copy_sockaddr`'s for this `wanted`.
    let storage = unsafe { copy_sockaddr(sa, mem::size_of::<libc::sockaddr_in6>()) }?;
    let addr: libc::sockaddr_in6 = read_from_storage(&storage);
    Some((Ipv6Addr::from(addr.sin6_addr.s6_addr), addr.sin6_scope_id))
}

/// A sockaddr struct for which every initialized byte pattern is a valid
/// value.
///
/// # Safety
///
/// Implementors must be `repr(C)` structs of integer or integer-array fields
/// only.
unsafe trait PlainSockaddr: Copy {}

// SAFETY: libc's `sockaddr_in` is `repr(C)` with integer and integer-array
// fields only.
unsafe impl PlainSockaddr for libc::sockaddr_in {}
// SAFETY: libc's `sockaddr_in6` is `repr(C)` with integer and integer-array
// fields only (`in6_addr` is a `[u8; 16]` wrapper).
unsafe impl PlainSockaddr for libc::sockaddr_in6 {}
// SAFETY: libc's `sockaddr_ll` is `repr(C)` with integer and integer-array
// fields only.
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe impl PlainSockaddr for libc::sockaddr_ll {}
// SAFETY: libc's `sockaddr_dl` is `repr(C)` with integer and integer-array
// fields only.
#[cfg(target_vendor = "apple")]
unsafe impl PlainSockaddr for libc::sockaddr_dl {}

/// Reinterpret the leading bytes of `storage` as a `T`.
fn read_from_storage<T: PlainSockaddr>(storage: &SockaddrBytes) -> T {
    const { assert!(mem::size_of::<T>() <= mem::size_of::<SockaddrBytes>()) };
    // SAFETY: `read_unaligned` needs `size_of::<T>()` readable bytes holding a
    // valid `T`, with no alignment requirement. The const assert keeps the read
    // inside `*storage`, whose bytes are initialized (`[u8]`); initialized
    // bytes are a valid `T` (`PlainSockaddr`; padding, if any, may hold any
    // byte).
    unsafe { ptr::read_unaligned(storage.as_ptr().cast::<T>()) }
}

/// Prefix length of `address`'s network per the given netmask sockaddr.
///
/// The mask is read with the family of the assigned address: netmask
/// sockaddrs frequently carry a zero/garbage family of their own. Zero and
/// non-contiguous masks yield `None`.
///
/// # Safety
///
/// The [`copy_sockaddr`] contract for `mask`, with `wanted` the size of the
/// `sockaddr_in` (IPv4 `address`) or `sockaddr_in6` (IPv6 `address`).
unsafe fn netmask_prefix(mask: *const libc::sockaddr, address: IpAddr) -> Option<u8> {
    let mask_addr = match address {
        // SAFETY: the IPv4 case of this function's contract is `read_v4`'s.
        IpAddr::V4(_) => IpAddr::V4(unsafe { read_v4(mask) }?),
        // SAFETY: the IPv6 case of this function's contract is `read_v6`'s.
        IpAddr::V6(_) => IpAddr::V6(unsafe { read_v6(mask) }?.0),
    };
    let prefix = IpNet::with_netmask(address, mask_addr).ok()?.prefix_len();
    (prefix > 0).then_some(prefix)
}

/// Read the hardware address and interface index from a link-layer sockaddr.
///
/// # Safety
///
/// The [`copy_sockaddr`] contract with `wanted = size_of::<sockaddr_ll>()`.
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn read_link(sa: *const libc::sockaddr) -> (Option<HardwareAddress>, Option<u32>) {
    // SAFETY: this function's contract is `copy_sockaddr`'s for this `wanted`.
    let Some(storage) = (unsafe { copy_sockaddr(sa, mem::size_of::<libc::sockaddr_ll>()) }) else {
        return (None, None);
    };
    let link: libc::sockaddr_ll = read_from_storage(&storage);

    let hw_address = link
        .sll_addr
        .get(..usize::from(link.sll_halen))
        .and_then(HardwareAddress::try_new);
    let index = u32::try_from(link.sll_ifindex)
        .ok()
        .filter(|index| *index != 0);
    (hw_address, index)
}

/// Read the hardware address and interface index from a link-layer sockaddr.
///
/// # Safety
///
/// The caller must ensure that `sa` is null or points to a sockaddr whose
/// first `max(1, sa_len)` bytes are initialized and readable, and not written
/// by anyone, for the duration of the call (`sa_len` being byte 0). This
/// implies the [`copy_sockaddr`] contract for any `wanted`.
#[cfg(target_vendor = "apple")]
unsafe fn read_link(sa: *const libc::sockaddr) -> (Option<HardwareAddress>, Option<u32>) {
    // SAFETY: implied by this function's contract (see `# Safety`).
    let Some(storage) = (unsafe { copy_sockaddr(sa, mem::size_of::<libc::sockaddr_dl>()) }) else {
        return (None, None);
    };
    let link: libc::sockaddr_dl = read_from_storage(&storage);

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
    // SAFETY: `copy_nonoverlapping` needs `src` readable and `bytes` writable
    // for `addr_len` bytes, without overlap. `link.sdl_len` equals `sa_len`
    // (byte 0 of `*sa`): it was copied when `sa_len >= 1` and is the zeroed 0
    // otherwise. So `start + addr_len <= sa_len` puts `src..src + addr_len`
    // inside the bytes the caller guarantees readable and initialized.
    // `addr_len <= MAX_LEN` bounds the write to `bytes`, a local that cannot
    // overlap `*sa`. u8 copies need no alignment.
    unsafe { ptr::copy_nonoverlapping(src, bytes.as_mut_ptr(), addr_len) };

    (
        bytes.get(..addr_len).and_then(HardwareAddress::try_new),
        index,
    )
}

fn name_to_index(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    // SAFETY: if_nametoindex(3) only reads the NUL-terminated string at its
    // argument; `name` is a live `CString`.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_sockaddr(octets: [u8; 4]) -> libc::sockaddr_in {
        // SAFETY: all-zero `sockaddr_in` is a valid value: integer fields only (`mem::zeroed` docs).
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
        // SAFETY: all-zero `sockaddr_in6` is a valid value: integer fields only (`mem::zeroed` docs).
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
        // SAFETY: `sin` is a live, fully initialized `sockaddr_in` (no padding;
        // apple: `sin_len` covers it), readable for the bytes `read_v4` reads.
        let got = unsafe { read_v4(ptr::from_ref(&sin).cast()) };
        assert_eq!(got, Some(Ipv4Addr::new(192, 168, 1, 7)));
    }

    #[test]
    fn read_v6_roundtrip() {
        let ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0);
        let sin6 = v6_sockaddr(ip);
        // SAFETY: `sin6` is a live, fully initialized `sockaddr_in6` (no
        // padding; apple: `sin6_len` covers it).
        let got = unsafe { read_v6(ptr::from_ref(&sin6).cast()) };
        assert_eq!(got, Some((ip, 0)));

        let mut scoped = v6_sockaddr(ip);
        scoped.sin6_scope_id = 7;
        // SAFETY: as above, for `scoped`.
        let got = unsafe { read_v6(ptr::from_ref(&scoped).cast()) };
        assert_eq!(got, Some((ip, 7)));
    }

    #[test]
    fn read_from_null_sockaddr() {
        // SAFETY: null is allowed by the `read_v4` contract.
        assert_eq!(unsafe { read_v4(ptr::null()) }, None);
        // SAFETY: null is allowed by the `read_v6` contract.
        assert_eq!(unsafe { read_v6(ptr::null()) }, None);
        // SAFETY: null is allowed by the `sockaddr_family` contract.
        assert_eq!(unsafe { sockaddr_family(ptr::null()) }, None);
    }

    #[test]
    fn netmask_prefix_contiguous_v4() {
        let mask = v4_sockaddr([255, 255, 255, 0]);
        let address: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        // SAFETY: `mask` is a live, fully initialized `sockaddr_in` (no
        // padding), matching the IPv4 `address`.
        let prefix = unsafe { netmask_prefix(ptr::from_ref(&mask).cast(), address) };
        assert_eq!(prefix, Some(24));
    }

    #[test]
    fn netmask_prefix_contiguous_v6() {
        let mask = v6_sockaddr(Ipv6Addr::from([
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0,
        ]));
        let address: IpAddr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into();
        // SAFETY: `mask` is a live, fully initialized `sockaddr_in6` (no
        // padding), matching the IPv6 `address`.
        let prefix = unsafe { netmask_prefix(ptr::from_ref(&mask).cast(), address) };
        assert_eq!(prefix, Some(64));
    }

    #[test]
    fn netmask_prefix_rejects_non_contiguous_and_zero_masks() {
        let address: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();

        let mask = v4_sockaddr([255, 0, 255, 0]);
        // SAFETY: `mask` is a live, fully initialized `sockaddr_in` (no
        // padding), matching the IPv4 `address`.
        let prefix = unsafe { netmask_prefix(ptr::from_ref(&mask).cast(), address) };
        assert_eq!(prefix, None);

        let mask = v4_sockaddr([0, 0, 0, 0]);
        // SAFETY: as above.
        let prefix = unsafe { netmask_prefix(ptr::from_ref(&mask).cast(), address) };
        assert_eq!(prefix, None);

        // SAFETY: null is allowed by the `netmask_prefix` contract.
        let prefix = unsafe { netmask_prefix(ptr::null(), address) };
        assert_eq!(prefix, None);
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn netmask_prefix_clamps_to_reported_sa_len() {
        // a /64 netmask as the kernel reports it: `sa_len` covers only the
        // first 8 mask bytes; anything beyond must not be interpreted.
        // SAFETY: all-zero `sockaddr_in6` is a valid value: integer fields only (`mem::zeroed` docs).
        let mut mask: libc::sockaddr_in6 = unsafe { mem::zeroed() };
        mask.sin6_len = 16; // 8 header bytes + 8 mask bytes
        mask.sin6_addr = libc::in6_addr {
            s6_addr: [0xff; 16],
        };

        let address: IpAddr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into();
        // SAFETY: `mask` is a live, fully initialized 28-byte `sockaddr_in6`;
        // `netmask_prefix` reads at most `sin6_len` (16) of its bytes.
        let prefix = unsafe { netmask_prefix(ptr::from_ref(&mask).cast(), address) };
        assert_eq!(prefix, Some(64));
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
        // SAFETY: all-zero `sockaddr_ll` is a valid value: integer fields only (`mem::zeroed` docs).
        let mut link: libc::sockaddr_ll = unsafe { mem::zeroed() };
        link.sll_family = libc::AF_PACKET as libc::c_ushort;
        link.sll_ifindex = 3;
        link.sll_halen = MAC.len() as libc::c_uchar;
        link.sll_addr[..MAC.len()].copy_from_slice(&MAC);

        // SAFETY: `link` is a live, fully initialized `sockaddr_ll` (no
        // padding), as `read_link` reads.
        let (hw_address, index) = unsafe { read_link(ptr::from_ref(&link).cast()) };
        assert_eq!(index, Some(3));
        assert_eq!(hw_address.unwrap().as_bytes(), &MAC);

        // an oversized (e.g. infiniband) hardware address is not truncated
        link.sll_halen = 20;
        // SAFETY: as above.
        let (hw_address, index) = unsafe { read_link(ptr::from_ref(&link).cast()) };
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

        // SAFETY: all-zero `sockaddr_dl` is a valid value: integer fields only (`mem::zeroed` docs).
        let mut link: libc::sockaddr_dl = unsafe { mem::zeroed() };
        link.sdl_len = total as libc::c_uchar;
        link.sdl_family = libc::AF_LINK as libc::c_uchar;
        link.sdl_index = 7;
        link.sdl_nlen = NAME.len() as libc::c_uchar;
        link.sdl_alen = MAC.len() as libc::c_uchar;
        // SAFETY: `write_unaligned` needs `buf` writable for the 20-byte
        // `sockaddr_dl` (64 bytes); its fields leave no padding, so `buf` stays
        // initialized.
        unsafe { ptr::write_unaligned(buf.as_mut_ptr().cast::<libc::sockaddr_dl>(), link) };
        buf[data_offset..data_offset + NAME.len()].copy_from_slice(NAME);
        buf[data_offset + NAME.len()..total].copy_from_slice(&MAC);

        // SAFETY: `buf` is 64 initialized bytes and the header's `sdl_len` is
        // at most 60, so the bytes `read_link` may read are in `buf`.
        let (hw_address, index) = unsafe { read_link(buf.as_ptr().cast()) };
        assert_eq!(index, Some(7));
        assert_eq!(hw_address.unwrap().as_bytes(), &MAC);

        // a truncated sdl_len must not yield (partial) address bytes
        // SAFETY: all-zero `sockaddr_dl` is a valid value: integer fields only (`mem::zeroed` docs).
        let mut short: libc::sockaddr_dl = unsafe { mem::zeroed() };
        short.sdl_len = (total - 3) as libc::c_uchar;
        short.sdl_index = 7;
        short.sdl_nlen = NAME.len() as libc::c_uchar;
        short.sdl_alen = MAC.len() as libc::c_uchar;
        // SAFETY: `write_unaligned` needs `buf` writable for the 20-byte
        // `sockaddr_dl` (64 bytes); its fields leave no padding, so `buf` stays
        // initialized.
        unsafe { ptr::write_unaligned(buf.as_mut_ptr().cast::<libc::sockaddr_dl>(), short) };

        // SAFETY: `buf` is 64 initialized bytes and the header's `sdl_len` is
        // at most 60, so the bytes `read_link` may read are in `buf`.
        let (hw_address, index) = unsafe { read_link(buf.as_ptr().cast()) };
        assert_eq!(index, Some(7));
        assert!(hw_address.is_none());

        // an oversized link-layer address is not truncated
        // SAFETY: all-zero `sockaddr_dl` is a valid value: integer fields only (`mem::zeroed` docs).
        let mut oversized: libc::sockaddr_dl = unsafe { mem::zeroed() };
        oversized.sdl_len = 60;
        oversized.sdl_index = 7;
        oversized.sdl_nlen = NAME.len() as libc::c_uchar;
        oversized.sdl_alen = 9;
        // SAFETY: `write_unaligned` needs `buf` writable for the 20-byte
        // `sockaddr_dl` (64 bytes); its fields leave no padding, so `buf` stays
        // initialized.
        unsafe { ptr::write_unaligned(buf.as_mut_ptr().cast::<libc::sockaddr_dl>(), oversized) };

        // SAFETY: `buf` is 64 initialized bytes and the header's `sdl_len` is
        // at most 60, so the bytes `read_link` may read are in `buf`.
        let (hw_address, index) = unsafe { read_link(buf.as_ptr().cast()) };
        assert_eq!(index, Some(7));
        assert!(hw_address.is_none());

        // exactly 8 address bytes (the maximum) are accepted
        const WIDE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        // SAFETY: all-zero `sockaddr_dl` is a valid value: integer fields only (`mem::zeroed` docs).
        let mut max: libc::sockaddr_dl = unsafe { mem::zeroed() };
        max.sdl_len = (data_offset + NAME.len() + WIDE.len()) as libc::c_uchar;
        max.sdl_index = 7;
        max.sdl_nlen = NAME.len() as libc::c_uchar;
        max.sdl_alen = WIDE.len() as libc::c_uchar;
        // SAFETY: `write_unaligned` needs `buf` writable for the 20-byte
        // `sockaddr_dl` (64 bytes); its fields leave no padding, so `buf` stays
        // initialized.
        unsafe { ptr::write_unaligned(buf.as_mut_ptr().cast::<libc::sockaddr_dl>(), max) };
        buf[data_offset + NAME.len()..data_offset + NAME.len() + WIDE.len()].copy_from_slice(&WIDE);

        // SAFETY: `buf` is 64 initialized bytes and the header's `sdl_len` is
        // at most 60, so the bytes `read_link` may read are in `buf`.
        let (hw_address, index) = unsafe { read_link(buf.as_ptr().cast()) };
        assert_eq!(index, Some(7));
        assert_eq!(hw_address.unwrap().as_bytes(), &WIDE);
    }
}
