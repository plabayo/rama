use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use rama_utils::str::smol_str::SmolStr;

use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    IF_TYPE_PPP, IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_NO_MULTICAST,
    IP_ADAPTER_UNICAST_ADDRESS_LH,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, IpDadStateDeprecated, IpDadStatePreferred,
    SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
};

use super::{HardwareAddress, Interface, InterfaceAddress, InterfaceFlags};

pub(super) fn interfaces() -> io::Result<Vec<Interface>> {
    const FLAGS: u32 = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

    // 16 KiB initial buffer as the API documentation recommends; u64 units
    // keep it aligned for `IP_ADAPTER_ADDRESSES_LH`.
    let mut buf: Vec<u64> = vec![0; 2048];
    for _ in 0..3 {
        let mut size = u32::try_from(buf.len() * mem::size_of::<u64>()).unwrap_or(u32::MAX);
        // SAFETY: `buf` is writable for `size` bytes and 8-byte aligned;
        // `size` is a valid in/out byte-count pointer.
        let ret = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                FLAGS,
                ptr::null(),
                buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &raw mut size,
            )
        };
        match ret {
            NO_ERROR => {
                // SAFETY: `GetAdaptersAddresses` succeeded, so per its docs
                // `buf` holds the `IP_ADAPTER_ADDRESSES` list (C structures,
                // each starting with its `Length`, laid out in the 8-aligned
                // buffer), with unicast lists, sockaddrs of `iSockaddrLength`
                // bytes and NUL-terminated names inside it: the
                // `parse_adapters` contract. `buf` is not
                // touched until it returns, and `as_ptr` after `as_mut_ptr`
                // keeps the API's pointers valid (`Vec::as_ptr` docs).
                return Ok(unsafe { parse_adapters(buf.as_ptr().cast()) });
            }
            ERROR_NO_DATA => return Ok(Vec::new()),
            ERROR_BUFFER_OVERFLOW => {
                buf.resize((size as usize).div_ceil(mem::size_of::<u64>()), 0);
            }
            code => return Err(io::Error::from_raw_os_error(code as i32)),
        }
    }

    Err(io::Error::other(
        "GetAdaptersAddresses did not settle on a buffer size",
    ))
}

/// Convert the adapter list returned by `GetAdaptersAddresses`.
///
/// # Safety
///
/// The caller must ensure that `head` is null or points to a list of nodes
/// linked by `Next` (null-terminated), each aligned for
/// `IP_ADAPTER_ADDRESSES_LH` with its leading `Length` and then its first
/// `Length` bytes initialized. Every node whose `Length` covers a whole
/// `IP_ADAPTER_ADDRESSES_LH` must have a `FirstUnicastAddress` list meeting
/// the same rule for `IP_ADAPTER_UNICAST_ADDRESS_LH`, `Address` entries of
/// those whole unicast nodes meeting the [`read_socket_address`] contract,
/// and a `FriendlyName` and `Description` meeting the [`wide_to_smolstr`]
/// contract. All of it must stay live and unmodified for the duration of the
/// call.
unsafe fn parse_adapters(head: *const IP_ADAPTER_ADDRESSES_LH) -> Vec<Interface> {
    // `Length` (at offset 0) and `Next` lead every version of both structures
    const _: () = assert!(
        mem::offset_of!(IP_ADAPTER_ADDRESSES_LH, Anonymous1) == 0
            && mem::offset_of!(IP_ADAPTER_UNICAST_ADDRESS_LH, Anonymous) == 0
    );
    const ADAPTER_NEXT_END: usize = mem::offset_of!(IP_ADAPTER_ADDRESSES_LH, Next)
        + mem::size_of::<*mut IP_ADAPTER_ADDRESSES_LH>();
    const UNICAST_NEXT_END: usize = mem::offset_of!(IP_ADAPTER_UNICAST_ADDRESS_LH, Next)
        + mem::size_of::<*mut IP_ADAPTER_UNICAST_ADDRESS_LH>();

    let mut out = Vec::new();

    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: `ptr::read` of the leading `Length` field, at offset 0: an
        // initialized u32 of the aligned non-null node (this function's
        // contract); no reference to the node is made.
        let length = unsafe { cursor.cast::<u32>().read() } as usize;
        if length < ADAPTER_NEXT_END {
            break;
        }
        if length < mem::size_of::<IP_ADAPTER_ADDRESSES_LH>() {
            // SAFETY: a place read of `Next`, which lies within the first
            // `length` initialized bytes (checked above).
            cursor = unsafe { (*cursor).Next };
            continue;
        }
        // SAFETY: `cursor` is non-null and is `head` or a `Next` link of the
        // list, and its `Length` covers a whole `IP_ADAPTER_ADDRESSES_LH`
        // (checked above), so by this function's contract it is an aligned,
        // initialized one, unmodified while `adapter` is used (this iteration).
        let adapter = unsafe { &*cursor };
        cursor = adapter.Next;

        // SAFETY: a union field read needs initialized bytes valid for the
        // field: the union holds integers only and `adapter` is initialized,
        // and every u32 bit pattern is valid.
        let if_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        let index = if if_index != 0 {
            Some(if_index)
        } else if adapter.Ipv6IfIndex != 0 {
            Some(adapter.Ipv6IfIndex)
        } else {
            None
        };

        let mut flags = InterfaceFlags::empty();
        if adapter.OperStatus == IfOperStatusUp {
            // administrative and operational state are not reported separately
            flags |= InterfaceFlags::UP | InterfaceFlags::RUNNING;
        }
        if adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
            flags |= InterfaceFlags::LOOPBACK;
        }
        if adapter.IfType == IF_TYPE_PPP {
            flags |= InterfaceFlags::POINT_TO_POINT;
        }
        // SAFETY: as for `IfIndex`: an initialized integer-only union read as
        // u32.
        let adapter_flags = unsafe { adapter.Anonymous2.Flags };
        if adapter_flags & IP_ADAPTER_NO_MULTICAST == 0 {
            flags |= InterfaceFlags::MULTICAST;
        }

        // an out-of-range length yields `None` rather than a truncated address
        let hw_address = usize::try_from(adapter.PhysicalAddressLength)
            .ok()
            .and_then(|len| adapter.PhysicalAddress.get(..len))
            .and_then(HardwareAddress::try_new);

        let mut addresses = Vec::new();
        let mut unicast_cursor = adapter.FirstUnicastAddress;
        while !unicast_cursor.is_null() {
            // SAFETY: as for the adapter's `Length`, for this unicast node.
            let length = unsafe { unicast_cursor.cast::<u32>().read() } as usize;
            if length < UNICAST_NEXT_END {
                break;
            }
            if length < mem::size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>() {
                // SAFETY: as for the adapter's `Next`.
                unicast_cursor = unsafe { (*unicast_cursor).Next };
                continue;
            }
            // SAFETY: as for `adapter`: a non-null `FirstUnicastAddress` or
            // `Next` link whose `Length` covers a whole
            // `IP_ADAPTER_UNICAST_ADDRESS_LH`, unmodified while `unicast` is
            // used (this iteration).
            let unicast = unsafe { &*unicast_cursor };
            unicast_cursor = unicast.Next;

            // skip addresses that failed or have not yet passed duplicate
            // address detection; deprecated ones are still assigned and usable
            if unicast.DadState != IpDadStatePreferred && unicast.DadState != IpDadStateDeprecated {
                continue;
            }
            // SAFETY: by this function's contract `unicast.Address` meets the
            // `read_socket_address` contract.
            let Some((address, scope_id)) = (unsafe { read_socket_address(&unicast.Address) })
            else {
                continue;
            };
            let prefix = (unicast.OnLinkPrefixLength > 0).then_some(unicast.OnLinkPrefixLength);
            addresses.push(InterfaceAddress::new(address, prefix, Some(scope_id)));
        }

        // SAFETY: by this function's contract `FriendlyName` meets the
        // `wide_to_smolstr` contract.
        let name = unsafe { wide_to_smolstr(adapter.FriendlyName) }.unwrap_or_default();
        // SAFETY: as for `FriendlyName`.
        let description = unsafe { wide_to_smolstr(adapter.Description) };
        out.push(Interface {
            name,
            index,
            flags,
            hw_address,
            description,
            addresses,
        });
    }

    out
}

/// Read an IP address and its zone (scope id; `0` for IPv4) from a socket address.
///
/// # Safety
///
/// The caller must ensure that `address.lpSockaddr` is null or points to
/// `address.iSockaddrLength` initialized, readable bytes that stay unmodified
/// for the duration of the call. No alignment is required.
unsafe fn read_socket_address(address: &SOCKET_ADDRESS) -> Option<(IpAddr, u32)> {
    const FAMILY_END: usize =
        mem::offset_of!(SOCKADDR, sa_family) + mem::size_of::<ADDRESS_FAMILY>();

    let sa = address.lpSockaddr;
    if sa.is_null() {
        return None;
    }
    let len = usize::try_from(address.iSockaddrLength).ok()?;
    if len < FAMILY_END {
        return None;
    }
    let family_ptr = sa
        .cast::<u8>()
        .wrapping_add(mem::offset_of!(SOCKADDR, sa_family));
    // SAFETY: `read_unaligned` needs `family_ptr` readable and initialized for
    // an `ADDRESS_FAMILY`, without alignment: those bytes end at
    // `FAMILY_END <= len`, inside what the caller guarantees.
    let family = unsafe { family_ptr.cast::<ADDRESS_FAMILY>().read_unaligned() };
    match family {
        AF_INET => {
            if len < mem::size_of::<SOCKADDR_IN>() {
                return None;
            }
            // SAFETY: `read_unaligned` needs `size_of::<SOCKADDR_IN>()`
            // readable bytes holding a valid `SOCKADDR_IN`, without alignment.
            // The length check above and the caller's contract cover the
            // bytes; `SOCKADDR_IN` has integer (and integer-union) fields only,
            // so any initialized bytes are valid.
            let sin = unsafe { ptr::read_unaligned(sa.cast::<SOCKADDR_IN>()) };
            // SAFETY: a union field read needs initialized bytes valid for the
            // field: `sin` is initialized and every u32 bit pattern is valid.
            let raw = unsafe { sin.sin_addr.S_un.S_addr };
            Some((IpAddr::V4(Ipv4Addr::from(u32::from_be(raw))), 0))
        }
        AF_INET6 => {
            if len < mem::size_of::<SOCKADDR_IN6>() {
                return None;
            }
            // SAFETY: as for `SOCKADDR_IN`, with the `SOCKADDR_IN6` length
            // check; it too has integer (and integer-union) fields only.
            let sin6 = unsafe { ptr::read_unaligned(sa.cast::<SOCKADDR_IN6>()) };
            // SAFETY: an initialized integer-only union read as `[u8; 16]`.
            let octets = unsafe { sin6.sin6_addr.u.Byte };
            // SAFETY: an initialized integer-only union read as u32.
            let scope_id = unsafe { sin6.Anonymous.sin6_scope_id };
            Some((IpAddr::V6(Ipv6Addr::from(octets)), scope_id))
        }
        _ => None,
    }
}

/// Decode a NUL-terminated UTF-16 string; `None` when null or empty.
///
/// # Safety
///
/// The caller must ensure that `wide` is null or points to an aligned,
/// initialized sequence of u16 units in one allocation, ending with a 0 unit,
/// that stays unmodified for the duration of the call.
unsafe fn wide_to_smolstr(wide: *const u16) -> Option<SmolStr> {
    if wide.is_null() {
        return None;
    }
    let mut len = 0usize;
    loop {
        let cursor = wide.wrapping_add(len);
        // SAFETY: a place read needs `cursor` aligned, readable and
        // initialized for a u16. Units `0..len` were non-zero, so `cursor` is
        // at or before the terminator, inside the caller-guaranteed sequence.
        if unsafe { *cursor } == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 {
        return None;
    }
    // SAFETY: `from_raw_parts` needs `wide` non-null, aligned, and `len`
    // initialized u16s in one allocation, unmodified for the slice's use (this
    // function), with `len * 2 <= isize::MAX`. The scan read units `0..len`
    // inside the caller's single-allocation sequence, which bounds the size.
    let units = unsafe { std::slice::from_raw_parts(wide, len) };
    // collect straight into a SmolStr: short names stay inline, heap-free
    Some(
        char::decode_utf16(units.iter().copied())
            .map(|result| result.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Networking::WinSock::{
        IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6_0,
    };

    #[test]
    fn read_socket_address_v4() {
        let mut sin = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_be_bytes([192, 168, 1, 7]).to_be(),
                },
            },
            ..Default::default()
        };
        let address = SOCKET_ADDRESS {
            lpSockaddr: ptr::from_mut(&mut sin).cast::<SOCKADDR>(),
            iSockaddrLength: i32::try_from(mem::size_of::<SOCKADDR_IN>()).unwrap(),
        };
        // SAFETY: `lpSockaddr` points to the live, initialized `sin`, whose
        // size is `iSockaddrLength`.
        let got = unsafe { read_socket_address(&address) };
        assert_eq!(got, Some((IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7)), 0)));
    }

    #[test]
    fn read_socket_address_v6() {
        let ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0);
        let mut sin6 = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 { Byte: ip.octets() },
            },
            Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 3 },
        };
        let address = SOCKET_ADDRESS {
            lpSockaddr: ptr::from_mut(&mut sin6).cast::<SOCKADDR>(),
            iSockaddrLength: i32::try_from(mem::size_of::<SOCKADDR_IN6>()).unwrap(),
        };
        // SAFETY: `lpSockaddr` points to the live, initialized `sin6`, whose
        // size is `iSockaddrLength`.
        let got = unsafe { read_socket_address(&address) };
        assert_eq!(got, Some((IpAddr::V6(ip), 3)));
    }

    #[test]
    fn read_socket_address_rejects_short_and_null() {
        let mut sin = SOCKADDR_IN {
            sin_family: AF_INET,
            ..Default::default()
        };
        let address = SOCKET_ADDRESS {
            lpSockaddr: ptr::from_mut(&mut sin).cast::<SOCKADDR>(),
            iSockaddrLength: 4,
        };
        // SAFETY: `lpSockaddr` points to the live, initialized 16-byte `sin`,
        // readable for the 4 bytes claimed.
        let got = unsafe { read_socket_address(&address) };
        assert_eq!(got, None);

        let address = SOCKET_ADDRESS {
            lpSockaddr: ptr::from_mut(&mut sin).cast::<SOCKADDR>(),
            iSockaddrLength: 1,
        };
        // SAFETY: as above, for 1 byte: too short to hold the family.
        let got = unsafe { read_socket_address(&address) };
        assert_eq!(got, None);

        let address = SOCKET_ADDRESS {
            lpSockaddr: ptr::null_mut(),
            iSockaddrLength: 0,
        };
        // SAFETY: a null `lpSockaddr` is allowed by the contract.
        let got = unsafe { read_socket_address(&address) };
        assert_eq!(got, None);
    }

    #[test]
    fn wide_to_smolstr_decodes_and_guards() {
        let wide: Vec<u16> = "Ethernet 1".encode_utf16().chain([0]).collect();
        // SAFETY: `wide` is a live, NUL-terminated u16 buffer.
        let got = unsafe { wide_to_smolstr(wide.as_ptr()) };
        assert_eq!(got.as_deref(), Some("Ethernet 1"));

        let empty = [0u16];
        // SAFETY: `empty` is a live, NUL-terminated u16 buffer.
        assert_eq!(unsafe { wide_to_smolstr(empty.as_ptr()) }, None);
        // SAFETY: null is allowed by the contract.
        assert_eq!(unsafe { wide_to_smolstr(ptr::null()) }, None);
    }

    /// The leading fields every version of the adapter structure has.
    #[repr(C)]
    struct ShortAdapter {
        length: u32,
        if_index: u32,
        next: *mut IP_ADAPTER_ADDRESSES_LH,
    }

    #[test]
    fn adapters_shorter_than_the_structure_are_skipped() {
        let name: Vec<u16> = "eth1".encode_utf16().chain([0]).collect();
        let mut whole = IP_ADAPTER_ADDRESSES_LH {
            FriendlyName: name.as_ptr().cast_mut(),
            ..Default::default()
        };
        whole.Anonymous1.Anonymous.Length =
            u32::try_from(mem::size_of::<IP_ADAPTER_ADDRESSES_LH>()).unwrap();
        whole.Anonymous1.Anonymous.IfIndex = 2;
        let mut short = ShortAdapter {
            length: u32::try_from(mem::size_of::<ShortAdapter>()).unwrap(),
            if_index: 1,
            next: &raw mut whole,
        };
        let head = (&raw mut short).cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: the `parse_adapters` contract: `short` is aligned for the
        // adapter structure and its `Length` initialized bytes lead to `whole`,
        // a whole initialized node with no unicast list, a NUL-terminated name
        // and a null description; all locals outlive the call.
        let got = unsafe { parse_adapters(head) };
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "eth1");
        assert_eq!(got[0].index, Some(2));
    }
}
