use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use rama_utils::str::smol_str::SmolStr;

use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    IF_TYPE_PPP, IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_NO_MULTICAST,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IpDadStateDeprecated, IpDadStatePreferred, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKET_ADDRESS,
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
                &mut size,
            )
        };
        match ret {
            NO_ERROR => {
                if (size as usize) < mem::size_of::<IP_ADAPTER_ADDRESSES_LH>() {
                    return Ok(Vec::new());
                }
                return Ok(parse_adapters(buf.as_ptr().cast()));
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

fn parse_adapters(head: *const IP_ADAPTER_ADDRESSES_LH) -> Vec<Interface> {
    let mut out = Vec::new();

    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: `cursor` is a live node of the linked list in the result buffer.
        let adapter = unsafe { &*cursor };
        cursor = adapter.Next;

        // SAFETY: reading the `IfIndex` view of the union; any bit pattern is a valid u32.
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
        // SAFETY: reading the `Flags` view of the union; any bit pattern is a valid u32.
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
            // SAFETY: `unicast_cursor` is a live node of the adapter's unicast list.
            let unicast = unsafe { &*unicast_cursor };
            unicast_cursor = unicast.Next;

            // skip addresses that failed or have not yet passed duplicate
            // address detection; deprecated ones are still assigned and usable
            if unicast.DadState != IpDadStatePreferred && unicast.DadState != IpDadStateDeprecated {
                continue;
            }
            let Some((address, scope_id)) = read_socket_address(&unicast.Address) else {
                continue;
            };
            let prefix = (unicast.OnLinkPrefixLength > 0).then_some(unicast.OnLinkPrefixLength);
            addresses.push(InterfaceAddress::new(address, prefix, Some(scope_id)));
        }

        out.push(Interface {
            name: wide_to_smolstr(adapter.FriendlyName).unwrap_or_default(),
            index,
            flags,
            hw_address,
            description: wide_to_smolstr(adapter.Description),
            addresses,
        });
    }

    out
}

/// Read an IP address and its zone (scope id; `0` for IPv4) from a socket address.
fn read_socket_address(address: &SOCKET_ADDRESS) -> Option<(IpAddr, u32)> {
    let sa = address.lpSockaddr;
    if sa.is_null() {
        return None;
    }
    let len = usize::try_from(address.iSockaddrLength).ok()?;
    // SAFETY: the family field is within any valid, non-null SOCKADDR.
    let family = unsafe { (*sa).sa_family };
    match family {
        AF_INET => {
            if len < mem::size_of::<SOCKADDR_IN>() {
                return None;
            }
            // SAFETY: length-checked read of a `SOCKADDR_IN`; `read_unaligned`
            // since the pointer's alignment is not guaranteed.
            let sin = unsafe { ptr::read_unaligned(sa.cast::<SOCKADDR_IN>()) };
            // SAFETY: reading the `S_addr` view of the union; any bit pattern is a valid u32.
            let raw = unsafe { sin.sin_addr.S_un.S_addr };
            Some((IpAddr::V4(Ipv4Addr::from(u32::from_be(raw))), 0))
        }
        AF_INET6 => {
            if len < mem::size_of::<SOCKADDR_IN6>() {
                return None;
            }
            // SAFETY: length-checked read of a `SOCKADDR_IN6`; `read_unaligned`
            // since the pointer's alignment is not guaranteed.
            let sin6 = unsafe { ptr::read_unaligned(sa.cast::<SOCKADDR_IN6>()) };
            // SAFETY: reading the `Byte` view of the union; any bit pattern is valid.
            let octets = unsafe { sin6.sin6_addr.u.Byte };
            // SAFETY: reading the `sin6_scope_id` view of the union; any bit pattern is a valid u32.
            let scope_id = unsafe { sin6.Anonymous.sin6_scope_id };
            Some((IpAddr::V6(Ipv6Addr::from(octets)), scope_id))
        }
        _ => None,
    }
}

fn wide_to_smolstr(wide: *const u16) -> Option<SmolStr> {
    if wide.is_null() {
        return None;
    }
    let mut len = 0usize;
    loop {
        let cursor = wide.wrapping_add(len);
        // SAFETY: `cursor` stays within the NUL-terminated UTF-16 string the API returned.
        if unsafe { *cursor } == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 {
        return None;
    }
    // SAFETY: `len` u16 units before the NUL terminator are readable.
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
        IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR, SOCKADDR_IN6_0,
    };

    #[test]
    fn read_socket_address_v4() {
        let mut sin = SOCKADDR_IN::default();
        sin.sin_family = AF_INET;
        sin.sin_addr = IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_be_bytes([192, 168, 1, 7]).to_be(),
            },
        };
        let address = SOCKET_ADDRESS {
            lpSockaddr: ptr::from_mut(&mut sin).cast::<SOCKADDR>(),
            iSockaddrLength: i32::try_from(mem::size_of::<SOCKADDR_IN>()).unwrap(),
        };
        assert_eq!(
            read_socket_address(&address),
            Some((IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7)), 0))
        );
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
        assert_eq!(read_socket_address(&address), Some((IpAddr::V6(ip), 3)));
    }

    #[test]
    fn read_socket_address_rejects_short_and_null() {
        let mut sin = SOCKADDR_IN::default();
        sin.sin_family = AF_INET;
        let address = SOCKET_ADDRESS {
            lpSockaddr: ptr::from_mut(&mut sin).cast::<SOCKADDR>(),
            iSockaddrLength: 4,
        };
        assert_eq!(read_socket_address(&address), None);

        let address = SOCKET_ADDRESS {
            lpSockaddr: ptr::null_mut(),
            iSockaddrLength: 0,
        };
        assert_eq!(read_socket_address(&address), None);
    }

    #[test]
    fn wide_to_smolstr_decodes_and_guards() {
        let wide: Vec<u16> = "Ethernet 1".encode_utf16().chain([0]).collect();
        assert_eq!(
            wide_to_smolstr(wide.as_ptr()).as_deref(),
            Some("Ethernet 1")
        );

        let empty = [0u16];
        assert_eq!(wide_to_smolstr(empty.as_ptr()), None);
        assert_eq!(wide_to_smolstr(ptr::null()), None);
    }
}
