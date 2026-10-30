use super::{ProcessSocket, TransportProtocol};
use std::{
    ffi::c_void,
    io,
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
    NetworkManagement::IpHelper::*,
    Networking::WinSock::{AF_INET, AF_INET6},
};

const MAX_TABLE_ATTEMPTS: usize = 8;

/// The IP Helper function that fills a table.
#[derive(Clone, Copy)]
enum TableApi {
    /// `GetExtendedTcpTable`.
    Tcp,
    /// `GetExtendedUdpTable`.
    Udp,
}

// Rows start right after the DWORD row count in all four owner-PID tables.
const _: () = {
    assert!(std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table) == size_of::<u32>());
    assert!(std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table) == size_of::<u32>());
    assert!(std::mem::offset_of!(MIB_UDPTABLE_OWNER_PID, table) == size_of::<u32>());
    assert!(std::mem::offset_of!(MIB_UDP6TABLE_OWNER_PID, table) == size_of::<u32>());
};

pub(super) fn listening_sockets(pid: u32) -> io::Result<Vec<ProcessSocket>> {
    let mut sockets = Vec::new();

    tcp_listeners(pid, &mut sockets)?;
    udp_endpoints(pid, &mut sockets)?;

    Ok(sockets)
}

fn tcp_listeners(pid: u32, sockets: &mut Vec<ProcessSocket>) -> io::Result<()> {
    // SAFETY: `GetExtendedTcpTable` with `AF_INET` and
    // `TCP_TABLE_OWNER_PID_LISTENER` returns a `MIB_TCPTABLE_OWNER_PID` of
    // `MIB_TCPROW_OWNER_PID` rows (API docs), whose fields are all u32.
    let ipv4 = unsafe {
        table::<MIB_TCPROW_OWNER_PID>(TableApi::Tcp, AF_INET, TCP_TABLE_OWNER_PID_LISTENER)?
    };
    for row in ipv4.into_iter().filter(|row| row.dwOwningPid == pid) {
        push_bound(
            sockets,
            TransportProtocol::Tcp,
            ipv4_address(row.dwLocalAddr, row.dwLocalPort),
        );
    }

    // SAFETY: with `AF_INET6` the table is a `MIB_TCP6TABLE_OWNER_PID` of
    // `MIB_TCP6ROW_OWNER_PID` rows (API docs): `[u8; 16]` and u32 fields.
    let ipv6 = unsafe {
        table::<MIB_TCP6ROW_OWNER_PID>(TableApi::Tcp, AF_INET6, TCP_TABLE_OWNER_PID_LISTENER)?
    };
    for row in ipv6.into_iter().filter(|row| row.dwOwningPid == pid) {
        push_bound(
            sockets,
            TransportProtocol::Tcp,
            ipv6_address(row.ucLocalAddr, row.dwLocalPort, row.dwLocalScopeId),
        );
    }

    Ok(())
}

fn udp_endpoints(pid: u32, sockets: &mut Vec<ProcessSocket>) -> io::Result<()> {
    // SAFETY: `GetExtendedUdpTable` with `AF_INET` and `UDP_TABLE_OWNER_PID`
    // returns a `MIB_UDPTABLE_OWNER_PID` of `MIB_UDPROW_OWNER_PID` rows (API
    // docs), whose fields are all u32.
    let ipv4 =
        unsafe { table::<MIB_UDPROW_OWNER_PID>(TableApi::Udp, AF_INET, UDP_TABLE_OWNER_PID)? };
    for row in ipv4.into_iter().filter(|row| row.dwOwningPid == pid) {
        push_bound(
            sockets,
            TransportProtocol::Udp,
            ipv4_address(row.dwLocalAddr, row.dwLocalPort),
        );
    }

    // SAFETY: with `AF_INET6` the table is a `MIB_UDP6TABLE_OWNER_PID` of
    // `MIB_UDP6ROW_OWNER_PID` rows (API docs): `[u8; 16]` and u32 fields.
    let ipv6 =
        unsafe { table::<MIB_UDP6ROW_OWNER_PID>(TableApi::Udp, AF_INET6, UDP_TABLE_OWNER_PID)? };
    for row in ipv6.into_iter().filter(|row| row.dwOwningPid == pid) {
        push_bound(
            sockets,
            TransportProtocol::Udp,
            ipv6_address(row.ucLocalAddr, row.dwLocalPort, row.dwLocalScopeId),
        );
    }

    Ok(())
}

fn push_bound(
    sockets: &mut Vec<ProcessSocket>,
    protocol: TransportProtocol,
    local_addr: SocketAddr,
) {
    if local_addr.port() != 0 {
        sockets.push(ProcessSocket {
            protocol,
            local_addr,
        });
    }
}

fn ipv4_address(address: u32, port: u32) -> SocketAddr {
    SocketAddr::from((
        Ipv4Addr::from(address.to_ne_bytes()),
        u16::from_be(port as u16),
    ))
}

fn ipv6_address(address: [u8; 16], port: u32, scope: u32) -> SocketAddr {
    SocketAddrV6::new(Ipv6Addr::from(address), u16::from_be(port as u16), 0, scope).into()
}

/// Read an IP Helper table whose rows follow a DWORD count.
///
/// # Safety
///
/// The caller must ensure that `api`, `family` and `class` select a table
/// whose rows are exactly `T`, starting right after the DWORD row count, and
/// that every initialized bit pattern of `size_of::<T>()` bytes is a valid `T`.
unsafe fn table<T: Copy>(api: TableApi, family: u16, class: i32) -> io::Result<Vec<T>> {
    let buffer = query_table(api, family, class)?;
    let Some(&count) = buffer.first() else {
        return Err(io::Error::other("missing process socket table"));
    };

    let row_bytes = (buffer.len() - 1) * size_of::<u32>();
    if size_of::<T>() == 0 || count as usize > row_bytes / size_of::<T>() {
        return Err(io::Error::other("invalid process socket table size"));
    }

    let mut rows = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let offset = size_of::<u32>() + index * size_of::<T>();
        let row = buffer
            .as_ptr()
            .cast::<u8>()
            .wrapping_add(offset)
            .cast::<T>();

        // SAFETY: `read_unaligned` needs `size_of::<T>()` readable bytes
        // holding a valid `T`, without alignment. `index < count` and the
        // `count` check give `offset + size_of::<T>() <= buffer.len() * 4`,
        // so the bytes lie in `buffer`, initialized as `u32`s; the caller
        // guarantees these bytes are row `index` and any of them is a valid `T`.
        let row = unsafe { row.read_unaligned() };
        rows.push(row);
    }

    Ok(rows)
}

fn query_table(api: TableApi, family: u16, class: i32) -> io::Result<Vec<u32>> {
    let mut size = 0;
    let mut buffer: Vec<u32> = Vec::new();

    // The system-wide socket tables can grow between the size query and read.
    // Loop invariant: `size as usize <= buffer.len() * 4`.
    for _ in 0..MAX_TABLE_ATTEMPTS {
        let destination: *mut c_void = if buffer.is_empty() {
            std::ptr::null_mut()
        } else {
            buffer.as_mut_ptr().cast()
        };

        // Both calls: per the `GetExtendedTcpTable`/`GetExtendedUdpTable` docs
        // the call writes at most `*pdwSize` bytes to the table pointer (only
        // the required size, into `size`, when that is too small or the
        // pointer is null) and returns synchronously. `destination` is null or
        // `buffer`'s allocation, writable for `buffer.len() * 4 >= size` bytes
        // (loop invariant); `size` is a live, writable u32.
        let result = match api {
            // SAFETY: discharged by the shared proof above.
            TableApi::Tcp => unsafe {
                GetExtendedTcpTable(destination, &mut size, 0, family.into(), class, 0)
            },
            // SAFETY: discharged by the shared proof above.
            TableApi::Udp => unsafe {
                GetExtendedUdpTable(destination, &mut size, 0, family.into(), class, 0)
            },
        };
        match result {
            ERROR_INSUFFICIENT_BUFFER => {
                // Restores the loop invariant for the new `size`.
                buffer.resize((size as usize).div_ceil(size_of::<u32>()), 0);
            }
            NO_ERROR => {
                if size as usize > buffer.len() * size_of::<u32>()
                    || !(size as usize).is_multiple_of(size_of::<u32>())
                {
                    return Err(io::Error::other("invalid process socket table size"));
                }
                buffer.truncate(size as usize / size_of::<u32>());
                return Ok(buffer);
            }
            error => return Err(io::Error::from_raw_os_error(error as i32)),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "process socket table kept growing",
    ))
}
