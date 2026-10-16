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
type Query = unsafe extern "system" fn(*mut c_void, *mut u32, i32, u32, i32, u32) -> u32;

pub(super) fn listening_sockets(pid: u32) -> io::Result<Vec<ProcessSocket>> {
    let mut sockets = Vec::new();

    tcp_listeners(pid, &mut sockets)?;
    udp_endpoints(pid, &mut sockets)?;

    Ok(sockets)
}

fn tcp_listeners(pid: u32, sockets: &mut Vec<ProcessSocket>) -> io::Result<()> {
    // SAFETY: each owner-PID TCP query is paired with its SDK row type. These
    // rows contain only integer fields and begin after the DWORD row count.
    let ipv4 = unsafe {
        table::<MIB_TCPROW_OWNER_PID>(GetExtendedTcpTable, AF_INET, TCP_TABLE_OWNER_PID_LISTENER)?
    };
    for row in ipv4.into_iter().filter(|row| row.dwOwningPid == pid) {
        push_bound(
            sockets,
            TransportProtocol::Tcp,
            ipv4_address(row.dwLocalAddr, row.dwLocalPort),
        );
    }

    // SAFETY: the IPv6 owner-PID TCP table uses MIB_TCP6ROW_OWNER_PID rows.
    let ipv6 = unsafe {
        table::<MIB_TCP6ROW_OWNER_PID>(GetExtendedTcpTable, AF_INET6, TCP_TABLE_OWNER_PID_LISTENER)?
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
    // SAFETY: the IPv4 owner-PID UDP table uses MIB_UDPROW_OWNER_PID rows.
    let ipv4 = unsafe {
        table::<MIB_UDPROW_OWNER_PID>(GetExtendedUdpTable, AF_INET, UDP_TABLE_OWNER_PID)?
    };
    for row in ipv4.into_iter().filter(|row| row.dwOwningPid == pid) {
        push_bound(
            sockets,
            TransportProtocol::Udp,
            ipv4_address(row.dwLocalAddr, row.dwLocalPort),
        );
    }

    // SAFETY: the IPv6 owner-PID UDP table uses MIB_UDP6ROW_OWNER_PID rows.
    let ipv6 = unsafe {
        table::<MIB_UDP6ROW_OWNER_PID>(GetExtendedUdpTable, AF_INET6, UDP_TABLE_OWNER_PID)?
    };
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
/// The query/family/class must describe rows of exactly T. T must have no
/// invalid bit patterns, as is the case for the four owner-PID SDK row types.
unsafe fn table<T: Copy>(query: Query, family: u16, class: i32) -> io::Result<Vec<T>> {
    let buffer = query_table(query, family, class)?;
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

        // SAFETY: every row lies within the initialized buffer, checked above.
        // The caller guarantees the row layout and validity of its bit patterns.
        let row = unsafe { row.read_unaligned() };
        rows.push(row);
    }

    Ok(rows)
}

fn query_table(query: Query, family: u16, class: i32) -> io::Result<Vec<u32>> {
    let mut size = 0;
    let mut buffer: Vec<u32> = Vec::new();

    // The system-wide socket tables can grow between the size query and read.
    for _ in 0..MAX_TABLE_ATTEMPTS {
        let destination = if buffer.is_empty() {
            std::ptr::null_mut()
        } else {
            buffer.as_mut_ptr().cast()
        };

        // SAFETY: null requests the size; otherwise the u32 allocation is
        // aligned for these DWORD-only tables and writable for size bytes.
        let result = unsafe { query(destination, &mut size, 0, family.into(), class, 0) };
        match result {
            ERROR_INSUFFICIENT_BUFFER => {
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
