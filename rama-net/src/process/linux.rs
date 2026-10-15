use super::{ProcessSocket, TransportProtocol};
use ahash::{HashSet, HashSetExt as _};
use std::{
    fs, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
};

pub(super) fn listening_sockets(pid: u32) -> io::Result<Vec<ProcessSocket>> {
    let process = format!("/proc/{pid}");
    let inodes = socket_inodes(&process)?;
    let mut sockets = Vec::new();

    for (table, protocol, ipv6) in [
        ("tcp", TransportProtocol::Tcp, false),
        ("tcp6", TransportProtocol::Tcp, true),
        ("udp", TransportProtocol::Udp, false),
        ("udp6", TransportProtocol::Udp, true),
    ] {
        let contents = match fs::read_to_string(format!("{process}/net/{table}")) {
            Ok(contents) => contents,
            // IPv6 tables need not exist when IPv6 is disabled in the kernel.
            Err(error) if ipv6 && error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };

        read_table(&contents, protocol, ipv6, &inodes, &mut sockets)?;
    }

    Ok(sockets)
}

fn socket_inodes(process: &str) -> io::Result<HashSet<u64>> {
    let mut inodes = HashSet::new();

    for fd in fs::read_dir(format!("{process}/fd"))? {
        let path = match fs::read_link(fd?.path()) {
            Ok(path) => path,
            // A descriptor can close between listing it and resolving its link.
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };

        if let Some(inode) = socket_inode(&path) {
            inodes.insert(inode);
        }
    }

    Ok(inodes)
}

fn socket_inode(path: &Path) -> Option<u64> {
    path.to_str()?
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn invalid_table() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid process socket table")
}

fn address(value: &str, ipv6: bool) -> io::Result<SocketAddr> {
    let (ip, port) = value.split_once(':').ok_or_else(invalid_table)?;
    let port = u16::from_str_radix(port, 16)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

    let ip = if ipv6 {
        if ip.len() != 32 || !ip.is_ascii() {
            return Err(invalid_table());
        }

        let mut octets = [0; 16];
        for (index, chunk) in octets.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let word = u32::from_str_radix(&ip[index * 8..index * 8 + 8], 16)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            chunk.copy_from_slice(&word.to_ne_bytes());
        }

        IpAddr::V6(Ipv6Addr::from(octets))
    } else {
        if ip.len() != 8 {
            return Err(invalid_table());
        }

        IpAddr::V4(Ipv4Addr::from(
            u32::from_str_radix(ip, 16)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
                .to_ne_bytes(),
        ))
    };

    Ok(SocketAddr::new(ip, port))
}

fn read_table(
    contents: &str,
    protocol: TransportProtocol,
    ipv6: bool,
    inodes: &HashSet<u64>,
    out: &mut Vec<ProcessSocket>,
) -> io::Result<()> {
    for line in contents
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
    {
        let mut fields = line.split_ascii_whitespace();
        let local = fields.nth(1).ok_or_else(invalid_table)?;
        let state = fields.nth(1).ok_or_else(invalid_table)?;
        let inode: u64 = fields
            .nth(5)
            .ok_or_else(invalid_table)?
            .parse()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

        // The namespace tables include other processes; ownership comes from
        // the descriptor inode, not from the /proc/<pid>/net path alone.
        if !inodes.contains(&inode) || (protocol == TransportProtocol::Tcp && state != "0A") {
            continue;
        }

        let local_addr = address(local, ipv6)?;
        if local_addr.port() != 0 {
            out.push(ProcessSocket {
                protocol,
                local_addr,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_rows_require_owned_inode_and_listen_state() {
        let rows = "header\n0: 0100007F:1234 00000000:0000 0A 0:0 0:0 0 0 0 42\n1: 0100007F:1235 00000000:0000 01 0:0 0:0 0 0 0 42\n2: 0100007F:1236 00000000:0000 0A 0:0 0:0 0 0 0 99\n";

        let mut out = Vec::new();
        read_table(
            rows,
            TransportProtocol::Tcp,
            false,
            &HashSet::from_iter([42]),
            &mut out,
        )
        .unwrap();

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].local_addr.port(), 0x1234);
        assert_eq!(socket_inode(Path::new("socket:[42]")), Some(42));
        assert_eq!(socket_inode(Path::new("pipe:[42]")), None);
    }

    #[test]
    fn decodes_native_endian_address_words() {
        let ipv4 = format!("{:08X}:1234", u32::from_ne_bytes([127, 0, 0, 1]));
        assert_eq!(
            address(&ipv4, false).unwrap(),
            "127.0.0.1:4660".parse::<SocketAddr>().unwrap()
        );

        let ipv6 = Ipv6Addr::LOCALHOST
            .octets()
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| format!("{:08X}", u32::from_ne_bytes(*word)))
            .collect::<String>();
        assert_eq!(
            address(&format!("{ipv6}:1234"), true).unwrap(),
            "[::1]:4660".parse::<SocketAddr>().unwrap()
        );

        assert_eq!(
            address("ZZ:1234", false).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            address("é0000000000000000000000000000000:1234", true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn includes_connected_udp_but_excludes_unbound_and_unowned_sockets() {
        let rows = "header\n0: 0100007F:1234 00000000:0000 07 0:0 0:0 0 0 0 42\n1: 0100007F:1235 0100007F:ABCD 01 0:0 0:0 0 0 0 42\n2: 00000000:0000 00000000:0000 07 0:0 0:0 0 0 0 42\n3: 0100007F:1236 00000000:0000 07 0:0 0:0 0 0 0 99\n";
        let mut sockets = Vec::new();

        read_table(
            rows,
            TransportProtocol::Udp,
            false,
            &HashSet::from_iter([42]),
            &mut sockets,
        )
        .unwrap();

        let ports: Vec<_> = sockets
            .iter()
            .map(|socket| socket.local_addr.port())
            .collect();
        assert_eq!(ports, [0x1234, 0x1235]);
    }
}
