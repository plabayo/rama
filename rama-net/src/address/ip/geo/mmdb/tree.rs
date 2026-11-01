//! Search-tree layout, validation and walk, shared by every reader.

use core::net::IpAddr;

use crate::std::boxed::Box;
use crate::std::sync::Arc;
use crate::std::vec;

use super::decoder::Section;
use super::{IpVersion, Metadata, RecordSize};
use crate::address::ip::IntoCanonicalIpAddr;
use crate::address::ip::geo::GeoIpError;

/// Bits resolved by one jump-table entry.
const JUMP_BITS: usize = 16;

/// Entries in one jump table.
const JUMP_ENTRIES: usize = 1 << JUMP_BITS;

/// Bytes of the separator between the search tree and the data section.
const SEPARATOR_LEN: usize = 16;

/// Zero bits walked from the root of an IPv6 tree to reach the IPv4 subtree.
const IPV4_SUBTREE_DEPTH: usize = 96;

/// Search-tree geometry of one database, validated against its source.
#[derive(Debug, Clone)]
pub(crate) struct Tree {
    /// End of the data section: the offset of the metadata marker.
    data_end: usize,
    node_count: usize,
    record_size: RecordSize,
    ip_version: IpVersion,
    node_size: usize,
    tree_size: usize,
    data_section: usize,
    /// Node reached after the leading 96 zero bits of an IPv6 tree; the
    /// starting node for IPv4 lookups there.
    ipv4_start_node: usize,
    jump: Option<Arc<JumpTables>>,
}

/// The node (or terminal record) reached after the first 16 address bits.
#[derive(Debug)]
struct JumpTables {
    /// From the root: IPv4 lookups in an IPv4 tree, IPv6 lookups in an IPv6 tree.
    root: Box<[u32]>,
    /// From the IPv4 start node of an IPv6 tree.
    ipv4: Option<Box<[u32]>>,
}

impl Tree {
    /// Validate the layout of a `size`-byte database whose metadata marker
    /// starts at `marker`, and build the jump tables when `jump_table` is set.
    pub(crate) fn new<S: Section + ?Sized>(
        src: &S,
        size: usize,
        metadata: &Metadata,
        marker: usize,
        jump_table: bool,
    ) -> Result<Self, GeoIpError> {
        // `record_size` and `ip_version` are validated into enums while
        // parsing; the binary-format major version is the remaining gate.
        if metadata.binary_format_major_version != 2 {
            return Err(GeoIpError::Unsupported("only binary format version 2"));
        }
        let node_size = metadata.record_size.node_size();
        let node_count = metadata.node_count as usize;
        let tree_size = node_count
            .checked_mul(node_size)
            .ok_or(GeoIpError::Corrupt("tree size overflow"))?;
        let data_section = tree_size
            .checked_add(SEPARATOR_LEN)
            .ok_or(GeoIpError::Corrupt("data section overflow"))?;
        if data_section > size {
            return Err(GeoIpError::Corrupt("tree extends past end of file"));
        }
        if marker < data_section {
            return Err(GeoIpError::Corrupt("metadata overlaps the search tree"));
        }
        // An empty data section is valid for a database without records:
        // every leaf must land below `marker`, so any data pointer then fails.
        // data pointers are 32-bit
        if u32::try_from(marker - data_section).is_err() {
            return Err(GeoIpError::Corrupt("data section larger than 4 GiB"));
        }
        let mut separator = [0u8; SEPARATOR_LEN];
        src.read_into(tree_size, &mut separator)?;
        if separator != [0u8; SEPARATOR_LEN] {
            return Err(GeoIpError::Corrupt("data section separator is not zeroed"));
        }

        let mut tree = Self {
            data_end: marker,
            node_count,
            record_size: metadata.record_size,
            ip_version: metadata.ip_version,
            node_size,
            tree_size,
            data_section,
            ipv4_start_node: 0,
            jump: None,
        };
        if tree.ip_version == IpVersion::V6 {
            tree.ipv4_start_node = tree.walk_zero_bits(src, IPV4_SUBTREE_DEPTH)?;
            tree.check_terminal(tree.ipv4_start_node)?;
        }
        // The top 16 levels are walked even without a jump table, so every
        // record they end in is checked and acceptance does not depend on
        // the table setting.
        let root = tree.scan_top_levels(src, 0, jump_table)?;
        let ipv4 = match tree.ip_version {
            IpVersion::V6 => tree.scan_top_levels(src, tree.ipv4_start_node, jump_table)?,
            IpVersion::V4 => None,
        };
        if let Some(root) = root {
            tree.jump = Some(Arc::new(JumpTables { root, ipv4 }));
        }
        Ok(tree)
    }

    /// Offset of the data section: record pointers are relative to it.
    pub(crate) fn data_section(&self) -> usize {
        self.data_section
    }

    /// End of the data section; record decoding never reads past it.
    pub(crate) fn data_end(&self) -> usize {
        self.data_end
    }

    /// Whether lookups use the 16-bit jump tables.
    pub(crate) fn has_jump_table(&self) -> bool {
        self.jump.is_some()
    }

    /// Drop the jump tables; lookups then walk from the root.
    pub(crate) fn drop_jump_table(&mut self) {
        self.jump = None;
    }

    /// Locate the data-section offset (into the source) of the record for
    /// `ip`, if any.
    pub(crate) fn find<S: Section + ?Sized>(
        &self,
        src: &S,
        ip: IpAddr,
    ) -> Result<Option<usize>, GeoIpError> {
        let ip = ip.into_canonical_ip_addr();

        // big-endian address bits, left-aligned into a 16-byte buffer
        let mut octets = [0u8; 16];
        let (start_node, nbits, table) = match (self.ip_version, ip) {
            (IpVersion::V4, IpAddr::V4(v4)) => {
                octets[..4].copy_from_slice(&v4.octets());
                (0, 32, self.jump.as_deref().map(|j| &j.root))
            }
            (IpVersion::V6, IpAddr::V6(v6)) => {
                octets.copy_from_slice(&v6.octets());
                (0, 128, self.jump.as_deref().map(|j| &j.root))
            }
            (IpVersion::V6, IpAddr::V4(v4)) => {
                octets[..4].copy_from_slice(&v4.octets());
                (
                    self.ipv4_start_node,
                    32,
                    self.jump.as_deref().and_then(|j| j.ipv4.as_ref()),
                )
            }
            // an IPv6 address cannot be represented in an IPv4-only tree
            (IpVersion::V4, IpAddr::V6(_)) => return Ok(None),
        };

        let prefix = usize::from(u16::from_be_bytes([octets[0], octets[1]]));
        let (mut node, first_bit) = match table.and_then(|t| t.get(prefix)) {
            Some(&entry) => (entry as usize, JUMP_BITS),
            None => (start_node, 0),
        };
        for i in first_bit..nbits {
            if node >= self.node_count {
                break;
            }
            let bit = (octets[i / 8] >> (7 - (i % 8))) & 1;
            node = self.read_record(src, node, bit)?;
        }
        self.resolve_leaf(node)
    }

    /// Map the record reached by a walk to a data offset, `None` for no data.
    fn resolve_leaf(&self, node: usize) -> Result<Option<usize>, GeoIpError> {
        if node <= self.node_count {
            // `node_count` is the explicit "no data" terminator; a smaller
            // value means the bits ran out before a leaf was reached
            return Ok(None);
        }
        // A leaf resolves to offset `tree_size + (value - node_count)`.
        // Values `node_count + 1 ..= node_count + 15` fall inside the 16-byte
        // separator and are not valid data pointers.
        let rel = node - self.node_count;
        if rel < SEPARATOR_LEN {
            return Err(GeoIpError::Corrupt(
                "data pointer inside the 16-byte separator",
            ));
        }
        self.tree_size
            .checked_add(rel)
            .filter(|&offset| offset < self.data_end)
            .map(Some)
            .ok_or(GeoIpError::Corrupt("data pointer out of bounds"))
    }

    /// Follow the left record from the root for `depth` bits.
    fn walk_zero_bits<S: Section + ?Sized>(
        &self,
        src: &S,
        depth: usize,
    ) -> Result<usize, GeoIpError> {
        let mut node = 0usize;
        for _ in 0..depth {
            if node >= self.node_count {
                break;
            }
            node = self.read_record(src, node, 0)?;
        }
        Ok(node)
    }

    /// A terminal record must be the "no data" value or point into the data section.
    fn check_terminal(&self, node: usize) -> Result<(), GeoIpError> {
        if node >= self.node_count {
            self.resolve_leaf(node)?;
        }
        Ok(())
    }

    /// Walk the top 16 levels from `start`, checking every terminal record.
    /// With `table`, also return the jump table: for each of the `2^16`
    /// prefixes the node reached after 16 bits, or the terminal record of a
    /// shorter path.
    fn scan_top_levels<S: Section + ?Sized>(
        &self,
        src: &S,
        start: usize,
        table: bool,
    ) -> Result<Option<Box<[u32]>>, GeoIpError> {
        let mut table = table.then(|| vec![0u32; JUMP_ENTRIES].into_boxed_slice());
        // depth-first over the top 16 levels: at most 2 entries per level
        let mut stack = vec![(start, 0usize, 0usize)];
        while let Some((node, depth, prefix)) = stack.pop() {
            if node >= self.node_count || depth == JUMP_BITS {
                self.check_terminal(node)?;
                if let Some(table) = table.as_deref_mut() {
                    let value = u32::try_from(node)
                        .ok()
                        .ok_or(GeoIpError::Corrupt("record value wider than 32 bits"))?;
                    let span = JUMP_ENTRIES >> depth;
                    let first = prefix * span;
                    table
                        .get_mut(first..first + span)
                        .ok_or(GeoIpError::Corrupt("jump table prefix out of range"))?
                        .fill(value);
                }
                continue;
            }
            let (left, right) = self.read_node(src, node)?;
            stack.push((right, depth + 1, prefix * 2 + 1));
            stack.push((left, depth + 1, prefix * 2));
        }
        Ok(table)
    }

    /// Read one record (left if `bit == 0`, right otherwise) from `node`.
    /// `node` must be `< node_count`.
    fn read_record<S: Section + ?Sized>(
        &self,
        src: &S,
        node: usize,
        bit: u8,
    ) -> Result<usize, GeoIpError> {
        let (left, right) = self.read_node(src, node)?;
        Ok(if bit == 0 { left } else { right })
    }

    /// Read both records of `node`. `node` must be `< node_count`.
    fn read_node<S: Section + ?Sized>(
        &self,
        src: &S,
        node: usize,
    ) -> Result<(usize, usize), GeoIpError> {
        let base = node
            .checked_mul(self.node_size)
            .ok_or(GeoIpError::Corrupt("node offset overflow"))?;
        let mut raw = [0u8; 8];
        let raw = raw
            .get_mut(..self.node_size)
            .ok_or(GeoIpError::Corrupt("node size out of range"))?;
        src.read_into(base, raw)?;
        let b = |i: usize| raw.get(i).copied().map_or(0, usize::from);
        Ok(match self.record_size {
            RecordSize::Bits24 => (
                (b(0) << 16) | (b(1) << 8) | b(2),
                (b(3) << 16) | (b(4) << 8) | b(5),
            ),
            RecordSize::Bits28 => (
                ((b(3) >> 4) << 24) | (b(0) << 16) | (b(1) << 8) | b(2),
                ((b(3) & 0x0f) << 24) | (b(4) << 16) | (b(5) << 8) | b(6),
            ),
            RecordSize::Bits32 => (
                (b(0) << 24) | (b(1) << 16) | (b(2) << 8) | b(3),
                (b(4) << 24) | (b(5) << 16) | (b(6) << 8) | b(7),
            ),
        })
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use ipnet::{IpNet, Ipv4Net, Ipv6Net};
    use rama_core::geo::Country;
    use rama_utils::octets::kib;

    use crate::address::ip::geo::mmdb::{IpVersion, MmdbBuilder, MmdbReader};
    use crate::address::ip::geo::{GeoIpError, GeoLocation};

    fn location(idx: u8) -> GeoLocation {
        GeoLocation {
            country: Some(Country::ALL[idx as usize % Country::ALL.len()].clone()),
            ..Default::default()
        }
    }

    /// Lookups with and without the jump table agree for every probe.
    fn agree(bytes: Vec<u8>, probes: impl IntoIterator<Item = IpAddr>) -> bool {
        let with = MmdbReader::from_bytes(bytes).unwrap();
        assert!(with.has_jump_table());
        let without = with.clone().without_jump_table();
        probes.into_iter().all(|ip| {
            let a = with.try_lookup(ip).map(|r| r.map(|v| v.to_owned()));
            let b = without.try_lookup(ip).map(|r| r.map(|v| v.to_owned()));
            match (a, b) {
                (Ok(a), Ok(b)) => a == b,
                (Err(GeoIpError::Corrupt(a)), Err(GeoIpError::Corrupt(b))) => a == b,
                _ => false,
            }
        })
    }

    /// Probes near every inserted network plus the given random ones.
    fn v4_probes(nets: &[(u32, u8)], extra: Vec<u32>) -> Vec<IpAddr> {
        nets.iter()
            .flat_map(|&(addr, _)| [addr, addr ^ 1, addr.wrapping_add(1 << 16), !addr])
            .chain(extra)
            .map(|bits| IpAddr::V4(Ipv4Addr::from(bits)))
            .collect()
    }

    #[quickcheck_macros::quickcheck]
    #[cfg_attr(miri, ignore = "quickcheck is too slow under miri")]
    fn prop_jump_table_v4(nets: Vec<(u32, u8, u8)>, extra: Vec<u32>) -> bool {
        let mut b = MmdbBuilder::new(IpVersion::V4, "T");
        let mut inserted = Vec::new();
        for (addr, prefix, country) in nets {
            // prefixes 1..=32, so many networks end above depth 16
            let prefix = prefix % 32 + 1;
            let net = Ipv4Net::new(Ipv4Addr::from(addr), prefix).unwrap().trunc();
            if b.insert(IpNet::V4(net), &location(country)).is_ok() {
                inserted.push((addr, prefix));
            }
        }
        agree(b.build().unwrap(), v4_probes(&inserted, extra))
    }

    #[quickcheck_macros::quickcheck]
    #[cfg_attr(miri, ignore = "quickcheck is too slow under miri")]
    fn prop_jump_table_v6(
        nets: Vec<(u32, u8, u8)>,
        v6: Vec<(u128, u8, u8)>,
        extra: Vec<u32>,
    ) -> bool {
        let mut b = MmdbBuilder::new(IpVersion::V6, "T");
        let mut inserted = Vec::new();
        for (addr, prefix, country) in nets {
            let prefix = prefix % 32 + 1;
            let net = Ipv4Net::new(Ipv4Addr::from(addr), prefix).unwrap().trunc();
            if b.insert(IpNet::V4(net), &location(country)).is_ok() {
                inserted.push((addr, prefix));
            }
        }
        let mut probes = v4_probes(&inserted, extra);
        for (addr, prefix, country) in v6 {
            let prefix = prefix % 128 + 1;
            let net = Ipv6Net::new(Ipv6Addr::from(addr), prefix).unwrap().trunc();
            if b.insert(IpNet::V6(net), &location(country)).is_ok() {
                probes.push(IpAddr::V6(Ipv6Addr::from(addr)));
                probes.push(IpAddr::V6(Ipv6Addr::from(addr ^ 1)));
            }
        }
        agree(b.build().unwrap(), probes)
    }

    #[test]
    fn v4_subtree_that_ends_early() {
        // `::/96` itself is a data record: every IPv4 lookup ends at the
        // IPv4 start node, so its jump table is filled with that record
        let mut b = MmdbBuilder::new(IpVersion::V6, "T");
        b.insert("::/96".parse().unwrap(), &location(1)).unwrap();
        b.insert("2001:db8::/32".parse().unwrap(), &location(2))
            .unwrap();
        let bytes = b.build().unwrap();
        let probes = [
            "1.2.3.4",
            "255.255.255.255",
            "0.0.0.0",
            "2001:db8::1",
            "::1",
        ]
        .map(|ip| ip.parse().unwrap());
        assert!(agree(bytes.clone(), probes));
        let reader = MmdbReader::from_bytes(bytes).unwrap();
        assert_eq!(
            reader
                .lookup("8.8.8.8".parse().unwrap())
                .unwrap()
                .to_owned(),
            location(1)
        );

        // a shorter v6 network that covers the whole IPv4 subtree
        let mut b = MmdbBuilder::new(IpVersion::V6, "T");
        b.insert("::/64".parse().unwrap(), &location(3)).unwrap();
        assert!(agree(b.build().unwrap(), probes));
    }

    #[test]
    fn networks_shorter_than_jump_depth() {
        let mut b = MmdbBuilder::new(IpVersion::V4, "T");
        b.insert("10.0.0.0/8".parse().unwrap(), &location(1))
            .unwrap();
        b.insert("128.0.0.0/1".parse().unwrap(), &location(2))
            .unwrap();
        b.insert("11.22.33.0/24".parse().unwrap(), &location(3))
            .unwrap();
        let bytes = b.build().unwrap();
        let probes = [
            "10.1.2.3",
            "10.255.0.1",
            "200.1.1.1",
            "128.0.0.0",
            "11.22.33.44",
            "11.22.34.1",
            "9.9.9.9",
        ]
        .map(|ip| ip.parse().unwrap());
        assert!(agree(bytes.clone(), probes));
        let reader = MmdbReader::from_bytes(bytes).unwrap();
        assert_eq!(
            reader
                .lookup("10.200.0.1".parse().unwrap())
                .unwrap()
                .to_owned(),
            location(1)
        );
        assert!(reader.lookup("9.9.9.9".parse().unwrap()).is_none());
    }

    #[test]
    fn rejects_non_zero_separator() {
        let mut b = MmdbBuilder::new(IpVersion::V4, "T");
        b.insert("1.2.3.0/24".parse().unwrap(), &location(1))
            .unwrap();
        let mut bytes = b.build().unwrap();
        let reader = MmdbReader::from_bytes(bytes.clone()).unwrap();
        let tree_size = reader.metadata().node_count as usize * 8;
        bytes[tree_size + 3] = 1;
        assert!(matches!(
            MmdbReader::from_bytes(bytes),
            Err(GeoIpError::Corrupt(_))
        ));
    }

    #[test]
    fn rejects_metadata_beyond_the_last_128_kib() {
        let mut b = MmdbBuilder::new(IpVersion::V4, "T");
        b.insert("1.2.3.0/24".parse().unwrap(), &location(1))
            .unwrap();
        let mut bytes = b.build().unwrap();
        bytes.extend(core::iter::repeat_n(0u8, kib(128)));
        assert!(matches!(
            MmdbReader::from_bytes(bytes),
            Err(GeoIpError::MissingMetadataMarker)
        ));
    }

    #[test]
    fn recordless_database_opens_with_empty_data_section() {
        let bytes = MmdbBuilder::new(IpVersion::V6, "T").build().unwrap();
        let reader = MmdbReader::from_bytes(bytes.clone()).unwrap();
        let data_section = reader.metadata().node_count as usize * 8 + 16;
        // the data section is empty: the marker follows the separator
        assert_eq!(&bytes[data_section..data_section + 3], b"\xab\xcd\xef");
        for ip in ["1.2.3.4", "::", "2001:db8::1", "255.255.255.255"] {
            assert!(reader.try_lookup(ip.parse().unwrap()).unwrap().is_none());
        }
    }

    #[test]
    fn pointer_into_empty_data_section_is_rejected() {
        let mut bytes = MmdbBuilder::new(IpVersion::V4, "T").build().unwrap();
        let node_count = MmdbReader::from_bytes(bytes.clone())
            .unwrap()
            .metadata()
            .node_count;
        // the smallest data pointer, at the start of the (empty) data section
        bytes[4..8].copy_from_slice(&(node_count + 16).to_be_bytes());
        assert!(matches!(
            MmdbReader::from_bytes(bytes),
            Err(GeoIpError::Corrupt("data pointer out of bounds"))
        ));
    }
}
