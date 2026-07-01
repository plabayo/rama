//! MaxMind DB (`.mmdb`) reader and minimal writer.
//!
//! See [`MmdbReader`] for querying an existing database and [`MmdbBuilder`]
//! for constructing one (used to synthesise test fixtures).

use core::net::IpAddr;

use crate::std::boxed::Box;
use crate::std::vec::Vec;

#[cfg(feature = "std")]
use std::path::Path;

use super::GeoIpError;
use super::location::GeoLocationRef;
use crate::address::ip::IntoCanonicalIpAddr;

use rama_core::bytes::Bytes;
use rama_core::geo::Locale;

pub(crate) mod decoder;
use decoder::Decoder;

#[cfg(feature = "std")]
mod writer;
#[cfg(feature = "std")]
pub(crate) use writer::MmdbValue;
#[cfg(feature = "std")]
pub use writer::{MmdbBuilder, MmdbWriteError};

/// The marker that separates the data section from the metadata section.
const METADATA_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";

/// The number of bits in each search-tree record. The format only defines
/// 24, 28 and 32; a node always holds two records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordSize {
    /// 24-bit records (6-byte nodes).
    Bits24,
    /// 28-bit records (7-byte nodes), with the high nibbles packed together.
    Bits28,
    /// 32-bit records (8-byte nodes).
    Bits32,
}

impl RecordSize {
    fn from_bits(bits: u16) -> Result<Self, GeoIpError> {
        match bits {
            24 => Ok(Self::Bits24),
            28 => Ok(Self::Bits28),
            32 => Ok(Self::Bits32),
            _ => Err(GeoIpError::Unsupported("record size must be 24, 28 or 32")),
        }
    }

    /// The number of bits per record.
    #[must_use]
    pub fn bits(self) -> u16 {
        match self {
            Self::Bits24 => 24,
            Self::Bits28 => 28,
            Self::Bits32 => 32,
        }
    }

    /// The number of bytes per node (two records).
    fn node_size(self) -> usize {
        (self.bits() as usize * 2) / 8
    }
}

/// The IP version of the addresses a database indexes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    /// IPv4 only.
    V4,
    /// IPv6 (which can also hold IPv4 data in the `::/96` range).
    V6,
}

impl IpVersion {
    fn from_number(version: u16) -> Result<Self, GeoIpError> {
        match version {
            4 => Ok(Self::V4),
            6 => Ok(Self::V6),
            _ => Err(GeoIpError::Unsupported("ip version must be 4 or 6")),
        }
    }

    /// The numeric IP version (`4` or `6`).
    #[must_use]
    pub fn number(self) -> u16 {
        match self {
            Self::V4 => 4,
            Self::V6 => 6,
        }
    }
}

/// Parsed metadata describing a MaxMind DB.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Metadata {
    /// Number of nodes in the binary search tree.
    pub node_count: u32,
    /// Number of bits per record in the search tree.
    pub record_size: RecordSize,
    /// IP version of the data in the tree.
    pub ip_version: IpVersion,
    /// Free-form string describing the record structure (e.g.
    /// `"GeoLite2-City"`).
    pub database_type: Box<str>,
    /// Locales for which localised data may be present.
    pub languages: Vec<Locale>,
    /// Major version of the binary format (always 2 for this reader).
    pub binary_format_major_version: u16,
    /// Minor version of the binary format.
    pub binary_format_minor_version: u16,
    /// Database build time, as a Unix epoch (seconds).
    pub build_epoch: u64,
}

/// A zero-copy reader over a MaxMind DB.
///
/// The database buffer is shared, so cloning a reader is cheap and a single
/// database can be queried concurrently from many tasks without locks. The
/// bytes are either held in memory ([`Self::from_bytes`] / [`Self::open`]) or,
/// with the `mmap` feature, memory-mapped from disk via `open_mmap`.
#[derive(Debug, Clone)]
pub struct MmdbReader {
    buf: Bytes,
    metadata: Metadata,
    node_size: usize,
    tree_size: usize,
    data_section: usize,
    /// Node reached after traversing the leading 96 zero bits, used as the
    /// starting node when looking up an IPv4 address in an IPv6 tree.
    ipv4_start_node: usize,
    lang: Box<str>,
}

impl MmdbReader {
    /// Build a reader from raw database bytes already held in memory.
    ///
    /// # Errors
    ///
    /// Returns [`GeoIpError`] if the bytes are not a valid MaxMind DB or use
    /// an unsupported record size / format version.
    pub fn from_bytes(bytes: impl Into<Bytes>) -> Result<Self, GeoIpError> {
        Self::from_buf(bytes.into())
    }

    fn from_buf(buf: Bytes) -> Result<Self, GeoIpError> {
        let metadata = parse_metadata(buf.as_ref())?;

        // `record_size` and `ip_version` are validated into enums while
        // parsing, so they can no longer hold impossible values here. The
        // binary-format major version is the remaining compatibility gate.
        if metadata.binary_format_major_version != 2 {
            return Err(GeoIpError::Unsupported("only binary format version 2"));
        }

        let node_size = metadata.record_size.node_size();
        let node_count = metadata.node_count as usize;
        let tree_size = node_count
            .checked_mul(node_size)
            .ok_or(GeoIpError::Corrupt("tree size overflow"))?;
        let data_section = tree_size
            .checked_add(16)
            .ok_or(GeoIpError::Corrupt("data section overflow"))?;
        if data_section > buf.len() {
            return Err(GeoIpError::Corrupt("tree extends past end of file"));
        }

        let mut reader = Self {
            buf,
            metadata,
            node_size,
            tree_size,
            data_section,
            ipv4_start_node: 0,
            lang: Box::from("en"),
        };
        reader.ipv4_start_node = reader.compute_ipv4_start_node()?;
        Ok(reader)
    }

    /// Read a MaxMind DB from disk into memory.
    ///
    /// The whole file is read into a shared buffer. With the `mmap` feature,
    /// `open_mmap` maps the file instead for a smaller resident set on very
    /// large databases.
    ///
    /// # Errors
    ///
    /// Returns [`GeoIpError::Io`] if the file cannot be read, or another
    /// [`GeoIpError`] if it is not a valid database.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn open(path: impl AsRef<Path>) -> Result<Self, GeoIpError> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(bytes)
    }

    /// Memory-map a MaxMind DB from disk instead of reading it into memory.
    ///
    /// Lookups fault in only the pages they touch, so a large database costs
    /// little resident memory. The mapping is held for the reader's lifetime.
    ///
    /// The file must not be modified or truncated while the reader is alive, or
    /// lookups may observe garbage (or fault on some platforms).
    ///
    /// # Errors
    ///
    /// Returns [`GeoIpError::Io`] if the file cannot be opened or mapped, or
    /// another [`GeoIpError`] if it is not a valid database.
    #[cfg(all(feature = "std", feature = "mmap"))]
    #[cfg_attr(docsrs, doc(cfg(all(feature = "std", feature = "mmap"))))]
    pub fn open_mmap(path: impl AsRef<Path>) -> Result<Self, GeoIpError> {
        let file = std::fs::File::open(path)?;
        // SAFETY: the file is opened read-only; the caller is responsible (per
        // the doc above) for not mutating it while the reader is alive.
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        Self::from_buf(Bytes::from_owner(mmap))
    }

    /// Set the preferred language code used to resolve localised names
    /// (default `"en"`). This is the lookup key into the database's localised
    /// `names` maps (e.g. `"en"`, `"de"`, `"pt-BR"`).
    #[must_use]
    pub fn with_language(mut self, lang: impl Into<Box<str>>) -> Self {
        self.lang = lang.into();
        self
    }

    /// The parsed [`Metadata`] of this database.
    #[must_use]
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Look up `ip`, returning a zero-copy view of its record if present.
    ///
    /// IPv4-mapped IPv6 inputs are canonicalised to IPv4 first. Looking up an
    /// IPv4 address in an IPv6 database traverses the `::/96` range.
    ///
    /// This is best-effort: a structurally corrupt database encountered mid
    /// lookup yields `None`, indistinguishable from a legitimate miss. Use
    /// [`Self::try_lookup`] when you need to observe corruption.
    #[must_use]
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoLocationRef<'_>> {
        self.try_lookup(ip).ok().flatten()
    }

    /// Like [`Self::lookup`], but reports database corruption encountered
    /// during traversal as a [`GeoIpError`] instead of collapsing it to `None`.
    ///
    /// # Errors
    ///
    /// Returns [`GeoIpError::Corrupt`] if the search tree is structurally
    /// invalid for `ip`.
    pub fn try_lookup(&self, ip: IpAddr) -> Result<Option<GeoLocationRef<'_>>, GeoIpError> {
        match self.find(ip)? {
            Some(record_offset) => {
                let decoder = Decoder::new(self.buf.as_ref(), self.data_section);
                Ok(Some(GeoLocationRef::new(
                    decoder,
                    record_offset,
                    &self.lang,
                )))
            }
            None => Ok(None),
        }
    }

    /// Locate the data-section file offset for `ip`, if any.
    fn find(&self, ip: IpAddr) -> Result<Option<usize>, GeoIpError> {
        let ip = ip.into_canonical_ip_addr();
        let node_count = self.metadata.node_count as usize;

        // big-endian address bits, left-aligned into a 16-byte buffer
        let mut octets = [0u8; 16];
        let (start_node, nbits): (usize, usize) = match (self.metadata.ip_version, ip) {
            (IpVersion::V4, IpAddr::V4(v4)) => {
                octets[..4].copy_from_slice(&v4.octets());
                (0, 32)
            }
            (IpVersion::V6, IpAddr::V6(v6)) => {
                octets.copy_from_slice(&v6.octets());
                (0, 128)
            }
            (IpVersion::V6, IpAddr::V4(v4)) => {
                octets[..4].copy_from_slice(&v4.octets());
                (self.ipv4_start_node, 32)
            }
            // an IPv6 address cannot be represented in an IPv4-only tree
            (IpVersion::V4, IpAddr::V6(_)) => return Ok(None),
        };

        let mut node = start_node;
        for i in 0..nbits {
            if node >= node_count {
                break;
            }
            let bit = (octets[i / 8] >> (7 - (i % 8))) & 1;
            node = self.read_record(node, bit)?;
        }

        if node == node_count {
            // explicit "no data" terminator
            Ok(None)
        } else if node > node_count {
            // A leaf resolves to file offset `tree_size + (value - node_count)`.
            // Values `node_count + 1 ..= node_count + 15` fall inside the
            // 16-byte data-section separator and are not valid data pointers;
            // reject those (and any offset past the buffer) as corrupt rather
            // than handing the decoder a bogus position.
            let rel = node - node_count;
            if rel < 16 {
                return Err(GeoIpError::Corrupt(
                    "data pointer inside the 16-byte separator",
                ));
            }
            let offset = self
                .tree_size
                .checked_add(rel)
                .filter(|&o| o < self.buf.len())
                .ok_or(GeoIpError::Corrupt("data pointer out of bounds"))?;
            Ok(Some(offset))
        } else {
            // ran out of bits without reaching a leaf
            Ok(None)
        }
    }

    /// Walk the leading 96 zero bits from the root to find the IPv4 start node
    /// in an IPv6 tree. Returns 0 for IPv4 trees.
    fn compute_ipv4_start_node(&self) -> Result<usize, GeoIpError> {
        if self.metadata.ip_version != IpVersion::V6 {
            return Ok(0);
        }
        let node_count = self.metadata.node_count as usize;
        let mut node = 0usize;
        for _ in 0..96 {
            if node >= node_count {
                break;
            }
            node = self.read_record(node, 0)?;
        }
        Ok(node)
    }

    /// Read one record (left if `bit == 0`, right otherwise) from `node`.
    /// `node` must be `< node_count`.
    fn read_record(&self, node: usize, bit: u8) -> Result<usize, GeoIpError> {
        let base = node
            .checked_mul(self.node_size)
            .ok_or(GeoIpError::Corrupt("node offset overflow"))?;
        let b = |i: usize| -> Result<usize, GeoIpError> {
            self.buf
                .get(base + i)
                .copied()
                .map(usize::from)
                .ok_or(GeoIpError::Corrupt("record out of bounds"))
        };
        let value = match self.metadata.record_size {
            RecordSize::Bits24 => {
                let o = if bit == 0 { 0 } else { 3 };
                (b(o)? << 16) | (b(o + 1)? << 8) | b(o + 2)?
            }
            RecordSize::Bits28 => {
                if bit == 0 {
                    ((b(3)? >> 4) << 24) | (b(0)? << 16) | (b(1)? << 8) | b(2)?
                } else {
                    ((b(3)? & 0x0f) << 24) | (b(4)? << 16) | (b(5)? << 8) | b(6)?
                }
            }
            RecordSize::Bits32 => {
                let o = if bit == 0 { 0 } else { 4 };
                (b(o)? << 24) | (b(o + 1)? << 16) | (b(o + 2)? << 8) | b(o + 3)?
            }
        };
        Ok(value)
    }
}

/// Locate and parse the metadata section of a database buffer.
fn parse_metadata(buf: &[u8]) -> Result<Metadata, GeoIpError> {
    let marker_pos = buf
        .windows(METADATA_MARKER.len())
        .rposition(|w| w == METADATA_MARKER)
        .ok_or(GeoIpError::MissingMetadataMarker)?;
    let meta_start = marker_pos + METADATA_MARKER.len();

    let dec = Decoder::new(buf, meta_start);
    let get = |key: &str| -> Result<usize, GeoIpError> {
        dec.map_get(meta_start, key)?
            .ok_or(GeoIpError::Corrupt("missing required metadata key"))
    };

    let node_count = dec.read_u32(get("node_count")?)?;
    let record_size = RecordSize::from_bits(dec.read_u16(get("record_size")?)?)?;
    let ip_version = IpVersion::from_number(dec.read_u16(get("ip_version")?)?)?;
    let database_type: Box<str> = dec.read_str(get("database_type")?)?.into();
    let binary_format_major_version = dec.read_u16(get("binary_format_major_version")?)?;
    let binary_format_minor_version = dec.read_u16(get("binary_format_minor_version")?)?;
    let build_epoch = dec.read_u64(get("build_epoch")?)?;

    let languages = match dec.map_get(meta_start, "languages")? {
        Some(off) => dec
            .array_offsets(off)?
            .into_iter()
            .map(|o| dec.read_str(o).map(Locale::parse))
            .collect::<Result<Vec<_>, _>>()?,
        None => Vec::new(),
    };

    Ok(Metadata {
        node_count,
        record_size,
        ip_version,
        database_type,
        languages,
        binary_format_major_version,
        binary_format_minor_version,
        build_epoch,
    })
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use core::net::{IpAddr, Ipv4Addr};

    use super::*;
    #[cfg(feature = "std")]
    use crate::address::ip::geo::{AsOrg, Coordinates, GeoLocation, Subdivision};
    #[cfg(feature = "std")]
    use crate::asn::LossyAsn;

    #[cfg(feature = "std")]
    use rama_core::geo::{Continent, Country, Locale};

    #[cfg(feature = "std")]
    use ipnet::{IpNet, Ipv4Net};

    #[cfg(feature = "std")]
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[cfg(feature = "std")]
    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[cfg(feature = "std")]
    fn city_record() -> GeoLocation {
        GeoLocation {
            continent: Some(Continent::NorthAmerica),
            country: Some(Country::UnitedStates),
            subdivisions: vec![Subdivision {
                iso_code: Some("NY".into()),
                name: Some("New York".into()),
            }],
            city: Some("Buffalo".into()),
            postal_code: Some("14202".into()),
            location: Some(Coordinates {
                latitude: 42.886_4,
                longitude: -78.878_4,
                accuracy_radius_km: Some(50),
                time_zone: Some("America/New_York".into()),
            }),
            ..Default::default()
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn city_lookup_ipv4_roundtrip() {
        let mut b = MmdbBuilder::new(IpVersion::V4, "GeoLite2-City").with_languages(["en", "de"]);
        b.insert(net("1.2.3.0/24"), &city_record()).unwrap();
        let reader = MmdbReader::from_bytes(b.build().unwrap()).unwrap();

        assert_eq!(reader.metadata().ip_version, IpVersion::V4);
        assert_eq!(reader.metadata().database_type.as_ref(), "GeoLite2-City");
        assert_eq!(
            reader.metadata().languages,
            vec![Locale::parse("en"), Locale::parse("de")]
        );

        let loc = reader.lookup(ip("1.2.3.4")).expect("address in range");
        assert_eq!(loc.continent().unwrap().code(), "NA");
        assert_eq!(loc.continent().unwrap().name(), Some("North America"));
        assert_eq!(loc.country().unwrap().code(), "US");
        assert_eq!(loc.country().unwrap().name(), Some("United States"));
        assert!(!loc.country().unwrap().to_owned().is_in_eu());
        assert_eq!(loc.city(), Some("Buffalo"));
        assert_eq!(loc.postal_code(), Some("14202"));
        assert_eq!(loc.latitude(), Some(42.886_4));
        assert_eq!(loc.longitude(), Some(-78.878_4));
        assert_eq!(loc.accuracy_radius_km(), Some(50));
        assert_eq!(loc.time_zone(), Some("America/New_York"));

        // addresses outside the inserted network have no data
        assert!(reader.lookup(ip("9.9.9.9")).is_none());
    }

    #[cfg(feature = "std")]
    #[test]
    fn language_fallback_and_selection() {
        // localised names (city, subdivision) honour the preferred language;
        // country/continent are identity enums and are language-independent.
        // Built via the internal raw API: multi-language names have no typed
        // GeoLocation representation (which carries a single resolved name).
        let mut b = MmdbBuilder::new(IpVersion::V4, "GeoLite2-City").with_languages(["en", "de"]);
        let rec = MmdbValue::map([(
            "city",
            MmdbValue::map([(
                "names",
                MmdbValue::map([
                    ("en", MmdbValue::string("Cologne")),
                    ("de", MmdbValue::string("Köln")),
                ]),
            )]),
        )]);
        b.insert_value(net("1.2.3.0/24"), rec).unwrap();
        let bytes = b.build().unwrap();

        let de = MmdbReader::from_bytes(bytes.clone())
            .unwrap()
            .with_language("de");
        assert_eq!(de.lookup(ip("1.2.3.4")).unwrap().city(), Some("Köln"));

        // a language with no entry falls back to English
        let fr = MmdbReader::from_bytes(bytes).unwrap().with_language("fr");
        assert_eq!(fr.lookup(ip("1.2.3.4")).unwrap().city(), Some("Cologne"));
    }

    #[cfg(feature = "std")]
    #[test]
    fn to_owned_and_serialize() {
        let mut b = MmdbBuilder::new(IpVersion::V4, "GeoLite2-City").with_languages(["en"]);
        b.insert(net("1.2.3.0/24"), &city_record()).unwrap();
        let reader = MmdbReader::from_bytes(b.build().unwrap()).unwrap();
        let owned = reader.lookup(ip("1.2.3.4")).unwrap().to_owned();

        assert_eq!(owned.country, Some(Country::UnitedStates));
        assert_eq!(owned.continent.as_ref().unwrap().code(), "NA");
        assert_eq!(owned.city.as_deref(), Some("Buffalo"));
        assert_eq!(owned.subdivisions.len(), 1);
        assert_eq!(owned.subdivisions[0].iso_code.as_deref(), Some("NY"));
        let coords = owned.location.as_ref().unwrap();
        assert_eq!(coords.accuracy_radius_km, Some(50));
        assert_eq!(
            coords.time_zone.as_ref().unwrap().as_str(),
            "America/New_York"
        );

        let json = serde_json::to_value(&owned).unwrap();
        // Country serialises as its alpha-2 code
        assert_eq!(json["country"], "US");
        assert_eq!(json["city"], "Buffalo");
        // empty / absent fields are skipped
        assert!(json.get("autonomous_system").is_none());
    }

    #[cfg(feature = "std")]
    #[test]
    fn ipv4_in_ipv6_tree() {
        let mut b = MmdbBuilder::new(IpVersion::V6, "GeoLite2-Country");
        let be = GeoLocation {
            country: Some(Country::Belgium),
            ..Default::default()
        };
        let de = GeoLocation {
            country: Some(Country::Germany),
            ..Default::default()
        };
        b.insert(net("9.9.9.0/24"), &be).unwrap();
        b.insert(net("2001:db8::/32"), &de).unwrap();
        let reader = MmdbReader::from_bytes(b.build().unwrap()).unwrap();

        let code = |r: &MmdbReader, addr: &str| {
            r.lookup(ip(addr))
                .unwrap()
                .country()
                .unwrap()
                .code()
                .to_owned()
        };
        assert_eq!(code(&reader, "9.9.9.9"), "BE");
        assert_eq!(code(&reader, "2001:db8::1"), "DE");
        // IPv4-mapped IPv6 canonicalises to IPv4 and resolves via ::/96
        assert_eq!(code(&reader, "::ffff:9.9.9.9"), "BE");
        assert!(reader.lookup(ip("8.8.8.8")).is_none());
    }

    #[cfg(feature = "std")]
    #[test]
    fn asn_database() {
        let mut b = MmdbBuilder::new(IpVersion::V4, "GeoLite2-ASN");
        let rec = GeoLocation {
            autonomous_system: Some(AsOrg {
                asn: Some(LossyAsn::from(15169)),
                organization: Some("Google LLC".into()),
            }),
            ..Default::default()
        };
        b.insert(net("8.8.8.0/24"), &rec).unwrap();
        let reader = MmdbReader::from_bytes(b.build().unwrap()).unwrap();

        let loc = reader.lookup(ip("8.8.8.8")).unwrap();
        assert_eq!(loc.asn().map(|a| a.as_u32()), Some(15169));
        assert!(loc.asn().unwrap().is_valid());
        assert_eq!(loc.as_organization(), Some("Google LLC"));
        let owned = loc.to_owned();
        assert_eq!(
            owned
                .autonomous_system
                .as_ref()
                .unwrap()
                .asn
                .unwrap()
                .as_u32(),
            15169
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn out_of_range_asn_keeps_organization() {
        let mut b = MmdbBuilder::new(IpVersion::V4, "GeoLite2-ASN");
        // 23456 (AS_TRANS) is outside rama's assignable-ASN ranges yet appears
        // in real ASN data — the owned conversion must not drop the record.
        let rec = GeoLocation {
            autonomous_system: Some(AsOrg {
                asn: Some(LossyAsn::from(23456)),
                organization: Some("Placeholder AS".into()),
            }),
            ..Default::default()
        };
        b.insert(net("203.0.113.0/24"), &rec).unwrap();
        let reader = MmdbReader::from_bytes(b.build().unwrap()).unwrap();
        let loc = reader.lookup(ip("203.0.113.5")).unwrap();
        // the raw zero-copy view preserves the number verbatim
        let viewed = loc.asn().unwrap();
        assert_eq!(viewed.as_u32(), 23456);
        assert!(!viewed.is_valid());
        // owned form keeps the AS record AND the exact number (no lossy fold)
        let owned = loc.to_owned();
        let asys = owned
            .autonomous_system
            .as_ref()
            .expect("AS record retained");
        assert_eq!(asys.asn.unwrap().as_u32(), 23456);
        assert!(!asys.asn.unwrap().is_valid());
        assert_eq!(asys.organization.as_deref(), Some("Placeholder AS"));
    }

    #[cfg(feature = "std")]
    #[test]
    fn owned_serde_roundtrip() {
        let mut b = MmdbBuilder::new(IpVersion::V4, "GeoLite2-City").with_languages(["en"]);
        b.insert(net("1.2.3.0/24"), &city_record()).unwrap();
        let reader = MmdbReader::from_bytes(b.build().unwrap()).unwrap();
        let owned = reader.lookup(ip("1.2.3.4")).unwrap().to_owned();

        let json = serde_json::to_string(&owned).unwrap();
        let back: GeoLocation = serde_json::from_str(&json).unwrap();
        assert_eq!(owned, back);
    }

    #[cfg(feature = "std")]
    #[test]
    fn identical_records_are_deduplicated() {
        let rec = GeoLocation {
            country: Some(Country::UnitedStates),
            ..Default::default()
        };
        let other = GeoLocation {
            country: Some(Country::Germany),
            ..Default::default()
        };

        // same value at two networks -> one shared data copy
        let mut same = MmdbBuilder::new(IpVersion::V4, "T");
        same.insert(net("1.0.0.0/24"), &rec).unwrap();
        same.insert(net("2.0.0.0/24"), &rec).unwrap();

        // distinct (same-length) values at the same two networks -> two copies
        let mut diff = MmdbBuilder::new(IpVersion::V4, "T");
        diff.insert(net("1.0.0.0/24"), &rec).unwrap();
        diff.insert(net("2.0.0.0/24"), &other).unwrap();

        // the trees are identical, so the smaller image proves the dedup
        assert!(same.build().unwrap().len() < diff.build().unwrap().len());

        // and both networks still resolve to the shared record
        let reader = MmdbReader::from_bytes(same.build().unwrap()).unwrap();
        assert_eq!(
            reader
                .lookup(ip("1.0.0.5"))
                .unwrap()
                .country()
                .unwrap()
                .code(),
            "US"
        );
        assert_eq!(
            reader
                .lookup(ip("2.0.0.5"))
                .unwrap()
                .country()
                .unwrap()
                .code(),
            "US"
        );
    }

    #[cfg(feature = "mmap")]
    #[cfg(feature = "std")]
    #[test]
    fn mmap_open_and_lookup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("country.mmdb");
        let mut b = MmdbBuilder::new(IpVersion::V4, "GeoLite2-Country");
        b.insert(
            net("1.2.3.0/24"),
            &GeoLocation {
                country: Some(Country::Belgium),
                ..Default::default()
            },
        )
        .unwrap();
        b.write_to_file(&path).unwrap();

        let reader = MmdbReader::open_mmap(&path).unwrap();
        assert_eq!(
            reader
                .lookup(ip("1.2.3.4"))
                .unwrap()
                .country()
                .unwrap()
                .code(),
            "BE"
        );
        assert!(reader.lookup(ip("9.9.9.9")).is_none());
    }

    #[test]
    fn malformed_inputs_error_not_panic() {
        assert!(matches!(
            MmdbReader::from_bytes(vec![0u8; 32]),
            Err(GeoIpError::MissingMetadataMarker)
        ));
        MmdbReader::from_bytes(Vec::new()).unwrap_err();
        // marker present but no valid metadata map after it
        let mut junk = b"\xab\xcd\xefMaxMind.com".to_vec();
        junk.push(0xff);
        MmdbReader::from_bytes(junk).unwrap_err();
    }

    /// Property: any IPv4 address inserted as a `/32` with any country resolves
    /// back to that country.
    #[cfg(feature = "std")]
    #[quickcheck_macros::quickcheck]
    fn prop_v4_country_roundtrips(ip_bits: u32, country_idx: u8) -> bool {
        let country = Country::ALL[country_idx as usize % Country::ALL.len()].clone();
        let addr = Ipv4Addr::from(ip_bits);
        let loc = GeoLocation {
            country: Some(country.clone()),
            ..Default::default()
        };
        let mut b = MmdbBuilder::new(IpVersion::V4, "T");
        b.insert(IpNet::V4(Ipv4Net::new(addr, 32).unwrap()), &loc)
            .unwrap();
        let reader = MmdbReader::from_bytes(b.build().unwrap()).unwrap();
        reader
            .lookup(IpAddr::V4(addr))
            .and_then(|r| r.country())
            .map(|c| c.to_owned())
            == Some(country)
    }

    #[cfg(feature = "std")]
    #[test]
    fn every_field_roundtrips() {
        // populate every GeoLocation field, including both subdivision shapes,
        // to guard the From<&GeoLocation> encoder and the reader accessors.
        let loc = GeoLocation {
            continent: Some(Continent::Europe),
            country: Some(Country::Belgium),
            registered_country: Some(Country::Netherlands),
            subdivisions: vec![
                Subdivision {
                    iso_code: Some("VLG".into()),
                    name: Some("Flanders".into()),
                },
                Subdivision {
                    iso_code: None,
                    name: Some("Antwerp".into()),
                },
            ],
            city: Some("Antwerp".into()),
            postal_code: Some("2000".into()),
            location: Some(Coordinates {
                latitude: 51.2194,
                longitude: 4.4025,
                accuracy_radius_km: Some(20),
                time_zone: Some("Europe/Brussels".into()),
            }),
            autonomous_system: Some(AsOrg {
                asn: Some(LossyAsn::from(5432)),
                organization: Some("Proximus".into()),
            }),
        };
        let mut b = MmdbBuilder::new(IpVersion::V4, "GeoLite2-City").with_languages(["en"]);
        b.insert(net("1.2.3.0/24"), &loc).unwrap();
        let reader = MmdbReader::from_bytes(b.build().unwrap()).unwrap();
        assert_eq!(reader.lookup(ip("1.2.3.4")).unwrap().to_owned(), loc);
    }

    #[cfg(feature = "std")]
    #[test]
    fn native_ipv6_lookup() {
        let mut b = MmdbBuilder::new(IpVersion::V6, "GeoLite2-Country");
        let cf = GeoLocation {
            country: Some(Country::UnitedStates),
            ..Default::default()
        };
        let goog = GeoLocation {
            country: Some(Country::Ireland),
            ..Default::default()
        };
        b.insert(net("2606:4700::/32"), &cf).unwrap();
        b.insert(net("2a00:1450::/32"), &goog).unwrap();
        let reader = MmdbReader::from_bytes(b.build().unwrap()).unwrap();

        let code = |addr: &str| {
            reader
                .lookup(ip(addr))
                .and_then(|r| r.country())
                .map(|c| c.code().to_owned())
        };
        assert_eq!(code("2606:4700::1111").as_deref(), Some("US"));
        assert_eq!(code("2a00:1450:4001::1").as_deref(), Some("IE"));
        // outside any inserted v6 network
        assert!(reader.lookup(ip("2001:db8::1")).is_none());
    }

    #[cfg(feature = "std")]
    #[test]
    fn writer_error_paths() {
        let loc = GeoLocation {
            country: Some(Country::Belgium),
            ..Default::default()
        };
        // a zero-length prefix is rejected
        let mut b = MmdbBuilder::new(IpVersion::V4, "T");
        assert!(matches!(
            b.insert(net("0.0.0.0/0"), &loc),
            Err(MmdbWriteError::ZeroPrefix)
        ));
        // an IPv6 network in an IPv4 database is a family mismatch
        assert!(matches!(
            b.insert(net("2001:db8::/32"), &loc),
            Err(MmdbWriteError::FamilyMismatch)
        ));
        // a network nested inside an already-inserted one overlaps
        b.insert(net("1.2.3.0/24"), &loc).unwrap();
        assert!(matches!(
            b.insert(net("1.2.3.0/25"), &loc),
            Err(MmdbWriteError::OverlappingNetwork)
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn writer_overlap_is_symmetric_and_non_destructive() {
        let be = GeoLocation {
            country: Some(Country::Belgium),
            ..Default::default()
        };
        let us = GeoLocation {
            country: Some(Country::UnitedStates),
            ..Default::default()
        };
        // inserting a *less*-specific prefix after a more-specific one must also
        // be rejected (not silently clobber the existing subtree)
        let mut b = MmdbBuilder::new(IpVersion::V4, "T");
        b.insert(net("1.2.3.0/24"), &be).unwrap();
        assert!(matches!(
            b.insert(net("1.2.0.0/16"), &us),
            Err(MmdbWriteError::OverlappingNetwork)
        ));
        // an exact duplicate is an overlap too (no silent last-wins)
        assert!(matches!(
            b.insert(net("1.2.3.0/24"), &us),
            Err(MmdbWriteError::OverlappingNetwork)
        ));
        // the original /24 entry survives the rejected inserts intact
        let reader = MmdbReader::from_bytes(b.build().unwrap()).unwrap();
        let got = reader.lookup("1.2.3.4".parse().unwrap()).unwrap();
        assert_eq!(got.country().unwrap().code(), "BE");
    }

    #[cfg(feature = "std")]
    #[test]
    fn open_missing_file_errors() {
        MmdbReader::open("/no/such/path/geoip-missing.mmdb").unwrap_err();
    }

    #[cfg(feature = "mmap")]
    #[cfg(feature = "std")]
    #[test]
    fn open_mmap_missing_file_errors() {
        MmdbReader::open_mmap("/no/such/path/geoip-missing.mmdb").unwrap_err();
    }

    #[cfg(feature = "std")]
    #[test]
    fn writer_roundtrips_extended_size_header() {
        // a string payload > 65820 bytes exercises the size-31 (3-byte) length
        // header branch in encode_header
        let big_city = "a".repeat(70_000);
        let mut b = MmdbBuilder::new(IpVersion::V4, "GeoLite2-City");
        b.insert(
            net("1.2.3.0/24"),
            &GeoLocation {
                city: Some(big_city.clone().into_boxed_str()),
                ..Default::default()
            },
        )
        .unwrap();
        let reader = MmdbReader::from_bytes(b.build().unwrap()).unwrap();
        let got = reader.lookup("1.2.3.4".parse().unwrap()).unwrap();
        assert_eq!(got.city(), Some(big_city.as_str()));
    }

    #[cfg(feature = "std")]
    #[test]
    fn metadata_roundtrips() {
        let mut b = MmdbBuilder::new(IpVersion::V4, "GeoLite2-City")
            .with_languages(["en", "de", "pt-BR"])
            .with_build_epoch(1_700_000_000);
        b.insert(
            net("1.2.3.0/24"),
            &GeoLocation {
                country: Some(Country::Belgium),
                ..Default::default()
            },
        )
        .unwrap();
        let md = MmdbReader::from_bytes(b.build().unwrap())
            .unwrap()
            .metadata()
            .clone();
        assert_eq!(md.build_epoch, 1_700_000_000);
        assert_eq!(
            md.languages,
            vec![
                Locale::parse("en"),
                Locale::parse("de"),
                Locale::parse("pt-BR")
            ]
        );
    }
}
