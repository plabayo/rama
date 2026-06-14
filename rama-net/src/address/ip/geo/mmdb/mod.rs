//! MaxMind DB (`.mmdb`) reader and minimal writer.
//!
//! See [`MmdbReader`] for querying an existing database and [`MmdbBuilder`]
//! for constructing one (used to synthesise test fixtures).

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use rama_core::geo::Locale;

use crate::address::ip::IntoCanonicalIpAddr;

use super::GeoIpError;
use super::location::GeoLocationRef;

pub(crate) mod decoder;
use decoder::Decoder;

mod writer;
pub use writer::{MmdbBuilder, MmdbValue, MmdbWriteError};

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

/// A zero-copy reader over a MaxMind DB held entirely in memory.
///
/// The database buffer is shared (`Arc`), so cloning a reader is cheap and a
/// single database can be queried concurrently from many tasks without locks.
#[derive(Debug, Clone)]
pub struct MmdbReader {
    buf: Arc<[u8]>,
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
    pub fn from_bytes(bytes: impl Into<Arc<[u8]>>) -> Result<Self, GeoIpError> {
        let buf: Arc<[u8]> = bytes.into();
        let metadata = parse_metadata(&buf)?;

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
    /// The whole file is read into a shared buffer. For very large databases
    /// on memory-constrained hosts a memory-mapped variant may be added later
    /// behind an opt-in feature.
    ///
    /// # Errors
    ///
    /// Returns [`GeoIpError::Io`] if the file cannot be read, or another
    /// [`GeoIpError`] if it is not a valid database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, GeoIpError> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(bytes)
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
            // data pointer: file offset = tree_size + (value - node_count)
            let offset = self
                .tree_size
                .checked_add(node - node_count)
                .ok_or(GeoIpError::Corrupt("data offset overflow"))?;
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
    use super::*;
    use rama_core::geo::{Country, Locale};
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn city_record() -> MmdbValue {
        MmdbValue::map([
            (
                "continent",
                MmdbValue::map([
                    ("code", MmdbValue::string("NA")),
                    (
                        "names",
                        MmdbValue::map([("en", MmdbValue::string("North America"))]),
                    ),
                ]),
            ),
            (
                "country",
                MmdbValue::map([
                    ("iso_code", MmdbValue::string("US")),
                    ("is_in_european_union", MmdbValue::Bool(false)),
                    (
                        "names",
                        MmdbValue::map([
                            ("en", MmdbValue::string("United States")),
                            ("de", MmdbValue::string("Vereinigte Staaten")),
                        ]),
                    ),
                ]),
            ),
            (
                "subdivisions",
                MmdbValue::Array(vec![MmdbValue::map([
                    ("iso_code", MmdbValue::string("NY")),
                    (
                        "names",
                        MmdbValue::map([("en", MmdbValue::string("New York"))]),
                    ),
                ])]),
            ),
            (
                "city",
                MmdbValue::map([(
                    "names",
                    MmdbValue::map([("en", MmdbValue::string("Buffalo"))]),
                )]),
            ),
            (
                "postal",
                MmdbValue::map([("code", MmdbValue::string("14202"))]),
            ),
            (
                "location",
                MmdbValue::map([
                    ("latitude", MmdbValue::Double(42.886_4)),
                    ("longitude", MmdbValue::Double(-78.878_4)),
                    ("accuracy_radius", MmdbValue::U16(50)),
                    ("time_zone", MmdbValue::string("America/New_York")),
                ]),
            ),
        ])
    }

    #[test]
    fn city_lookup_ipv4_roundtrip() {
        let mut b = MmdbBuilder::new(IpVersion::V4, "GeoLite2-City").with_languages(["en", "de"]);
        b.insert(ip("1.2.3.0"), 24, &city_record()).unwrap();
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

    #[test]
    fn language_fallback_and_selection() {
        // localised names (city, subdivision) honour the preferred language;
        // country/continent are identity enums and are language-independent.
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
        b.insert(ip("1.2.3.0"), 24, &rec).unwrap();
        let bytes = b.build().unwrap();

        let de = MmdbReader::from_bytes(bytes.clone())
            .unwrap()
            .with_language("de");
        assert_eq!(de.lookup(ip("1.2.3.4")).unwrap().city(), Some("Köln"));

        // a language with no entry falls back to English
        let fr = MmdbReader::from_bytes(bytes).unwrap().with_language("fr");
        assert_eq!(fr.lookup(ip("1.2.3.4")).unwrap().city(), Some("Cologne"));
    }

    #[test]
    fn to_owned_and_serialize() {
        let mut b = MmdbBuilder::new(IpVersion::V4, "GeoLite2-City").with_languages(["en"]);
        b.insert(ip("1.2.3.0"), 24, &city_record()).unwrap();
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

    #[test]
    fn ipv4_in_ipv6_tree() {
        let mut b = MmdbBuilder::new(IpVersion::V6, "GeoLite2-Country");
        let be = MmdbValue::map([(
            "country",
            MmdbValue::map([("iso_code", MmdbValue::string("BE"))]),
        )]);
        let de = MmdbValue::map([(
            "country",
            MmdbValue::map([("iso_code", MmdbValue::string("DE"))]),
        )]);
        b.insert(ip("9.9.9.0"), 24, &be).unwrap();
        b.insert(ip("2001:db8::"), 32, &de).unwrap();
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

    #[test]
    fn asn_database() {
        let mut b = MmdbBuilder::new(IpVersion::V4, "GeoLite2-ASN");
        let rec = MmdbValue::map([
            ("autonomous_system_number", MmdbValue::U32(15169)),
            (
                "autonomous_system_organization",
                MmdbValue::string("Google LLC"),
            ),
        ]);
        b.insert(ip("8.8.8.0"), 24, &rec).unwrap();
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

    #[test]
    fn out_of_range_asn_keeps_organization() {
        let mut b = MmdbBuilder::new(IpVersion::V4, "GeoLite2-ASN");
        // 23456 (AS_TRANS) is outside rama's assignable-ASN ranges yet appears
        // in real ASN data — the owned conversion must not drop the record.
        let rec = MmdbValue::map([
            ("autonomous_system_number", MmdbValue::U32(23456)),
            (
                "autonomous_system_organization",
                MmdbValue::string("Placeholder AS"),
            ),
        ]);
        b.insert(ip("203.0.113.0"), 24, &rec).unwrap();
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

    #[test]
    fn owned_serde_roundtrip() {
        use crate::address::ip::geo::GeoLocation;
        let mut b = MmdbBuilder::new(IpVersion::V4, "GeoLite2-City").with_languages(["en"]);
        b.insert(ip("1.2.3.0"), 24, &city_record()).unwrap();
        let reader = MmdbReader::from_bytes(b.build().unwrap()).unwrap();
        let owned = reader.lookup(ip("1.2.3.4")).unwrap().to_owned();

        let json = serde_json::to_string(&owned).unwrap();
        let back: GeoLocation = serde_json::from_str(&json).unwrap();
        assert_eq!(owned, back);
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
}
