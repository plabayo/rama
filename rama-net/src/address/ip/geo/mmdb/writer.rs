//! Minimal MaxMind DB writer.
//!
//! Builds a spec-compliant `.mmdb` image from inserted `(network, value)`
//! pairs, emitting 32-bit records. Identical records are stored once and
//! shared. [`MmdbBuilder::write_to`] / [`MmdbBuilder::write_to_file`] serialise
//! directly to the sink, so a large database can be streamed to disk.

use std::fmt;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use ahash::HashMap;
use ipnet::IpNet;

use super::{IpVersion, METADATA_MARKER, RecordSize};

/// Error returned while building or serialising a MaxMind DB.
#[derive(Debug)]
#[non_exhaustive]
pub enum MmdbWriteError {
    /// A zero-length prefix (`/0`) was supplied; the builder requires at
    /// least one bit.
    ZeroPrefix,
    /// The IP family of the inserted network does not match the database's
    /// `ip_version`.
    FamilyMismatch,
    /// The network overlaps a previously inserted one (the builder does not
    /// split existing leaves).
    OverlappingNetwork,
    /// The database exceeds the format's 4 GiB / `u32` addressing limit.
    TooLarge,
    /// Failed to write the serialised database to a sink.
    Io(io::Error),
}

impl fmt::Display for MmdbWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroPrefix => f.write_str("mmdb writer: zero-length prefix is not supported"),
            Self::FamilyMismatch => {
                f.write_str("mmdb writer: ip family does not match database ip_version")
            }
            Self::OverlappingNetwork => f.write_str("mmdb writer: overlapping networks"),
            Self::TooLarge => f.write_str("mmdb writer: database exceeds 4 GiB addressing limit"),
            Self::Io(err) => write!(f, "mmdb writer: i/o error: {err}"),
        }
    }
}

impl std::error::Error for MmdbWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for MmdbWriteError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// A value that can be stored in a MaxMind DB data record.
///
/// Internal building block: databases are built from typed [`GeoLocation`]
/// values via [`MmdbBuilder::insert`], not from this dynamic representation.
///
/// [`GeoLocation`]: crate::address::ip::geo::GeoLocation
/// [`MmdbBuilder::insert`]: crate::address::ip::geo::MmdbBuilder::insert
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub(crate) enum MmdbValue {
    /// A map of string keys to values (insertion order preserved).
    Map(Vec<(String, Self)>),
    /// An ordered list of values.
    Array(Vec<Self>),
    /// A UTF-8 string.
    String(String),
    /// An IEEE-754 `binary64` double.
    Double(f64),
    /// An unsigned 16-bit integer.
    U16(u16),
    /// An unsigned 32-bit integer.
    U32(u32),
    /// An unsigned 64-bit integer.
    U64(u64),
}

impl MmdbValue {
    /// Convenience constructor for a map.
    pub(crate) fn map<I, K>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, Self)>,
        K: Into<String>,
    {
        Self::Map(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    /// Convenience constructor for a string value.
    pub(crate) fn string(s: impl Into<String>) -> Self {
        Self::String(s.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Record {
    #[default]
    Empty,
    Node(u32),
    Data(u32),
}

#[derive(Debug, Clone, Copy, Default)]
struct Node {
    left: Record,
    right: Record,
}

impl Node {
    fn get(&self, bit: u8) -> Record {
        if bit == 0 { self.left } else { self.right }
    }
    fn set(&mut self, bit: u8, rec: Record) {
        if bit == 0 {
            self.left = rec;
        } else {
            self.right = rec;
        }
    }
}

/// A builder for MaxMind DB byte images.
#[derive(Debug, Clone)]
pub struct MmdbBuilder {
    ip_version: IpVersion,
    record_size: RecordSize,
    database_type: String,
    languages: Vec<String>,
    build_epoch: u64,
    nodes: Vec<Node>,
    data: Vec<u8>,
    /// Encoded record -> its offset in `data`, so identical records are
    /// stored once.
    dedup: HashMap<Box<[u8]>, usize>,
}

impl MmdbBuilder {
    /// Create a builder for a database of the given [`IpVersion`] and
    /// `database_type` string (e.g. `"GeoLite2-City"`). Records are emitted at
    /// 32 bits.
    #[must_use]
    pub fn new(ip_version: IpVersion, database_type: impl Into<String>) -> Self {
        Self {
            ip_version,
            record_size: RecordSize::Bits32,
            database_type: database_type.into(),
            languages: Vec::new(),
            build_epoch: 0,
            nodes: vec![Node::default()],
            data: Vec::new(),
            dedup: HashMap::default(),
        }
    }

    /// Declare the locale codes for which localised data is present.
    #[must_use]
    pub fn with_languages<I, S>(mut self, langs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.languages = langs.into_iter().map(Into::into).collect();
        self
    }

    /// Set the build timestamp (Unix epoch seconds).
    #[must_use]
    pub fn with_build_epoch(mut self, epoch: u64) -> Self {
        self.build_epoch = epoch;
        self
    }

    /// Insert a `(network, value)` mapping. Internal: the public, typed entry
    /// point is [`MmdbBuilder::insert`] (which takes a `&GeoLocation`).
    ///
    /// For an IPv6 database, IPv4 networks are placed in the `::/96` range so
    /// the reader's IPv4-in-IPv6 traversal finds them.
    ///
    /// # Errors
    ///
    /// Returns [`MmdbWriteError`] if the IP family does not match the database,
    /// the network overlaps an existing entry, or the data section grows beyond
    /// 4 GiB.
    ///
    /// [`MmdbBuilder::insert`]: crate::address::ip::geo::MmdbBuilder::insert
    pub(crate) fn insert_value(
        &mut self,
        net: IpNet,
        value: impl Into<MmdbValue>,
    ) -> Result<(), MmdbWriteError> {
        let data_offset = self.append_data(&value.into());
        let data_offset = u32::try_from(data_offset)
            .ok()
            .ok_or(MmdbWriteError::TooLarge)?;

        let mut octets = [0u8; 16];
        let nbits = match (self.ip_version, net) {
            (IpVersion::V4, IpNet::V4(n)) => {
                octets[..4].copy_from_slice(&n.addr().octets());
                n.prefix_len() as usize
            }
            (IpVersion::V6, IpNet::V6(n)) => {
                octets.copy_from_slice(&n.addr().octets());
                n.prefix_len() as usize
            }
            (IpVersion::V6, IpNet::V4(n)) => {
                // place the IPv4 network in the ::/96 range (bits 96..128)
                octets[12..16].copy_from_slice(&n.addr().octets());
                96 + n.prefix_len() as usize
            }
            (IpVersion::V4, IpNet::V6(_)) => return Err(MmdbWriteError::FamilyMismatch),
        };
        if nbits == 0 {
            return Err(MmdbWriteError::ZeroPrefix);
        }

        let mut node = 0usize;
        for i in 0..nbits {
            let bit = (octets[i / 8] >> (7 - (i % 8))) & 1;
            if i == nbits - 1 {
                self.nodes[node].set(bit, Record::Data(data_offset));
            } else {
                node = self.follow_or_create(node, bit)?;
            }
        }
        Ok(())
    }

    fn follow_or_create(&mut self, node: usize, bit: u8) -> Result<usize, MmdbWriteError> {
        match self.nodes[node].get(bit) {
            Record::Node(idx) => Ok(idx as usize),
            Record::Empty => {
                // Reject before pushing so the new index (and the final
                // node_count) always stay strictly within `u32`.
                if self.nodes.len() >= u32::MAX as usize {
                    return Err(MmdbWriteError::TooLarge);
                }
                let new = self.nodes.len() as u32;
                self.nodes.push(Node::default());
                self.nodes[node].set(bit, Record::Node(new));
                Ok(new as usize)
            }
            Record::Data(_) => Err(MmdbWriteError::OverlappingNetwork),
        }
    }

    fn append_data(&mut self, value: &MmdbValue) -> usize {
        let mut encoded = Vec::new();
        encode_inline(value, &mut encoded);
        if let Some(&offset) = self.dedup.get(encoded.as_slice()) {
            return offset;
        }
        let offset = self.data.len();
        self.data.extend_from_slice(&encoded);
        self.dedup.insert(encoded.into_boxed_slice(), offset);
        offset
    }

    /// Serialise the database to a byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`MmdbWriteError::TooLarge`] if the resulting tree/data layout
    /// exceeds the format's `u32` addressing limit. `follow_or_create` already
    /// bounds the node count, so `node_count as u32` here is always exact.
    pub fn build(&self) -> Result<Vec<u8>, MmdbWriteError> {
        let mut out = Vec::new();
        self.serialize_to(&mut out)?;
        Ok(out)
    }

    /// Serialise the database directly into `w` without buffering the whole
    /// image first.
    fn serialize_to<W: Write>(&self, w: &mut W) -> Result<(), MmdbWriteError> {
        let node_count = self.nodes.len() as u32;
        for node in &self.nodes {
            write_record(w, node.left, node_count)?;
            write_record(w, node.right, node_count)?;
        }
        w.write_all(&[0u8; 16])?; // data section separator
        w.write_all(&self.data)?;
        w.write_all(METADATA_MARKER)?;
        w.write_all(&self.encode_metadata(node_count))?;
        Ok(())
    }

    /// Serialise the database to any writer, streaming directly to the sink.
    ///
    /// # Errors
    ///
    /// Returns [`MmdbWriteError`] if the database is too large to encode or the
    /// underlying write fails.
    pub fn write_to<W: Write>(&self, mut w: W) -> Result<(), MmdbWriteError> {
        self.serialize_to(&mut w)
    }

    /// Serialise the database to a file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`MmdbWriteError`] if the database is too large to encode or the
    /// file cannot be written.
    pub fn write_to_file(&self, path: impl AsRef<Path>) -> Result<(), MmdbWriteError> {
        let file = std::fs::File::create(path)?;
        let mut writer = BufWriter::new(file);
        self.serialize_to(&mut writer)?;
        writer.flush()?;
        Ok(())
    }

    fn encode_metadata(&self, node_count: u32) -> Vec<u8> {
        let mut pairs = vec![
            ("node_count".to_owned(), MmdbValue::U32(node_count)),
            (
                "record_size".to_owned(),
                MmdbValue::U16(self.record_size.bits()),
            ),
            (
                "ip_version".to_owned(),
                MmdbValue::U16(self.ip_version.number()),
            ),
            (
                "database_type".to_owned(),
                MmdbValue::String(self.database_type.clone()),
            ),
            ("binary_format_major_version".to_owned(), MmdbValue::U16(2)),
            ("binary_format_minor_version".to_owned(), MmdbValue::U16(0)),
            ("build_epoch".to_owned(), MmdbValue::U64(self.build_epoch)),
        ];
        if !self.languages.is_empty() {
            pairs.push((
                "languages".to_owned(),
                MmdbValue::Array(
                    self.languages
                        .iter()
                        .map(|l| MmdbValue::String(l.clone()))
                        .collect(),
                ),
            ));
        }
        let mut out = Vec::new();
        encode_inline(&MmdbValue::Map(pairs), &mut out);
        out
    }
}

fn write_record<W: Write>(w: &mut W, rec: Record, node_count: u32) -> Result<(), MmdbWriteError> {
    let value: u32 = match rec {
        Record::Node(idx) => idx,
        Record::Empty => node_count,
        // data leaf value = node_count + 16 + data_offset; reject (rather than
        // wrap) if the addressable space is exhausted.
        Record::Data(off) => node_count
            .checked_add(16)
            .and_then(|v| v.checked_add(off))
            .ok_or(MmdbWriteError::TooLarge)?,
    };
    w.write_all(&value.to_be_bytes())?;
    Ok(())
}

/// Encode a value (and its children) inline into `out`.
fn encode_inline(value: &MmdbValue, out: &mut Vec<u8>) {
    match value {
        MmdbValue::Map(pairs) => {
            encode_header(7, pairs.len(), out);
            for (k, v) in pairs {
                encode_string(k, out);
                encode_inline(v, out);
            }
        }
        MmdbValue::Array(items) => {
            encode_header(11, items.len(), out);
            for v in items {
                encode_inline(v, out);
            }
        }
        MmdbValue::String(s) => encode_string(s, out),
        MmdbValue::Double(f) => {
            encode_header(3, 8, out);
            out.extend_from_slice(&f.to_be_bytes());
        }
        MmdbValue::U16(n) => encode_uint(5, u128::from(*n), out),
        MmdbValue::U32(n) => encode_uint(6, u128::from(*n), out),
        MmdbValue::U64(n) => encode_uint(9, u128::from(*n), out),
    }
}

fn encode_string(s: &str, out: &mut Vec<u8>) {
    encode_header(2, s.len(), out);
    out.extend_from_slice(s.as_bytes());
}

fn encode_uint(type_num: u8, value: u128, out: &mut Vec<u8>) {
    let bytes = min_be_bytes(value);
    encode_header(type_num, bytes.len(), out);
    out.extend_from_slice(&bytes);
}

/// Minimal big-endian byte representation of `value` (empty for zero).
fn min_be_bytes(value: u128) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let full = value.to_be_bytes();
    let first = full.iter().position(|&b| b != 0).unwrap_or(full.len());
    full[first..].to_vec()
}

/// Encode a control byte (+ extended type byte + size-extension bytes).
fn encode_header(type_num: u8, size: usize, out: &mut Vec<u8>) {
    let type_bits = if type_num <= 7 { type_num } else { 0 };
    let (low5, ext): (u8, Vec<u8>) = if size <= 28 {
        (size as u8, Vec::new())
    } else if size <= 284 {
        (29, vec![(size - 29) as u8])
    } else if size <= 65820 {
        (30, ((size - 285) as u16).to_be_bytes().to_vec())
    } else {
        let s = (size - 65821) as u32;
        (31, vec![(s >> 16) as u8, (s >> 8) as u8, s as u8])
    };
    out.push((type_bits << 5) | low5);
    if type_num > 7 {
        out.push(type_num - 7);
    }
    out.extend_from_slice(&ext);
}
