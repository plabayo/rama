//! IP geolocation lookups per database access mode.
//!
//! Every mode returns an owned [`GeoLocation`], as `IpGeoDb` does, so the
//! modes compare like for like. The modes are an in-memory buffer, a memory
//! map, and positional reads without a cache or with a 4 MiB / 16 MiB block
//! cache, each with and without the 16-bit jump table.
//!
//! The `synth` database is generated (about a million IPv4 networks). Real
//! databases are benchmarked when `RAMA_BENCH_GEO_DIR` names a directory with
//! `GeoLite2-ASN.mmdb`, `GeoLite2-City.mmdb` or `IP2Location-LITE-DB11.mmdb`.
//!
//! `RAMA_BENCH_GEO_CASE` keeps only the cases whose name starts with it (such
//! as `city/pread`), to measure the resident set of one mode with
//! `/usr/bin/time -l` (macOS) or `-v` (Linux), which divan does not report.

#![expect(
    clippy::unwrap_used,
    reason = "bench: panic-on-error is the standard pattern for harnesses"
)]

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::LazyLock;

use divan::{Bencher, black_box, counter::ItemsCount};
use rama::geo::Country;
use rama::io::BlockCacheConfig;
use rama::net::address::ip::geo::{
    GeoLocation, IpVersion, MmdbBuilder, MmdbFileConfig, MmdbFileReader, MmdbReader,
};
use rama::net::address::ip::ipnet::{IpNet, Ipv4Net};
use rama::utils::fs::TempDir;

mod bench_alloc;

fn main() {
    divan::main();
}

/// Lookups per timed iteration.
const BATCH: usize = 1024;

/// Networks in the generated database.
const SYNTH_NETWORKS: u32 = 1_000_000;

#[derive(Debug, Clone, Copy)]
enum Db {
    Synth,
    Asn,
    City,
    Db11,
}

impl Db {
    fn file_name(self) -> &'static str {
        match self {
            Self::Synth => "synth.mmdb",
            Self::Asn => "GeoLite2-ASN.mmdb",
            Self::City => "GeoLite2-City.mmdb",
            Self::Db11 => "IP2Location-LITE-DB11.mmdb",
        }
    }

    fn path(self) -> Option<PathBuf> {
        if matches!(self, Self::Synth) {
            return Some(SYNTH.1.clone());
        }
        let dir = std::env::var_os("RAMA_BENCH_GEO_DIR")?;
        let path = PathBuf::from(dir).join(self.file_name());
        path.is_file().then_some(path)
    }
}

#[derive(Debug, Clone, Copy)]
enum Mode {
    Memory,
    Mmap,
    Pread,
    Pread4Mib,
    Pread16Mib,
}

#[derive(Debug, Clone, Copy)]
struct Case {
    db: Db,
    mode: Mode,
    jump_table: bool,
}

impl fmt::Display for Case {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let db = match self.db {
            Db::Synth => "synth",
            Db::Asn => "asn",
            Db::City => "city",
            Db::Db11 => "db11",
        };
        let mode = match self.mode {
            Mode::Memory => "memory",
            Mode::Mmap => "mmap",
            Mode::Pread => "pread",
            Mode::Pread4Mib => "pread-4mib",
            Mode::Pread16Mib => "pread-16mib",
        };
        let jump = if self.jump_table { "jump" } else { "nojump" };
        write!(f, "{db}/{mode}/{jump}")
    }
}

enum Reader {
    Slice(MmdbReader),
    File(MmdbFileReader),
}

impl Reader {
    fn open(case: Case) -> Option<Self> {
        let path = case.db.path()?;
        let slice = |reader: MmdbReader| {
            Self::Slice(if case.jump_table {
                reader
            } else {
                reader.without_jump_table()
            })
        };
        let file = |budget: usize| {
            let config = MmdbFileConfig::default()
                .with_jump_table(case.jump_table)
                .with_cache(BlockCacheConfig::new(budget));
            Self::File(MmdbFileReader::open_with_config(&path, config).unwrap())
        };
        Some(match case.mode {
            Mode::Memory => slice(MmdbReader::open(&path).unwrap()),
            // SAFETY: nothing writes the benchmark databases while they are mapped.
            Mode::Mmap => slice(unsafe { MmdbReader::open_mmap(&path) }.unwrap()),
            Mode::Pread => file(0),
            Mode::Pread4Mib => file(4 << 20),
            Mode::Pread16Mib => file(16 << 20),
        })
    }

    fn lookup(&self, ip: IpAddr) -> Option<GeoLocation> {
        match self {
            Self::Slice(reader) => reader.lookup(ip).map(|view| view.to_owned()),
            Self::File(reader) => reader.lookup(ip),
        }
    }
}

/// The generated database, kept on disk for the file-backed modes.
static SYNTH: LazyLock<(TempDir, PathBuf)> = LazyLock::new(|| {
    let dir = rama::utils::fs::tempdir().unwrap();
    let path = dir.path().join(Db::Synth.file_name());
    let mut b = MmdbBuilder::new(IpVersion::V6, "Synth-City");
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    for _ in 0..SYNTH_NETWORKS {
        let bits = xorshift(&mut state) as u32;
        let prefix = 16 + (bits % 17) as u8;
        let net = Ipv4Net::new(Ipv4Addr::from(bits), prefix).unwrap().trunc();
        let idx = (bits >> 8) as usize % 400;
        let loc = GeoLocation {
            country: Some(Country::ALL[idx % 200].clone()),
            city: Some(format!("City {idx}").into()),
            ..Default::default()
        };
        // overlapping draws are skipped
        drop(b.insert(IpNet::V4(net), &loc));
    }
    b.write_to_file(&path).unwrap();
    (dir, path)
});

/// Lookup addresses: three in four IPv4, the rest in global unicast IPv6.
static IPS: LazyLock<Vec<IpAddr>> = LazyLock::new(|| {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    (0..BATCH)
        .map(|n| {
            let bits = xorshift(&mut state);
            if n % 4 == 0 {
                IpAddr::V6(Ipv6Addr::from(
                    (0x2000u128 << 112) | (u128::from(bits) << 48),
                ))
            } else {
                IpAddr::V4(Ipv4Addr::from(bits as u32))
            }
        })
        .collect()
});

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn cases() -> Vec<Case> {
    let only = std::env::var("RAMA_BENCH_GEO_CASE").unwrap_or_default();
    let mut cases = Vec::new();
    for db in [Db::Synth, Db::Asn, Db::City, Db::Db11] {
        for mode in [
            Mode::Memory,
            Mode::Mmap,
            Mode::Pread,
            Mode::Pread4Mib,
            Mode::Pread16Mib,
        ] {
            for jump_table in [true, false] {
                cases.push(Case {
                    db,
                    mode,
                    jump_table,
                });
            }
        }
    }
    // filter by name first, so a skipped synth database is never generated
    cases.retain(|case| case.to_string().starts_with(&only) && case.db.path().is_some());
    cases
}

#[divan::bench(args = cases(), threads = [1, 0])]
fn lookup(bencher: Bencher, case: Case) {
    let Some(reader) = Reader::open(case) else {
        return;
    };
    let ips = &*IPS;
    // warm the page cache so modes compare without disk latency
    for &ip in ips {
        black_box(reader.lookup(ip));
    }
    bencher.counter(ItemsCount::new(BATCH)).bench(|| {
        for &ip in ips {
            black_box(reader.lookup(ip));
        }
    });
}
