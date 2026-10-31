use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use core::time::Duration;

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Instant, SystemTime};

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt as _;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rama_core::geo::Country;
use rama_core::io::BlockCacheConfig;
use rama_utils::octets::{kib, mib};

use super::super::{METADATA_MARKER, MmdbValue};
use super::*;
use crate::address::ip::geo::mmdb::{IpVersion, MmdbBuilder, MmdbReader, RecordSize};

/// Access right to change file times without read or write access.
#[cfg(windows)]
const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;

/// Countries cycled over the fixture networks; all codes have two letters, so
/// every variant has the same layout.
const COUNTRIES: usize = 20;

/// IPv4 networks in [`fixture`], few under miri where building is slow.
const NETWORKS: u32 = if cfg!(miri) { 40 } else { 3000 };

/// IPv6 networks in [`fixture`].
const V6_NETWORKS: u16 = if cfg!(miri) { 4 } else { 64 };

fn country(variant: usize, i: u32) -> Country {
    Country::ALL[(i as usize + variant) % COUNTRIES].clone()
}

/// An IPv6 database of `NETWORKS` IPv4 /24s plus a few IPv6 /48s. Variants
/// share the layout and differ in the country stored at each offset.
fn fixture(variant: usize) -> Vec<u8> {
    let mut b =
        MmdbBuilder::new(IpVersion::V6, "Test-Country").with_build_epoch(1000 + variant as u64);
    for i in 0..NETWORKS {
        let net = Ipv4Net::new(v4(i), 24).unwrap().trunc();
        let loc = GeoLocation {
            country: Some(country(variant, i)),
            ..Default::default()
        };
        b.insert(IpNet::V4(net), &loc).unwrap();
    }
    for i in 0..V6_NETWORKS {
        let net = Ipv6Net::new(Ipv6Addr::new(0x2001, 0xdb8, i, 0, 0, 0, 0, 0), 48).unwrap();
        let loc = GeoLocation {
            country: Some(country(variant, u32::from(i))),
            ..Default::default()
        };
        b.insert(IpNet::V6(net), &loc).unwrap();
    }
    b.build().unwrap()
}

/// Address inside the `i`-th fixture network.
fn v4(i: u32) -> Ipv4Addr {
    Ipv4Addr::from(0x0A00_0001 + (i << 8))
}

fn country_of(reader: &MmdbFileReader, i: u32) -> Option<Country> {
    reader.lookup(IpAddr::V4(v4(i))).and_then(|loc| loc.country)
}

/// Write `bytes` next to `path` and rename it over `path`.
fn replace(path: &Path, bytes: &[u8]) {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).unwrap();
    fs::rename(&tmp, path).unwrap();
}

/// Set the modification time with attribute access only, which an open
/// reader allows on every platform.
fn set_mtime(path: &Path, mtime: SystemTime) {
    #[cfg(windows)]
    let file = fs::File::options()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .open(path)
        .unwrap();
    #[cfg(not(windows))]
    let file = fs::File::open(path).unwrap();
    file.set_modified(mtime).unwrap();
}

fn marker_offset(bytes: &[u8]) -> usize {
    bytes
        .windows(METADATA_MARKER.len())
        .rposition(|w| w == METADATA_MARKER)
        .unwrap()
}

/// Make the next lookup check the path.
fn force_check(reader: &MmdbFileReader) {
    reader.shared.next_check_nanos.store(0, Ordering::Relaxed);
}

/// Reload attempts, swaps and warnings so far.
fn stats(reader: &MmdbFileReader) -> (u64, u64, u64) {
    let stats = &reader.shared.stats;
    (
        stats.attempts.load(Ordering::Relaxed),
        stats.swaps.load(Ordering::Relaxed),
        stats.warnings.load(Ordering::Relaxed),
    )
}

/// Long interval: only [`force_check`] or a short read trigger a reload.
fn manual() -> MmdbFileConfig {
    MmdbFileConfig::default().with_check_interval(Duration::from_hours(1))
}

fn every_lookup() -> MmdbFileConfig {
    MmdbFileConfig::default().with_check_interval(Duration::ZERO)
}

fn probes() -> Vec<IpAddr> {
    let mut probes: Vec<IpAddr> = (0..NETWORKS + 20)
        .step_by(7)
        .map(|i| IpAddr::V4(v4(i)))
        .collect();
    probes.extend(
        [
            "2001:db8:5::1",
            "2001:db8:ffff::1",
            "::ffff:10.0.2.1",
            "9.9.9.9",
            "::1",
        ]
        .map(|ip| ip.parse::<IpAddr>().unwrap()),
    );
    probes
}

/// Owned results of the memory reader, the reference for every other mode.
fn reference(bytes: &[u8], ips: &[IpAddr]) -> Vec<Option<GeoLocation>> {
    let reader = MmdbReader::from_bytes(bytes.to_vec()).unwrap();
    ips.iter()
        .map(|&ip| reader.lookup(ip).map(|view| view.to_owned()))
        .collect()
}

fn configs() -> [MmdbFileConfig; 3] {
    [
        MmdbFileConfig::default(),
        MmdbFileConfig::default().with_jump_table(false),
        MmdbFileConfig::default().with_cache(
            BlockCacheConfig::new(kib(64)).with_block_size(NonZeroUsize::new(512).unwrap()),
        ),
    ]
}

#[test]
fn vec_source_matches_memory_reader() {
    let bytes = fixture(0);
    let ips = probes();
    let expected = reference(&bytes, &ips);
    assert!(expected.iter().filter(|loc| loc.is_some()).count() as u32 > NETWORKS / 7);
    for config in configs() {
        let reader = MmdbFileReader::from_read_at(bytes.clone(), config).unwrap();
        assert!(reader.path().is_none());
        let got: Vec<_> = ips.iter().map(|&ip| reader.lookup(ip)).collect();
        assert_eq!(got, expected);
    }
}

#[test]
fn vec_source_language_and_metadata() {
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
    b.insert_value("1.2.3.0/24".parse().unwrap(), rec).unwrap();
    let reader =
        MmdbFileReader::from_read_at(b.build().unwrap(), MmdbFileConfig::default()).unwrap();
    assert_eq!(reader.metadata().database_type.as_ref(), "GeoLite2-City");
    let ip = "1.2.3.4".parse().unwrap();
    assert_eq!(reader.lookup(ip).unwrap().city.as_deref(), Some("Cologne"));
    let de = reader.clone().with_language("de");
    assert_eq!(de.lookup(ip).unwrap().city.as_deref(), Some("Köln"));
    let fr = reader.with_language("fr");
    assert_eq!(fr.lookup(ip).unwrap().city.as_deref(), Some("Cologne"));
}

#[test]
fn vec_source_rejects_malformed_input() {
    let config = MmdbFileConfig::default;
    assert!(matches!(
        MmdbFileReader::from_read_at(vec![0u8; 32], config()),
        Err(GeoIpError::MissingMetadataMarker)
    ));
    MmdbFileReader::from_read_at(Vec::new(), config()).unwrap_err();
    let mut junk = METADATA_MARKER.to_vec();
    junk.push(0xff);
    MmdbFileReader::from_read_at(junk, config()).unwrap_err();
}

#[test]
fn vec_source_that_shrinks_reports_source_changed() {
    /// Reads past `cut` hit the end, as a file truncated after open.
    struct Shrinking {
        data: Vec<u8>,
        cut: AtomicU64,
    }

    impl ReadAt for Shrinking {
        fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
            let end = offset + buf.len() as u64;
            if end > self.cut.load(Ordering::Relaxed) {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            self.data.read_exact_at(buf, offset)
        }

        fn size(&self) -> std::io::Result<u64> {
            self.data.size()
        }
    }

    let source = Arc::new(Shrinking {
        data: fixture(0),
        cut: AtomicU64::new(u64::MAX),
    });
    let reader = MmdbFileReader::from_read_at(source.clone(), MmdbFileConfig::default()).unwrap();
    let ip = IpAddr::V4(v4(NETWORKS - 1));
    assert!(reader.try_lookup(ip).unwrap().is_some());

    // past the tree: the walk succeeds, the record read fails
    let data_start = reader.metadata().node_count as u64 * 8 + 16;
    source.cut.store(data_start, Ordering::Relaxed);
    assert!(matches!(
        reader.try_lookup(ip),
        Err(GeoIpError::SourceChanged)
    ));
    assert!(reader.lookup(ip).is_none());

    source.cut.store(0, Ordering::Relaxed);
    assert!(matches!(
        reader.try_lookup(ip),
        Err(GeoIpError::SourceChanged)
    ));
}

/// Random fixtures: every positional mode returns what the memory reader does.
#[quickcheck_macros::quickcheck]
#[cfg_attr(miri, ignore = "quickcheck is too slow under miri")]
fn prop_positional_matches_memory(nets: Vec<(u32, u8, u8)>, extra: Vec<u32>, v6: bool) -> bool {
    let version = if v6 { IpVersion::V6 } else { IpVersion::V4 };
    let mut b = MmdbBuilder::new(version, "T");
    let mut ips: Vec<IpAddr> = extra
        .into_iter()
        .map(|bits| IpAddr::V4(bits.into()))
        .collect();
    for (addr, prefix, idx) in nets {
        let net = Ipv4Net::new(Ipv4Addr::from(addr), prefix % 32 + 1)
            .unwrap()
            .trunc();
        let loc = GeoLocation {
            country: Some(Country::ALL[idx as usize % Country::ALL.len()].clone()),
            city: (idx % 3 == 0).then(|| "Somewhere".into()),
            ..Default::default()
        };
        if b.insert(IpNet::V4(net), &loc).is_ok() {
            ips.push(IpAddr::V4(Ipv4Addr::from(addr)));
        }
    }
    let bytes = b.build().unwrap();
    let expected = reference(&bytes, &ips);
    configs().into_iter().all(|config| {
        let reader = MmdbFileReader::from_read_at(bytes.clone(), config).unwrap();
        ips.iter().map(|&ip| reader.lookup(ip)).collect::<Vec<_>>() == expected
    })
}

#[test]
#[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
fn file_and_mmap_match_memory_reader() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("db.mmdb");
    let bytes = fixture(3);
    fs::write(&path, &bytes).unwrap();
    let ips = probes();
    let expected = reference(&bytes, &ips);

    for config in configs() {
        let reader = MmdbFileReader::open_with_config(&path, config).unwrap();
        assert_eq!(reader.path(), Some(path.as_path()));
        let got: Vec<_> = ips.iter().map(|&ip| reader.lookup(ip)).collect();
        assert_eq!(got, expected);
    }
    #[cfg(feature = "mmap")]
    {
        // SAFETY: the file lives in a private temp dir that nothing writes to
        // while `mapped` lives, and `dir` outlives it.
        let mapped = unsafe { MmdbReader::open_mmap(&path) }.unwrap();
        let got: Vec<_> = ips
            .iter()
            .map(|&ip| mapped.lookup(ip).map(|view| view.to_owned()))
            .collect();
        assert_eq!(got, expected);
    }
}

#[test]
#[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
fn rename_over_serves_old_data_until_checked() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("db.mmdb");
    fs::write(&path, fixture(0)).unwrap();
    let reader = MmdbFileReader::open_with_config(&path, manual()).unwrap();
    let old = Arc::downgrade(&reader.shared.current.load_full());
    assert_eq!(country_of(&reader, 5), Some(country(0, 5)));

    replace(&path, &fixture(1));
    assert_eq!(country_of(&reader, 5), Some(country(0, 5)));
    assert!(old.upgrade().is_some());

    force_check(&reader);
    assert_eq!(country_of(&reader, 5), Some(country(1, 5)));
    assert_eq!(reader.metadata().build_epoch, 1001);
    assert_eq!(stats(&reader), (1, 1, 0));
    // the old version, and with it its file handles, is gone
    assert!(old.upgrade().is_none());
}

#[test]
#[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
fn older_mtime_replacement_is_detected() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("db.mmdb");
    fs::write(&path, fixture(0)).unwrap();
    let reader = MmdbFileReader::open_with_config(&path, every_lookup()).unwrap();
    assert_eq!(country_of(&reader, 9), Some(country(0, 9)));

    let tmp = path.with_extension("tmp");
    fs::write(&tmp, fixture(1)).unwrap();
    set_mtime(
        &tmp,
        SystemTime::UNIX_EPOCH + Duration::from_hours(24 * 365),
    );
    fs::rename(&tmp, &path).unwrap();
    assert_eq!(country_of(&reader, 9), Some(country(1, 9)));
    assert_eq!(stats(&reader).1, 1);
}

#[test]
#[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
fn rename_then_chtimes_reopens_at_most_twice() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("db.mmdb");
    fs::write(&path, fixture(0)).unwrap();
    let reader = MmdbFileReader::open_with_config(&path, every_lookup()).unwrap();

    replace(&path, &fixture(1));
    assert_eq!(country_of(&reader, 2), Some(country(1, 2)));
    // a server Last-Modified applied after the rename
    set_mtime(
        &path,
        SystemTime::UNIX_EPOCH + Duration::from_hours(24 * 400),
    );
    assert_eq!(country_of(&reader, 2), Some(country(1, 2)));
    let (attempts, swaps, warnings) = stats(&reader);
    assert!(attempts <= 2, "{attempts} attempts");
    assert_eq!((swaps, warnings), (attempts, 0));
}

#[cfg(unix)]
#[test]
#[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
fn same_size_and_mtime_new_inode_is_detected() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("db.mmdb");
    fs::write(&path, fixture(0)).unwrap();
    let mtime = fs::metadata(&path).unwrap().modified().unwrap();
    let reader = MmdbFileReader::open_with_config(&path, every_lookup()).unwrap();

    let tmp = path.with_extension("tmp");
    let next = fixture(1);
    assert_eq!(next.len() as u64, fs::metadata(&path).unwrap().len());
    fs::write(&tmp, next).unwrap();
    set_mtime(&tmp, mtime);
    fs::rename(&tmp, &path).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), mtime);
    assert_eq!(country_of(&reader, 4), Some(country(1, 4)));
}

#[cfg(unix)]
#[test]
#[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
fn symlinked_data_dir_swap() {
    use std::os::unix::fs::symlink;

    // the layout of a projected Kubernetes volume
    let dir = rama_utils::fs::tempdir().unwrap();
    let root = dir.path();
    let first = root.join("..2026_10_30_00_00_00.1");
    fs::create_dir(&first).unwrap();
    fs::write(first.join("db.mmdb"), fixture(0)).unwrap();
    symlink(&first, root.join("..data")).unwrap();
    symlink(root.join("..data/db.mmdb"), root.join("db.mmdb")).unwrap();

    let reader = MmdbFileReader::open_with_config(root.join("db.mmdb"), manual()).unwrap();
    assert_eq!(country_of(&reader, 7), Some(country(0, 7)));

    let second = root.join("..2026_10_31_00_00_00.2");
    fs::create_dir(&second).unwrap();
    fs::write(second.join("db.mmdb"), fixture(1)).unwrap();
    symlink(&second, root.join("..data_tmp")).unwrap();
    fs::rename(root.join("..data_tmp"), root.join("..data")).unwrap();
    fs::remove_dir_all(&first).unwrap();

    assert_eq!(country_of(&reader, 7), Some(country(0, 7)));
    force_check(&reader);
    assert_eq!(country_of(&reader, 7), Some(country(1, 7)));
}

#[test]
#[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
fn bad_replacements_keep_old_data_and_warn_once_each() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("db.mmdb");
    let good = fixture(0);
    fs::write(&path, &good).unwrap();
    let reader = MmdbFileReader::open_with_config(&path, every_lookup()).unwrap();
    let started = Instant::now();

    // truncated mid tree
    replace(&path, &good[..good.len() / 3]);
    for i in 0..50 {
        assert_eq!(country_of(&reader, i), Some(country(0, i)));
    }
    let (attempts, _, warnings) = stats(&reader);
    assert_eq!(warnings, 1);
    // retried only after the back-off
    assert!(attempts <= 1 + started.elapsed().as_secs(), "{attempts}");

    // a database without metadata
    replace(&path, &good[..marker_offset(&good)]);
    for i in 0..50 {
        assert_eq!(country_of(&reader, i), Some(country(0, i)));
    }
    assert_eq!(stats(&reader).2, 2);

    replace(&path, &fixture(1));
    assert_eq!(country_of(&reader, 3), Some(country(1, 3)));
    let (_, swaps, warnings) = stats(&reader);
    assert_eq!((swaps, warnings), (1, 2));
}

#[test]
#[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
fn missing_path_then_directory_then_good_file() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("db.mmdb");
    fs::write(&path, fixture(0)).unwrap();
    let reader = MmdbFileReader::open_with_config(&path, every_lookup()).unwrap();

    fs::remove_file(&path).unwrap();
    assert_eq!(country_of(&reader, 1), Some(country(0, 1)));
    assert_eq!(country_of(&reader, 2), Some(country(0, 2)));

    fs::create_dir(&path).unwrap();
    assert_eq!(country_of(&reader, 1), Some(country(0, 1)));
    assert_eq!(stats(&reader).2, 2);

    fs::remove_dir(&path).unwrap();
    fs::write(&path, fixture(1)).unwrap();
    assert_eq!(country_of(&reader, 1), Some(country(1, 1)));
    assert_eq!(stats(&reader).1, 1);
}

// in-place writers are refused on Windows while the reader is open
#[cfg(unix)]
#[test]
#[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
fn in_place_truncation_reports_source_changed_with_bounded_reopens() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("db.mmdb");
    fs::write(&path, fixture(0)).unwrap();
    let reader = MmdbFileReader::open_with_config(&path, manual()).unwrap();
    let tree_size = u64::from(reader.metadata().node_count) * 8;

    let started = Instant::now();
    fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(tree_size / 2)
        .unwrap();
    let changed = AtomicU64::new(0);
    std::thread::scope(|s| {
        for t in 0..16u32 {
            let (reader, changed) = (&reader, &changed);
            s.spawn(move || {
                for i in 0..1000u32 {
                    let ip = IpAddr::V4(v4((t * 1000 + i) % NETWORKS));
                    match reader.try_lookup(ip) {
                        Err(GeoIpError::SourceChanged) => {
                            changed.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(_) | Err(GeoIpError::Corrupt(_)) => {}
                        Err(err) => panic!("unexpected error: {err}"),
                    }
                }
            });
        }
    });
    assert!(changed.load(Ordering::Relaxed) > 0);
    let (attempts, swaps, warnings) = stats(&reader);
    let bound = 1 + started.elapsed().as_secs();
    assert!(attempts <= bound, "{attempts} reopen attempts > {bound}");
    assert_eq!((swaps, warnings), (0, 1));
}

#[cfg(unix)]
#[test]
#[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
fn in_place_overwrite_is_wrong_but_safe() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("db.mmdb");
    let mut bytes = fixture(0);
    fs::write(&path, &bytes).unwrap();
    let reader = MmdbFileReader::open_with_config(&path, manual()).unwrap();
    let ips = probes();
    let before: Vec<_> = ips.iter().map(|&ip| reader.lookup(ip)).collect();

    let data_start = reader.metadata().node_count as usize * 8 + 16;
    let marker = marker_offset(&bytes);
    bytes[data_start..marker].fill(0xFF);
    fs::write(&path, &bytes).unwrap();

    let after: Vec<_> = ips.iter().map(|&ip| reader.try_lookup(ip)).collect();
    assert!(
        after
            .iter()
            .all(|r| matches!(r, Ok(_) | Err(GeoIpError::Corrupt(_))))
    );
    let after: Vec<_> = after.into_iter().map(|r| r.ok().flatten()).collect();
    assert_ne!(after, before);
}

#[test]
#[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
fn herd_reopens_once_per_change() {
    const CHANGES: usize = 5;
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("db.mmdb");
    fs::write(&path, fixture(0)).unwrap();
    let reader = MmdbFileReader::open_with_config(&path, every_lookup()).unwrap();
    let done = AtomicBool::new(false);
    let start = Barrier::new(33);
    let mut unseen = None;

    std::thread::scope(|s| {
        for t in 0..32u32 {
            let (reader, done, start) = (&reader, &done, &start);
            s.spawn(move || {
                start.wait();
                let mut i = t;
                while !done.load(Ordering::Relaxed) {
                    // old or new data, never a miss
                    assert!(country_of(reader, i % NETWORKS).is_some());
                    i = i.wrapping_add(31);
                }
            });
        }
        start.wait();
        'changes: for variant in 1..=CHANGES {
            replace(&path, &fixture(variant));
            let deadline = Instant::now() + Duration::from_secs(30);
            while country_of(&reader, 0) != Some(country(variant, 0)) {
                if Instant::now() > deadline {
                    unseen = Some(variant);
                    break 'changes;
                }
                std::thread::yield_now();
            }
        }
        done.store(true, Ordering::Relaxed);
    });
    // checked after the scope: a panic inside it would join readers that never stop
    assert_eq!(unseen, None, "replacement never became visible");
    let (attempts, swaps, warnings) = stats(&reader);
    assert_eq!(
        (attempts, swaps, warnings),
        (CHANGES as u64, CHANGES as u64, 0)
    );
}

#[test]
#[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
fn cache_is_not_shared_across_versions() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("db.mmdb");
    let (a, b) = (fixture(0), fixture(1));
    assert_eq!(a.len(), b.len());
    fs::write(&path, &a).unwrap();
    let config = manual().with_cache(BlockCacheConfig::new(mib(4)));
    let reader = MmdbFileReader::open_with_config(&path, config).unwrap();
    for i in 0..NETWORKS {
        assert_eq!(country_of(&reader, i), Some(country(0, i)));
    }
    replace(&path, &b);
    force_check(&reader);
    for i in 0..NETWORKS {
        assert_eq!(country_of(&reader, i), Some(country(1, i)));
    }
}

#[cfg(windows)]
#[test]
fn windows_replace_and_remove_while_open() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("db.mmdb");
    fs::write(&path, fixture(0)).unwrap();
    let reader = MmdbFileReader::open_with_config(&path, manual()).unwrap();

    let tmp = path.with_extension("tmp");
    fs::write(&tmp, fixture(1)).unwrap();
    fs::rename(&tmp, &path).unwrap();
    assert_eq!(country_of(&reader, 6), Some(country(0, 6)));
    fs::remove_file(&path).unwrap();
    assert_eq!(country_of(&reader, 6), Some(country(0, 6)));
}

/// Compares every mode on the databases in `RAMA_TEST_GEO_DIR`.
#[test]
#[ignore = "needs real databases in RAMA_TEST_GEO_DIR"]
fn real_databases_match_across_modes() {
    let dir = std::env::var("RAMA_TEST_GEO_DIR").expect("RAMA_TEST_GEO_DIR");
    let mut checked = 0;
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|ext| ext != "mmdb") {
            continue;
        }
        let memory = MmdbReader::open(&path).unwrap();
        let plain = memory.clone().without_jump_table();
        let positional = MmdbFileReader::open(&path).unwrap();
        let cached = MmdbFileReader::open_with_config(
            &path,
            MmdbFileConfig::default().with_cache(BlockCacheConfig::new(mib(16))),
        )
        .unwrap();
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for n in 0..20_000u32 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let ip = if n % 4 == 0 {
                IpAddr::V6(Ipv6Addr::from(
                    (0x2000u128 << 112) | (u128::from(state) << 48),
                ))
            } else {
                IpAddr::V4(Ipv4Addr::from(state as u32))
            };
            let expected = memory.lookup(ip).map(|view| view.to_owned());
            assert_eq!(plain.lookup(ip).map(|view| view.to_owned()), expected);
            assert_eq!(
                positional.lookup(ip),
                expected,
                "{ip} in {}",
                path.display()
            );
            assert_eq!(cached.lookup(ip), expected);
        }
        checked += 1;
    }
    assert!(checked > 0, "no .mmdb files found");
}

/// Patch the right record of the root of a 32-bit tree built by [`fixture`].
fn with_root_right(mut bytes: Vec<u8>, value: u32) -> Vec<u8> {
    bytes[4..8].copy_from_slice(&value.to_be_bytes());
    bytes
}

/// Bad root records of the [`fixture`] tree: inside the separator, at the
/// metadata marker, and past the end of the file.
fn bad_root_records(good: &[u8]) -> [Vec<u8>; 3] {
    let reader = MmdbReader::from_bytes(good.to_vec()).unwrap();
    let node_count = reader.metadata().node_count;
    let tree_size = node_count * 8;
    let marker = marker_offset(good) as u32;
    [
        with_root_right(good.to_vec(), node_count + 1),
        with_root_right(good.to_vec(), node_count + (marker - tree_size)),
        with_root_right(good.to_vec(), node_count + good.len() as u32),
    ]
}

#[test]
fn bad_terminal_records_are_rejected_at_open() {
    let good = fixture(0);
    for bad in bad_root_records(&good) {
        for config in configs() {
            assert!(matches!(
                MmdbFileReader::from_read_at(bad.clone(), config),
                Err(GeoIpError::Corrupt(_))
            ));
        }
        assert!(matches!(
            MmdbReader::from_bytes(bad),
            Err(GeoIpError::Corrupt(_))
        ));
    }
    // the last byte before the marker is still a valid target
    let marker = marker_offset(&good) as u32;
    let reader = MmdbReader::from_bytes(good.clone()).unwrap();
    let node_count = reader.metadata().node_count;
    let last = with_root_right(good, node_count + (marker - node_count * 8) - 1);
    MmdbReader::from_bytes(last.clone()).unwrap();
    MmdbFileReader::from_read_at(last, MmdbFileConfig::default()).unwrap();
}

#[test]
#[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
fn bad_terminal_record_replacements_keep_the_loaded_version() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("db.mmdb");
    let good = fixture(0);
    fs::write(&path, &good).unwrap();
    let reader = MmdbFileReader::open_with_config(&path, manual()).unwrap();
    for (n, bad) in bad_root_records(&good).into_iter().enumerate() {
        replace(&path, &bad);
        force_check(&reader);
        assert_eq!(country_of(&reader, 3), Some(country(0, 3)));
        force_check(&reader);
        assert_eq!(country_of(&reader, 4), Some(country(0, 4)));
        let (attempts, swaps, warnings) = stats(&reader);
        assert_eq!((swaps, warnings), (0, n as u64 + 1));
        // the second check sees the same bad file within its back-off
        assert_eq!(attempts, n as u64 + 1);
    }
}

#[test]
#[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
fn backoff_expires_doubles_and_caps() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("db.mmdb");
    let good = fixture(0);
    fs::write(&path, &good).unwrap();
    let config = MmdbFileConfig::default().with_check_interval(Duration::from_secs(4));
    let reader = MmdbFileReader::open_with_config(&path, config).unwrap();
    replace(&path, &good[..good.len() / 3]);

    let backoff = || {
        reader
            .shared
            .reload
            .lock()
            .failed
            .as_ref()
            .map(|failed| failed.backoff)
    };
    let expire = || {
        if let Some(failed) = reader.shared.reload.lock().failed.as_mut() {
            failed.retry_at_nanos = 0;
        }
    };

    force_check(&reader);
    assert_eq!(country_of(&reader, 1), Some(country(0, 1)));
    assert_eq!(backoff(), Some(Duration::from_secs(1)));
    // within the back-off: no attempt
    force_check(&reader);
    country_of(&reader, 1);
    assert_eq!(stats(&reader).0, 1);

    let mut expected = [2, 4, 4].map(Duration::from_secs).into_iter();
    for attempt in 2..=4 {
        expire();
        force_check(&reader);
        assert_eq!(country_of(&reader, 1), Some(country(0, 1)));
        assert_eq!(stats(&reader), (attempt, 0, 1));
        assert_eq!(backoff(), expected.next());
    }

    // a different file is tried at once and resets the back-off
    replace(&path, &fixture(1));
    force_check(&reader);
    assert_eq!(country_of(&reader, 1), Some(country(1, 1)));
    assert_eq!(backoff(), None);
}

#[test]
#[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
fn one_check_per_deadline_under_concurrent_lookups() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("db.mmdb");
    fs::write(&path, fixture(0)).unwrap();
    let reader = MmdbFileReader::open_with_config(&path, manual()).unwrap();
    let checks = || reader.shared.stats.checks.load(Ordering::Relaxed);

    // not due yet: nobody checks
    for i in 0..100 {
        country_of(&reader, i);
    }
    assert_eq!(checks(), 0);

    replace(&path, &fixture(1));
    force_check(&reader);
    let start = Barrier::new(32);
    std::thread::scope(|s| {
        for t in 0..32u32 {
            let (reader, start) = (&reader, &start);
            s.spawn(move || {
                start.wait();
                for i in 0..100 {
                    country_of(reader, (t * 100 + i) % NETWORKS);
                }
            });
        }
    });
    assert_eq!(checks(), 1);
    assert_eq!(stats(&reader), (1, 1, 0));
    assert_eq!(country_of(&reader, 0), Some(country(1, 0)));
}

#[test]
#[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
fn lookup_holding_an_old_version_across_two_swaps() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("db.mmdb");
    fs::write(&path, fixture(0)).unwrap();
    let reader = MmdbFileReader::open_with_config(&path, manual()).unwrap();
    // what an in-flight lookup holds
    let held = reader.shared.current.load_full();

    replace(&path, &fixture(1));
    force_check(&reader);
    assert_eq!(country_of(&reader, 8), Some(country(1, 8)));
    let middle = Arc::downgrade(&reader.shared.current.load_full());

    replace(&path, &fixture(2));
    force_check(&reader);
    assert_eq!(country_of(&reader, 8), Some(country(2, 8)));

    // the held version still answers from its own file and handles
    let old = held.lookup(IpAddr::V4(v4(8)), "en").unwrap().unwrap();
    assert_eq!(old.country, Some(country(0, 8)));
    assert!(middle.upgrade().is_none());
    let held_weak = Arc::downgrade(&held);
    drop(held);
    assert!(held_weak.upgrade().is_none());
}

#[cfg(unix)]
#[test]
#[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
fn short_read_recovers_by_reopening_the_path() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("db.mmdb");
    fs::write(&path, fixture(0)).unwrap();
    let reader = MmdbFileReader::open_with_config(&path, manual()).unwrap();

    // the loaded file shrinks in place, then a good file takes its name
    let tree_size = u64::from(reader.metadata().node_count) * 8;
    fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(tree_size / 2)
        .unwrap();
    replace(&path, &fixture(1));
    // no periodic check is due: the short read itself reopens
    let recovered = (0..NETWORKS).find_map(|i| {
        let loc = reader.try_lookup(IpAddr::V4(v4(i))).unwrap()?;
        (loc.country == Some(country(1, i))).then_some(i)
    });
    assert!(recovered.is_some());
    assert_eq!(stats(&reader), (1, 1, 0));
    assert_eq!(reader.shared.stats.checks.load(Ordering::Relaxed), 0);
}

#[test]
fn stale_handle_reports_source_changed() {
    /// Fails every read past `cut` with a stale handle, as NFS does after a
    /// replacement on another client.
    struct Stale {
        data: Vec<u8>,
        cut: AtomicU64,
    }

    impl ReadAt for Stale {
        fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
            if offset + buf.len() as u64 > self.cut.load(Ordering::Relaxed) {
                return Err(std::io::ErrorKind::StaleNetworkFileHandle.into());
            }
            self.data.read_exact_at(buf, offset)
        }

        fn size(&self) -> std::io::Result<u64> {
            self.data.size()
        }
    }

    let source = Arc::new(Stale {
        data: fixture(0),
        cut: AtomicU64::new(u64::MAX),
    });
    let reader = MmdbFileReader::from_read_at(source.clone(), MmdbFileConfig::default()).unwrap();
    let ip = IpAddr::V4(v4(1));
    assert!(reader.try_lookup(ip).unwrap().is_some());
    source.cut.store(0, Ordering::Relaxed);
    assert!(matches!(
        reader.try_lookup(ip),
        Err(GeoIpError::SourceChanged)
    ));
}

/// Minimal MaxMind DB encoder for fixtures the builder cannot produce: 24 and
/// 28-bit records and every pointer encoding.
mod handmade {
    use super::*;

    pub(super) fn header(kind: u8, size: usize) -> Vec<u8> {
        let (bits, extra): (u8, Vec<u8>) = match size {
            0..29 => (size as u8, Vec::new()),
            29..285 => (29, vec![(size - 29) as u8]),
            285..65821 => (30, ((size - 285) as u16).to_be_bytes().to_vec()),
            _ => (31, ((size - 65821) as u32).to_be_bytes()[1..].to_vec()),
        };
        let mut out = if kind <= 7 {
            vec![(kind << 5) | bits]
        } else {
            vec![bits, kind - 7]
        };
        out.extend(extra);
        out
    }

    pub(super) fn string(s: &str) -> Vec<u8> {
        let mut out = header(2, s.len());
        out.extend(s.as_bytes());
        out
    }

    pub(super) fn bytes(len: usize) -> Vec<u8> {
        let mut out = header(4, len);
        out.resize(out.len() + len, 0xAB);
        out
    }

    pub(super) fn uint(kind: u8, value: u64) -> Vec<u8> {
        let raw = value.to_be_bytes();
        let start = raw.iter().position(|&b| b != 0).unwrap_or(raw.len());
        let mut out = header(kind, raw.len() - start);
        out.extend(&raw[start..]);
        out
    }

    pub(super) fn double(value: f64) -> Vec<u8> {
        let mut out = header(3, 8);
        out.extend(value.to_be_bytes());
        out
    }

    pub(super) fn map(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut out = header(7, pairs.len());
        for (key, value) in pairs {
            out.extend(key);
            out.extend(value);
        }
        out
    }

    pub(super) fn array(items: &[Vec<u8>]) -> Vec<u8> {
        let mut out = header(11, items.len());
        for item in items {
            out.extend(item);
        }
        out
    }

    /// A pointer to data-section offset `target` in encoding `size` (0..=3).
    pub(super) fn pointer(size: u8, target: usize) -> Vec<u8> {
        let value = match size {
            1 => target - 2048,
            2 => target - 526_336,
            _ => target,
        };
        let v = value as u32;
        match size {
            0 => vec![0x20 | (v >> 8) as u8, v as u8],
            1 => vec![0x28 | (v >> 16) as u8, (v >> 8) as u8, v as u8],
            2 => vec![
                0x30 | (v >> 24) as u8,
                (v >> 16) as u8,
                (v >> 8) as u8,
                v as u8,
            ],
            _ => {
                let mut out = vec![0x38];
                out.extend(v.to_be_bytes());
                out
            }
        }
    }

    /// Search tree for `(bits, data offset)` networks, encoded with `bits`
    /// per record.
    pub(super) fn tree(record: RecordSize, networks: &[(Vec<u8>, usize)]) -> (Vec<u8>, u32) {
        #[derive(Clone, Copy)]
        enum Slot {
            Empty,
            Node(usize),
            Data(usize),
        }
        let mut nodes = vec![[Slot::Empty; 2]];
        for (path, offset) in networks {
            let mut node = 0;
            for (depth, &bit) in path.iter().enumerate() {
                let bit = usize::from(bit);
                if depth + 1 == path.len() {
                    nodes[node][bit] = Slot::Data(*offset);
                } else {
                    node = if let Slot::Node(next) = nodes[node][bit] {
                        next
                    } else {
                        nodes.push([Slot::Empty; 2]);
                        nodes[node][bit] = Slot::Node(nodes.len() - 1);
                        nodes.len() - 1
                    };
                }
            }
        }
        let count = nodes.len() as u32;
        let value = |slot: Slot| match slot {
            Slot::Empty => count,
            Slot::Node(next) => next as u32,
            Slot::Data(offset) => count + 16 + offset as u32,
        };
        let mut out = Vec::new();
        for [left, right] in nodes {
            let (l, r) = (value(left), value(right));
            match record {
                RecordSize::Bits24 => {
                    out.extend(&l.to_be_bytes()[1..]);
                    out.extend(&r.to_be_bytes()[1..]);
                }
                RecordSize::Bits28 => {
                    out.extend(&l.to_be_bytes()[1..]);
                    out.push((((l >> 24) as u8) << 4) | (r >> 24) as u8);
                    out.extend(&r.to_be_bytes()[1..]);
                }
                RecordSize::Bits32 => {
                    out.extend(l.to_be_bytes());
                    out.extend(r.to_be_bytes());
                }
            }
        }
        (out, count)
    }

    /// Bits of `net`, placed under `::/96` for an IPv6 tree.
    pub(super) fn path(version: IpVersion, net: Ipv4Net) -> Vec<u8> {
        let addr = u32::from(net.addr());
        let mut bits: Vec<u8> = (0..net.prefix_len())
            .map(|i| ((addr >> (31 - i)) & 1) as u8)
            .collect();
        if version == IpVersion::V6 {
            let mut v6 = vec![0u8; 96];
            v6.append(&mut bits);
            bits = v6;
        }
        bits
    }

    pub(super) fn database(record: RecordSize, version: IpVersion) -> Vec<u8> {
        let key = |k: &str| string(k);
        // shared values, at offsets that need each pointer encoding
        let mut data = Vec::new();
        let country_be = data.len();
        data.extend(map(&[(key("iso_code"), string("BE"))]));
        let key_country = data.len();
        data.extend(string("country"));
        data.extend(bytes(2100));
        let continent = data.len();
        data.extend(map(&[(key("code"), string("EU"))]));
        data.extend(bytes(530_000));
        let city = data.len();
        data.extend(map(&[(
            key("names"),
            map(&[
                (key("en"), string("Antwerp")),
                (key("de"), string("Antwerpen")),
            ]),
        )]));
        let postal = data.len();
        data.extend(map(&[(key("code"), string("2000"))]));
        assert!(continent >= 2048 && city >= 526_336);

        let first = data.len();
        data.extend(map(&[
            (key("country"), pointer(0, country_be)),
            (key("continent"), pointer(1, continent)),
            (key("city"), pointer(2, city)),
            (key("postal"), pointer(3, postal)),
            (
                key("location"),
                map(&[
                    (key("latitude"), double(51.2194)),
                    (key("longitude"), double(4.4025)),
                    (key("accuracy_radius"), uint(5, 20)),
                ]),
            ),
            (
                key("subdivisions"),
                array(&[map(&[(key("iso_code"), string("VLG"))])]),
            ),
            (key("autonomous_system_number"), uint(6, 5432)),
        ]));
        let second = data.len();
        // a map key reached through a pointer
        data.extend(map(&[(
            pointer(0, key_country),
            map(&[(key("iso_code"), string("NL"))]),
        )]));

        let networks = [
            (path(version, "1.0.0.0/8".parse().unwrap()), first),
            (path(version, "2.3.0.0/16".parse().unwrap()), second),
            (path(version, "200.1.2.0/24".parse().unwrap()), first),
        ];
        let (tree, node_count) = tree(record, &networks);
        let metadata = map(&[
            (key("node_count"), uint(6, u64::from(node_count))),
            (key("record_size"), uint(5, u64::from(record.bits()))),
            (key("ip_version"), uint(5, u64::from(version.number()))),
            (key("database_type"), string("Handmade-City")),
            (key("languages"), array(&[string("en"), string("de")])),
            (key("binary_format_major_version"), uint(5, 2)),
            (key("binary_format_minor_version"), uint(5, 0)),
            (key("build_epoch"), uint(9, 1_700_000_000)),
        ]);

        let mut out = tree;
        out.extend([0u8; 16]);
        out.extend(data);
        out.extend(METADATA_MARKER);
        out.extend(metadata);
        out
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "the fixture is larger than miri runs in reasonable time"
)]
fn record_sizes_and_pointer_encodings_match_memory_reader() {
    let ips: Vec<IpAddr> = [
        "1.2.3.4",
        "1.255.0.1",
        "2.3.4.5",
        "2.4.0.1",
        "200.1.2.3",
        "200.1.3.3",
        "9.9.9.9",
    ]
    .map(|ip| ip.parse().unwrap())
    .into();
    for record in [RecordSize::Bits24, RecordSize::Bits28, RecordSize::Bits32] {
        for version in [IpVersion::V4, IpVersion::V6] {
            let bytes = handmade::database(record, version);
            let memory = MmdbReader::from_bytes(bytes.clone()).unwrap();
            assert_eq!(memory.metadata().record_size, record);
            let expected = reference(&bytes, &ips);

            let first = expected[0].as_ref().unwrap();
            assert_eq!(first.country, Some(Country::Belgium));
            assert_eq!(first.continent.as_ref().map(|c| c.code()), Some("EU"));
            assert_eq!(first.city.as_deref(), Some("Antwerp"));
            assert_eq!(first.postal_code.as_deref(), Some("2000"));
            assert_eq!(first.subdivisions[0].iso_code.as_deref(), Some("VLG"));
            assert_eq!(
                first.location.as_ref().unwrap().accuracy_radius_km,
                Some(20)
            );
            assert_eq!(
                first
                    .autonomous_system
                    .as_ref()
                    .unwrap()
                    .asn
                    .unwrap()
                    .as_u32(),
                5432
            );
            let second = expected[2].as_ref().unwrap();
            assert_eq!(second.country, Some(Country::Netherlands));
            assert!(expected[3].is_none());
            assert_eq!(&expected[4], &expected[0]);
            assert!(expected[6].is_none());

            for config in configs() {
                let reader = MmdbFileReader::from_read_at(bytes.clone(), config).unwrap();
                let got: Vec<_> = ips.iter().map(|&ip| reader.lookup(ip)).collect();
                assert_eq!(got, expected, "{record:?} {version:?}");
            }
            let de = MmdbFileReader::from_read_at(bytes, MmdbFileConfig::default())
                .unwrap()
                .with_language("de");
            assert_eq!(
                de.lookup(ips[0]).unwrap().city.as_deref(),
                Some("Antwerpen")
            );
        }
    }
}

#[test]
fn vec_source_recordless_database() {
    let bytes = MmdbBuilder::new(IpVersion::V6, "T").build().unwrap();
    for config in configs() {
        let reader = MmdbFileReader::from_read_at(bytes.clone(), config).unwrap();
        for ip in probes() {
            assert!(reader.try_lookup(ip).unwrap().is_none());
        }
    }
}

#[test]
#[cfg_attr(miri, ignore = "file I/O is not supported under miri isolation")]
fn recordless_replacement_reloads() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("db.mmdb");
    fs::write(&path, fixture(0)).unwrap();
    let reader = MmdbFileReader::open_with_config(&path, manual()).unwrap();
    assert_eq!(country_of(&reader, 1), Some(country(0, 1)));

    replace(
        &path,
        &MmdbBuilder::new(IpVersion::V6, "T").build().unwrap(),
    );
    force_check(&reader);
    for ip in probes() {
        assert!(reader.try_lookup(ip).unwrap().is_none());
    }
    assert_eq!(stats(&reader), (1, 1, 0));
}
