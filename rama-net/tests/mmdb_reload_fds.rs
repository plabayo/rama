//! Reloading a positional MaxMind DB reader must not leak file descriptors.
//!
//! Its own test binary, so no other test opens files while fds are counted.

#![cfg(all(feature = "std", any(target_os = "linux", target_os = "macos")))]

use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use ipnet::IpNet;
use rama_core::geo::Country;
use rama_net::address::ip::geo::{
    GeoLocation, IpVersion, MmdbBuilder, MmdbFileConfig, MmdbFileReader,
};

const CYCLES: usize = 200;

#[test]
fn reload_cycles_keep_fd_count_stable() {
    let open_fds = || {
        let dir = if cfg!(target_os = "linux") {
            "/proc/self/fd"
        } else {
            "/dev/fd"
        };
        fs::read_dir(dir).unwrap().count()
    };
    let database = |country: Country| {
        let mut b = MmdbBuilder::new(IpVersion::V4, "Test-Country");
        let net: IpNet = "1.2.3.0/24".parse().unwrap();
        let loc = GeoLocation {
            country: Some(country),
            ..Default::default()
        };
        b.insert(net, &loc).unwrap();
        b.build().unwrap()
    };
    let replace = |path: &Path, bytes: &[u8]| {
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, bytes).unwrap();
        fs::rename(&tmp, path).unwrap();
    };

    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("db.mmdb");
    let countries = [Country::Belgium, Country::Germany];
    fs::write(&path, database(countries[0].clone())).unwrap();
    let ip: IpAddr = "1.2.3.4".parse().unwrap();

    let config = MmdbFileConfig::default().with_check_interval(Duration::ZERO);
    let reader = MmdbFileReader::open_with_config(&path, config).unwrap();
    assert_eq!(reader.lookup(ip).unwrap().country, Some(Country::Belgium));
    let baseline = open_fds();

    for cycle in 1..=CYCLES {
        let country = countries[cycle % 2].clone();
        replace(&path, &database(country.clone()));
        assert_eq!(reader.lookup(ip).unwrap().country, Some(country));
    }
    assert_eq!(open_fds(), baseline);
}
