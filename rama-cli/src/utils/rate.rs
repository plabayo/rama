//! rate-related CLI argument helpers

use rama::utils::rate::Rate;

/// Map an optional `--rate`/`--throttle`-style argument to a [`Rate`]:
/// absent or `0` means "no limit".
pub fn opt_per_sec(n: Option<u64>) -> Option<Rate> {
    n.and_then(|n| (n > 0).then(|| Rate::per_sec(n)))
}
