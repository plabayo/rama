//! ABI smoke coverage for the transparent proxy example static library.
//!
//! These tests exercise the exported C ABI surface without going through a network flow. They are
//! intentionally small and isolate contract regressions from dataplane regressions.

use serial_test::serial;

use super::ffi::ffi_config_has_rules;

#[test]
#[serial]
fn ffi_contract_config_exposes_default_rules() {
    ffi_config_has_rules();
}
