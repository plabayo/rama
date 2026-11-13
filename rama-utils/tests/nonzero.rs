#![cfg(not(loom))]

use rama_utils::macros::nonzero;

#[test]
fn nonzero_constants_infer_integer_type() {
    const PATHS: std::num::NonZeroUsize = nonzero!(4);
    const SIGNED: std::num::NonZeroI16 = nonzero!(-2);
    assert_eq!(PATHS.get(), 4);
    assert_eq!(SIGNED.get(), -2);
    assert_eq!(nonzero!(256u32).get(), 256);
}

#[test]
fn nonzero_rejects_zero_and_runtime_values() {
    trybuild::TestCases::new().compile_fail("tests/nonzero/*.rs");
}
