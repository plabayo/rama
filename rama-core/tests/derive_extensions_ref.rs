// The `.stderr` snapshots track stable rustc; beta and nightly render diagnostics differently.
#[rustversion::stable]
#[ignore = "slow: compiles a trybuild project"]
#[test]
fn derive_extensions_ref() {
    let t = trybuild::TestCases::new();
    t.pass("tests/derive_extensions_ref/pass/*.rs");
    t.compile_fail("tests/derive_extensions_ref/fail/*.rs");
}
