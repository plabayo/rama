// The `.stderr` snapshots track stable rustc; beta and nightly render diagnostics differently.
#[rustversion::stable]
#[ignore = "slow: compiles a trybuild project"]
#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
