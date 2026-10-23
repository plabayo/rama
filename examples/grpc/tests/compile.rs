#[test]
#[ignore = "slow: compiles a trybuild project"]
fn ui() {
    let t = trybuild::TestCases::new();
    t.pass("tests/compile/*.rs");
}
