#[test]
#[ignore]
fn ui() {
    let t = trybuild::TestCases::new();
    t.pass("tests/compile/*.rs");
}
