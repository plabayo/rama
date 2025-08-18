#[test]
fn include_dir_no_compile() {
    // paths are normalized on windows
    // which makes it return different error types
    // TODO: add windows version as part of <https://github.com/plabayo/rama/issues/666>
    #[cfg(not(target_os = "windows"))]
    {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/include_dir_no_compile/*.rs");
    }
}
