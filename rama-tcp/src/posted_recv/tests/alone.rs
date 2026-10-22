//! Tests that read process-wide state run in a child of this test binary, so no
//! other test shares their process whichever test runner started them.

use std::process::Command;

/// Marks the child that runs the test body.
const CHILD: &str = "RAMA_TCP_TEST_ALONE";

/// Whether the caller is the child that runs the test body. Otherwise this runs
/// `module::test` alone in a child and fails with it.
pub(super) fn in_own_process(module: &str, test: &str) -> bool {
    if std::env::var_os(CHILD).is_some() {
        return true;
    }
    // libtest names a test by its module path without the crate.
    let module = module.split_once("::").map_or("", |(_, path)| path);
    let name = format!("{module}::{test}");
    let output = Command::new(std::env::current_exe().expect("this test binary's path"))
        .args(["--exact", &name, "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .output()
        .expect("this test binary starts again");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // A name that selects nothing would pass without testing anything.
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed"),
        "{name} in its own process: {}\nstdout:\n{stdout}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    false
}
