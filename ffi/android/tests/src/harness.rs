//! A minimal test runner reporting in `cargo test` style.

use std::panic::{AssertUnwindSafe, catch_unwind};

/// A named test: `Err` or a panic fails it.
pub(crate) type Test = (&'static str, fn() -> Result<(), String>);

/// Run every test whose `suite::test` name contains `filter`, returning the
/// number of failures. Selecting no test at all is a failure too.
pub(crate) fn run(suites: &[(&str, &[Test])], filter: &str) -> i32 {
    let (mut passed, mut failed) = (0, 0);
    for (suite, tests) in suites {
        for (name, test) in *tests {
            let name = format!("{suite}::{name}");
            if !name.contains(filter) {
                continue;
            }
            match catch_unwind(AssertUnwindSafe(test)) {
                Ok(Ok(())) => {
                    passed += 1;
                    println!("test {name} ... ok");
                }
                Ok(Err(reason)) => {
                    failed += 1;
                    println!("test {name} ... FAILED: {reason}");
                }
                Err(_) => {
                    failed += 1;
                    println!("test {name} ... FAILED: panicked");
                }
            }
        }
    }
    if passed + failed == 0 {
        println!("no test matches {filter:?}");
        return 1;
    }
    println!("test result: {passed} passed; {failed} failed");
    failed
}

/// Fail with `message` unless `condition` holds.
pub(crate) fn ensure(condition: bool, message: impl Into<String>) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
