//! Exercise `rama pac eval` through its executable.

use std::{
    error::Error,
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const DEADLINE: Duration = Duration::from_secs(60);
const SOURCE: &str = "function FindProxyForURL() { return 'DIRECT'; }";

// Batch mode also reads piped stdin URIs, so stdin is closed to keep the run independent of the harness.
fn pac_eval(uris: &[&str]) -> TestResult<Output> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rama"))
        .args([
            "pac",
            "eval",
            "--offline",
            "--format",
            "jsonl",
            "--source",
            SOURCE,
        ])
        .args(uris)
        .env("RUST_LOG", "off")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let started = Instant::now();
    // Output stays far below the pipe buffer, so polling cannot block the child.
    while child.try_wait()?.is_none() {
        if started.elapsed() > DEADLINE {
            child.kill()?;
            return Err(format!("rama pac eval did not finish within {DEADLINE:?}").into());
        }
        thread::sleep(Duration::from_millis(20));
    }
    Ok(child.wait_with_output()?)
}

#[test]
fn command_runner_succeeds_only_when_every_evaluation_succeeds() -> TestResult {
    let output = pac_eval(&["https://valid.example/"])?;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    assert!(
        output.status.success(),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("\"directives\":\"DIRECT\""), "{stdout}");

    let output = pac_eval(&["mailto:first@example.com", "urn:second"])?;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stderr.contains("PAC evaluations failed"), "{stderr}");
    assert_eq!(stdout.matches("\"error\":").count(), 2, "{stdout}");
    Ok(())
}
