//! `rama inspect` through the binary, the way a user runs it.
//!
//! Without a terminal the command prints its summary instead of opening the
//! viewer, which is exactly what a test (or a pipe) gets.

use std::{
    error::Error,
    path::{Path, PathBuf},
    process::{Command, Output},
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn inspect<S: AsRef<std::ffi::OsStr>>(args: &[S]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_rama"))
        .arg("inspect")
        .args(args)
        .output()?)
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_har_file_opens_with_its_timeline() -> TestResult {
    let output = inspect(&[fixture("example.har")])?;
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let stdout = stdout(&output);
    assert!(stdout.contains("HAR 1.2 · example.har"), "stdout: {stdout}");
    assert!(
        stdout.contains("creator: rama-test 0.5.0"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("connections (3)"), "stdout: {stdout}");
    assert!(
        stdout.contains("https://example.test/index.html  200 OK"),
        "stdout: {stdout}",
    );
    assert!(stdout.contains("401 Unauthorized"), "stdout: {stdout}");
    assert!(stdout.contains("WS →"), "websocket messages: {stdout}");
    Ok(())
}

#[test]
fn a_rama_recorded_qlog_file_opens_with_its_events() -> TestResult {
    let output = inspect(&[fixture("quic.qlog")])?;
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let stdout = stdout(&output);
    assert!(
        stdout.contains("qlog draft-14 (json-seq) · quic.qlog"),
        "stdout: {stdout}",
    );
    assert!(stdout.contains("connection_started"), "stdout: {stdout}");
    assert!(stdout.contains("quic"), "stdout: {stdout}");
    Ok(())
}

#[test]
fn an_explicit_format_overrides_detection() -> TestResult {
    let path = fixture("example.har");
    let output = inspect(&[path.as_os_str(), "--format".as_ref(), "qlog".as_ref()])?;
    assert!(!output.status.success(), "stdout: {}", stdout(&output));
    assert!(
        stderr(&output).contains("not a qlog file"),
        "stderr: {}",
        stderr(&output),
    );
    Ok(())
}

#[test]
fn an_unrecognized_file_is_reported_instead_of_guessed() -> TestResult {
    let dir = rama::utils::fs::TempDir::with_prefix("rama-inspect-test-")?;
    let path = dir.path().join("capture.bin");
    std::fs::write(&path, b"GET / HTTP/1.1\r\nhost: example.test\r\n\r\n")?;

    let output = inspect(&[&path])?;
    assert!(!output.status.success(), "stdout: {}", stdout(&output));
    assert!(
        stderr(&output).contains("unrecognized capture format"),
        "stderr: {}",
        stderr(&output),
    );

    // the extension is enough even when the content is not
    let named = dir.path().join("capture.har");
    std::fs::write(&named, b"not json")?;
    let output = inspect(&[&named])?;
    assert!(
        stderr(&output).contains("parse HAR file"),
        "stderr: {}",
        stderr(&output),
    );
    Ok(())
}

#[test]
fn limits_are_reported_rather_than_silently_truncating() -> TestResult {
    let path = fixture("example.har");
    let output = inspect(&[path.as_os_str(), "--max-records".as_ref(), "1".as_ref()])?;
    assert!(!output.status.success(), "stdout: {}", stdout(&output));
    assert!(
        stderr(&output).contains("HAR entry limit exceeded"),
        "stderr: {}",
        stderr(&output),
    );

    let output = inspect(&[path.as_os_str(), "--max-size".as_ref(), "16".as_ref()])?;
    assert!(!output.status.success(), "stdout: {}", stdout(&output));
    assert!(
        stderr(&output).contains("exceeds --max-size"),
        "stderr: {}",
        stderr(&output),
    );

    let output = inspect(&[
        fixture("quic.qlog").as_os_str(),
        "--max-record-size".as_ref(),
        "32".as_ref(),
    ])?;
    assert!(!output.status.success(), "stdout: {}", stdout(&output));
    assert!(
        stderr(&output).contains("record exceeds the size limit"),
        "stderr: {}",
        stderr(&output),
    );
    Ok(())
}

#[test]
fn a_missing_file_is_reported_with_its_path() -> TestResult {
    let output = inspect(&["/definitely/not/here.har"])?;
    assert!(!output.status.success(), "stdout: {}", stdout(&output));
    assert!(
        stderr(&output).contains("read capture file metadata"),
        "stderr: {}",
        stderr(&output),
    );
    Ok(())
}

#[test]
fn the_help_states_the_supported_formats_and_the_limits() -> TestResult {
    let output = inspect(&["--help"])?;
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let stdout = stdout(&output);
    assert!(stdout.contains("HTTP Archive 1.2"), "stdout: {stdout}");
    assert!(
        stdout.contains("qlog main schema draft 14"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("--max-size"), "stdout: {stdout}");
    assert!(stdout.contains("--max-records"), "stdout: {stdout}");
    assert!(stdout.contains("--max-body"), "stdout: {stdout}");
    Ok(())
}
