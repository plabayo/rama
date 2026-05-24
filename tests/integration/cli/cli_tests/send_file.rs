//! E2E tests for `rama send file://...` — the local-filesystem
//! transport that mirrors curl's `file:` behavior.

use super::utils;
use std::io::Write;

#[tokio::test]
#[ignore]
async fn test_send_file_streams_contents_to_stdout() {
    utils::init_tracing();

    // Fixture: write a known body to a temp file. Using `env::temp_dir`
    // keeps the path predictable across platforms; the random suffix
    // avoids collisions between parallel CI runs.
    let suffix: u64 = rand::random();
    let path = std::env::temp_dir().join(format!("rama-send-file-test-{suffix}.txt"));
    let body = b"hello rama file scheme\n";
    {
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body).unwrap();
        f.sync_all().unwrap();
    }
    let _cleanup = TempPath(path.clone());

    let uri = format!("file://{}", path.display());
    let (ok, stdout, stderr) =
        utils::RamaService::run_capture(&["send", uri.as_str()]).expect("spawn rama send");
    assert!(ok, "rama send file:// failed; stderr:\n{stderr}");
    assert_eq!(
        stdout.as_bytes(),
        body,
        "stdout mismatch; stderr:\n{stderr}"
    );
}

#[tokio::test]
#[ignore]
async fn test_send_file_missing_errors() {
    utils::init_tracing();

    let suffix: u64 = rand::random();
    let path = std::env::temp_dir()
        .join(format!("rama-send-file-missing-{suffix}.txt"))
        .display()
        .to_string();
    let uri = format!("file://{path}");

    let (ok, _stdout, stderr) =
        utils::RamaService::run_capture(&["send", uri.as_str()]).expect("spawn rama send");
    assert!(!ok, "missing file:// should exit non-zero");
    // curl-equivalent diagnostic — wording from the file handler.
    assert!(
        stderr.contains("Couldn't open file"),
        "stderr should mention 'Couldn't open file', got:\n{stderr}"
    );
}

/// Drop guard that removes a temp file. Best-effort; ignores errors so
/// a test that already panicked doesn't double-panic on cleanup.
struct TempPath(std::path::PathBuf);
impl Drop for TempPath {
    fn drop(&mut self) {
        // Best-effort cleanup; ignore the Result so a test that already
        // panicked doesn't double-panic on cleanup.
        if let Err(err) = std::fs::remove_file(&self.0) {
            eprintln!("test cleanup: failed to remove temp file: {err}");
        }
    }
}
