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
async fn test_send_file_no_authority_form_reads_local_file() {
    utils::init_tracing();

    let suffix: u64 = rand::random();
    let path = std::env::temp_dir().join(format!("rama-send-file-noauth-{suffix}.txt"));
    let body = b"no authority form\n";
    {
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body).unwrap();
        f.sync_all().unwrap();
    }
    let _cleanup = TempPath(path.clone());

    // RFC 8089 `file:/path`: must read the file, not GET http://file/path
    let uri = format!("file:{}", path.display());
    let (ok, stdout, stderr) =
        utils::RamaService::run_capture(&["send", uri.as_str()]).expect("spawn rama send");
    assert!(ok, "rama send file:/... failed; stderr:\n{stderr}");
    assert_eq!(
        stdout.as_bytes(),
        body,
        "stdout mismatch; stderr:\n{stderr}"
    );
}

#[tokio::test]
#[ignore]
async fn test_send_file_remote_authority_errors() {
    utils::init_tracing();

    let suffix: u64 = rand::random();
    let path = std::env::temp_dir().join(format!("rama-send-file-authority-{suffix}.txt"));
    let body = "local file behind a remote authority\n";
    {
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        f.sync_all().unwrap();
    }
    let _cleanup = TempPath(path.clone());

    // RFC 8089 §2: the authority names another machine, so this path is
    // theirs — it must never be served from our own filesystem
    let uri = format!("file://fileserver.corp{}", path.display());
    let (ok, stdout, stderr) =
        utils::RamaService::run_capture(&["send", uri.as_str()]).expect("spawn rama send");
    assert!(
        !ok,
        "a non-local file:// authority should exit non-zero; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains(body),
        "the local file must not be served; stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("non-local host"),
        "stderr should explain the authority is not local, got:\n{stderr}"
    );
}

#[tokio::test]
#[ignore]
async fn test_send_file_localhost_authority_reads_local_file() {
    utils::init_tracing();

    let suffix: u64 = rand::random();
    let path = std::env::temp_dir().join(format!("rama-send-file-localhost-{suffix}.txt"));
    let body = b"localhost authority form\n";
    {
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body).unwrap();
        f.sync_all().unwrap();
    }
    let _cleanup = TempPath(path.clone());

    // RFC 8089 §2: `localhost` is the other spelling of the local host
    let uri = format!("file://localhost{}", path.display());
    let (ok, stdout, stderr) =
        utils::RamaService::run_capture(&["send", uri.as_str()]).expect("spawn rama send");
    assert!(
        ok,
        "rama send file://localhost/... failed; stderr:\n{stderr}"
    );
    assert_eq!(
        stdout.as_bytes(),
        body,
        "stdout mismatch; stderr:\n{stderr}"
    );
}

#[tokio::test]
#[ignore]
async fn test_send_file_directory_errors() {
    utils::init_tracing();

    let uri = format!("file://{}", std::env::temp_dir().display());
    let (ok, stdout, stderr) =
        utils::RamaService::run_capture(&["send", uri.as_str()]).expect("spawn rama send");
    assert!(!ok, "a directory should exit non-zero; stdout:\n{stdout}");
    assert!(
        stderr.contains("regular file"),
        "stderr should explain it is not a regular file, got:\n{stderr}"
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
    assert!(
        stderr.contains("open file") && stderr.contains(&path),
        "stderr should name the file it could not open, got:\n{stderr}"
    );
    assert!(
        !stderr.contains(r#"path="\""#),
        "path field should not contain nested debug quotes, got:\n{stderr}"
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
