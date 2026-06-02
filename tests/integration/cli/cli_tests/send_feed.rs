//! E2E tests for the web client's feed handling.
//!
//! The interactive RSS/Atom reader only engages when stdout is a real
//! terminal. These tests run the binary with its output captured (a pipe, not
//! a TTY), so they assert the *non-interactive* contract: a feed response is
//! written to stdout verbatim and the reader never takes over. That is the
//! important regression guard — piping or redirecting a feed must keep
//! behaving like curl. The reader's rendering itself is covered by unit tests
//! in `rama-cli` using ratatui's `TestBackend`.

use super::utils;
use std::path::PathBuf;

#[tokio::test]
#[ignore]
async fn test_send_rss_feed_piped_is_raw_not_tui() {
    utils::init_tracing();

    let _guard = utils::RamaService::serve_fs(63140, Some(PathBuf::from("test-files")));

    let (ok, stdout, stderr) =
        utils::RamaService::run_capture(&["-k", "https://127.0.0.1:63140/feed.xml"])
            .expect("spawn rama send");
    assert!(ok, "rama send failed; stderr:\n{stderr}");

    // Output is a pipe, not a terminal: the body must be the raw feed.
    assert!(
        stdout.contains("<rss"),
        "expected raw rss in stdout, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Rust Insights"),
        "expected feed title in raw output, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Async streams explained"),
        "expected entry title in raw output, got:\n{stdout}"
    );
    // The reader must not have engaged: no alternate-screen / raw-mode escapes.
    assert!(
        !stdout.contains('\u{1b}'),
        "terminal escape sequence leaked into piped output:\n{stdout:?}"
    );
}

#[tokio::test]
#[ignore]
async fn test_send_atom_feed_piped_is_raw_not_tui() {
    utils::init_tracing();

    let _guard = utils::RamaService::serve_fs(63141, Some(PathBuf::from("test-files")));

    let (ok, stdout, stderr) =
        utils::RamaService::run_capture(&["-k", "https://127.0.0.1:63141/atom.xml"])
            .expect("spawn rama send");
    assert!(ok, "rama send failed; stderr:\n{stderr}");

    assert!(
        stdout.contains("<feed"),
        "expected raw atom in stdout, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Atomic Notes"),
        "expected feed title in raw output, got:\n{stdout}"
    );
    assert!(
        !stdout.contains('\u{1b}'),
        "terminal escape sequence leaked into piped output:\n{stdout:?}"
    );
}
