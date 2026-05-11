//! Small async I/O helpers shared by the FastCGI server and client.

use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Discard exactly `n` bytes from `r` without allocating a per-call buffer.
///
/// Uses [`tokio::io::copy`] piped into [`tokio::io::sink`] via a `take`
/// adaptor, so the implementation reuses a small kernel-buffer-sized scratch
/// allocation rather than allocating `n` bytes up front.
pub(crate) async fn discard_n<R>(r: &mut R, n: u64) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    if n == 0 {
        return Ok(());
    }
    let mut limited = AsyncReadExt::take(r, n);
    let copied = tokio::io::copy(&mut limited, &mut tokio::io::sink()).await?;
    if copied < n {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "fastcgi: unexpected eof while discarding content",
        ));
    }
    Ok(())
}

/// Apply an optional read timeout to `fut`. If `timeout` is `None` the future
/// is awaited as-is. On timeout, returns `io::ErrorKind::TimedOut`.
pub(crate) async fn with_optional_timeout<F, T>(timeout: Option<Duration>, fut: F) -> io::Result<T>
where
    F: std::future::Future<Output = io::Result<T>>,
{
    match timeout {
        Some(d) => match tokio::time::timeout(d, fut).await {
            Ok(res) => res,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "fastcgi: idle timeout while reading record",
            )),
        },
        None => fut.await,
    }
}
