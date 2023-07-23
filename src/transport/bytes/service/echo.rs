use std::io::{Error, ErrorKind};

use tower_async::Service;

use crate::transport::{bytes::ByteStream, connection::Connection};

/// An async service which echoes the incoming bytes back on the same connection.
///
/// # Example
///
/// ```rust
/// use tower_async::Service;
/// use rama::transport::bytes::service::EchoService;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let stream = tokio_test::io::Builder::new().read(b"hello world").write(b"hello world").build();
/// # let conn = rama::transport::connection::Connection::new(stream, rama::transport::graceful::Token::pending(), ());
/// let mut service = EchoService::new()
///     .respect_shutdown(Some(std::time::Duration::from_secs(5)));
///
/// let bytes_copied = service.call(conn).await?;
/// # assert_eq!(bytes_copied, 11);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct EchoService {
    respect_shutdown: bool,
    shutdown_delay: Option<std::time::Duration>,
}

impl EchoService {
    /// Creates a new [`EchoService`],
    pub fn new() -> Self {
        Self {
            respect_shutdown: false,
            shutdown_delay: None,
        }
    }

    /// Enable the option that this service will stop its work
    /// as soon as the graceful shutdown is requested, optionally with
    /// a a delay to give the actual work some time to finish.
    pub fn respect_shutdown(mut self, delay: Option<std::time::Duration>) -> Self {
        self.respect_shutdown = true;
        self.shutdown_delay = delay;
        self
    }
}

impl Default for EchoService {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, S> Service<Connection<S, T>> for EchoService
where
    S: ByteStream,
{
    type Response = u64;
    type Error = Error;

    async fn call(&mut self, conn: Connection<S, T>) -> Result<Self::Response, Self::Error> {
        let (stream, token, _) = conn.into_parts();
        let (mut reader, mut writer) = tokio::io::split(stream);
        if self.respect_shutdown {
            if let Some(delay) = self.shutdown_delay {
                let wait_for_shutdown = async {
                    token.shutdown().await;
                    tokio::time::sleep(delay).await;
                };
                tokio::select! {
                    _ = wait_for_shutdown => Err(Error::new(ErrorKind::Interrupted, "echo: graceful shutdown requested and delay expired")),
                    res = tokio::io::copy(&mut reader, &mut writer) => res,
                }
            } else {
                tokio::select! {
                    _ = token.shutdown() => Err(Error::new(ErrorKind::Interrupted, "echo: graceful shutdown requested")),
                    res = tokio::io::copy(&mut reader, &mut writer) => res,
                }
            }
        } else {
            tokio::io::copy(&mut reader, &mut writer).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test_echo_no_respect_shutdown() {
        let stream = Builder::new()
            .read(b"one")
            .write(b"one")
            .read(b"two")
            .write(b"two")
            .build();

        let graceful_service = crate::transport::graceful::service(tokio::time::sleep(
            std::time::Duration::from_millis(200),
        ));

        let conn = Connection::new(stream, graceful_service.token(), ());

        EchoService::new().call(conn).await.unwrap();

        graceful_service.shutdown().await;
    }

    #[tokio::test]
    #[should_panic(expected = "There is still data left to write.")]
    async fn test_echo_respect_shutdown_instant() {
        let stream = Builder::new()
            .read(b"one")
            .write(b"one")
            .read(b"two")
            .wait(std::time::Duration::from_millis(500))
            .write(b"two")
            .build();

        let graceful_service = crate::transport::graceful::service(tokio::time::sleep(
            std::time::Duration::from_millis(200),
        ));

        let conn = Connection::new(stream, graceful_service.token(), ());

        assert!(EchoService::new()
            .respect_shutdown(None)
            .call(conn)
            .await
            .is_err());

        graceful_service.shutdown().await;
    }

    #[tokio::test]
    async fn test_echo_respect_shutdown_with_delay() {
        let stream = Builder::new()
            .read(b"one")
            .write(b"one")
            .read(b"two")
            .wait(std::time::Duration::from_millis(500))
            .write(b"two")
            .build();

        let graceful_service = crate::transport::graceful::service(tokio::time::sleep(
            std::time::Duration::from_millis(200),
        ));

        let conn = Connection::new(stream, graceful_service.token(), ());

        EchoService::new()
            .respect_shutdown(Some(std::time::Duration::from_secs(1)))
            .call(conn)
            .await
            .unwrap();

        graceful_service.shutdown().await;
    }

    #[tokio::test]
    #[should_panic(expected = "There is still data left to write.")]
    async fn test_echo_respect_shutdown_with_delay_partial_error() {
        let stream = Builder::new()
            .read(b"one")
            .write(b"one")
            .read(b"two")
            .write(b"two")
            .read(b"three")
            .wait(std::time::Duration::from_secs(2))
            .write(b"three")
            .build();

        let graceful_service = crate::transport::graceful::service(tokio::time::sleep(
            std::time::Duration::from_millis(250),
        ));

        let conn = Connection::new(stream, graceful_service.token(), ());

        assert!(EchoService::new()
            .respect_shutdown(Some(std::time::Duration::from_millis(500)))
            .call(conn)
            .await
            .is_err());

        graceful_service.shutdown().await;
    }
}
