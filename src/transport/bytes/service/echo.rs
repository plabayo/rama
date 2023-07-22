use std::io::{Error, ErrorKind};

use tower_async::Service;

use crate::transport::{bytes::ByteStream, connection::Connection};

/// Creates an async service which echoes the incoming bytes back on the same connection,
/// and which respects the graceful shutdown, by shutting down the connection when requested.
pub fn echo_service<B, T>() -> impl Service<Connection<B, T>>
where
    B: ByteStream,
{
    crate::transport::connection::service_fn(|conn: Connection<B, T>| async {
        let (socket, token, _) = conn.into_parts();
        let (mut reader, mut writer) = tokio::io::split(socket);
        tokio::select! {
            _ = token.shutdown() => Err(Error::new(ErrorKind::Interrupted, "echo: graceful shutdown requested")),
            res = tokio::io::copy(&mut reader, &mut writer) => res,
        }
    })
}

/// Creates an async service which echoes the incoming bytes back on the same connection,
/// and which does not respect the graceful shutdown, by not shutting down the connection when requested,
/// and instead keeps echoing bytes until the connection is closed or other error.
pub fn echo_service_ungraceful<B, T>() -> impl Service<Connection<B, T>>
where
    B: ByteStream,
{
    crate::transport::connection::service_fn(|stream: B| async {
        let (mut reader, mut writer) = tokio::io::split(stream);
        tokio::io::copy(&mut reader, &mut writer).await
    })
}
