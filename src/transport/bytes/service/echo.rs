use std::io::{Error, ErrorKind, Result};

use tower_async::Service;

use crate::transport::{bytes::ByteStream, connection::Connection};

async fn echo<T, B>(conn: Connection<B, T>) -> Result<u64>
where
    B: ByteStream,
{
    let (socket, token, _) = conn.into_parts();
    let (mut reader, mut writer) = tokio::io::split(socket);
    tokio::select! {
        _ = token.shutdown() => Err(Error::new(ErrorKind::Interrupted, "echo: graceful shutdown requested")),
        res = tokio::io::copy(&mut reader, &mut writer) => res,
    }
}

/// Crates an async service which echoes the incoming bytes back on the same connection.
pub fn echo_service<T, B>() -> impl Service<Connection<B, T>>
where
    B: ByteStream,
{
    crate::transport::connection::service_fn(echo)
}
