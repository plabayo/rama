use std::io::{Error, ErrorKind, Result};

use crate::transport::{bytes::ByteStream, connection::Connection};

pub async fn echo<T, B>(conn: Connection<B, T>) -> Result<()>
where
    B: ByteStream,
{
    let (socket, token, _) = conn.into_parts();
    let (mut reader, mut writer) = tokio::io::split(socket);
    tokio::select! {
        _ = token.shutdown() => Err(Error::new(ErrorKind::Interrupted, "graceful shutdown requested")),
        res = tokio::io::copy(&mut reader, &mut writer) => res.map(|_| ()),
    }
}
