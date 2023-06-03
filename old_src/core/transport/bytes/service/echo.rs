use std::io::{Error, ErrorKind, Result};

use crate::core::transport::{bytes::ByteStream, graceful::Token};

pub async fn echo(stream: impl ByteStream, token: Token) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    tokio::select! {
        _ = token.shutdown() => Err(Error::new(ErrorKind::Interrupted, "graceful shutdown requested")),
        res = tokio::io::copy(&mut reader, &mut writer) => res,
    }?;
    Ok(())
}
