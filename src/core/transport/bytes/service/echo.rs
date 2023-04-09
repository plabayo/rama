use std::io::{Error, ErrorKind, Result};

use crate::core::transport::bytes::ByteStream;
use crate::core::transport::graceful::Graceful;

pub async fn echo<'a>(stream: impl ByteStream + Graceful<'a> + 'a) -> Result<()> {
    let token = stream.token();
    let (mut reader, mut writer) = tokio::io::split(stream);
    tokio::select! {
        _ = token.shutdown() => Err(Error::new(ErrorKind::Interrupted, "graceful shutdown requested")),
        res = tokio::io::copy(&mut reader, &mut writer) => res,
    }?;
    Ok(())
}
