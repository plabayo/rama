use super::GracefulTcpStream;

use crate::core::transport::tcp::server::{Error, Result};

pub async fn echo(stream: GracefulTcpStream) -> Result<()> {
    let (mut stream, token) = stream.into_inner();
    let (mut reader, mut writer) = stream.split();
    tokio::select! {
        _ = token.shutdown() => Err(Error::Interupt),
        res = tokio::io::copy(&mut reader, &mut writer) => match res {
            Ok(_) => Ok(()),
            Err(err) => Err(Error::IO(err)),
        },
    }?;
    Ok(())
}
