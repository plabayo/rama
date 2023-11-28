use std::{io::Error, pin::Pin};

use crate::{service::Service, stream::Stream};

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ForwardService();

impl ForwardService {
    pub fn new() -> Self {
        Self
    }
}

impl<S: Stream> Service<TcpStream<S>> for ForwardService {
    type Response = (u64, u64);
    type Error = Error;

    async fn call(&mut self, stream: TcpStream<S>) -> Result<Self::Response, Self::Error> {
        crate::pin!(source);
        crate::io::copy_bidirectional(&mut source, &mut self.destination).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::rt::test_util::io::Builder;

    #[crate::rt::test(crate = "crate")]
    async fn test_forwarder() {
        let destination = Builder::new()
            .write(b"to(1)")
            .read(b"from(1)")
            .write(b"to(2)")
            .wait(std::time::Duration::from_secs(1))
            .read(b"from(2)")
            .build();
        let stream = Builder::new()
            .read(b"to(1)")
            .write(b"from(1)")
            .read(b"to(2)")
            .write(b"from(2)")
            .build();

        ForwardService::new(destination).call(stream).await.unwrap();
    }
}
