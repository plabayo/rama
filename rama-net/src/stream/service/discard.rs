use rama_core::{
    Service,
    error::{BoxError, ErrorContext as _},
    stream::Stream,
};

/// An async service which discard all the incoming bytes,
/// and sents no response back.
///
/// This service is often used when accepting TCP or UDP
/// services on port `9`, as an implementation of [RFC 863].
///
/// [RFC 863]: https://datatracker.ietf.org/doc/html/rfc863
///
/// ## TCP Based Discard Service
///
/// One discard service is defined as a connection based application on
/// TCP. A server listens for TCP connections on TCP port `9`. Once a
/// connection is established any data received is thrown away. No
/// response is sent. This continues until the calling user terminates
/// the connection.
///
/// ## UDP Based Discard Service
///
/// Another discard service is defined as a datagram based application on
/// UDP. A server listens for UDP datagrams on UDP port `9`. When a
/// datagram is received, it is thrown away. No response is sent.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DiscardService;

impl DiscardService {
    /// Creates a new [`DiscardService`],
    #[must_use]
    #[inline(always)]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for DiscardService {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Service<S> for DiscardService
where
    S: Stream + 'static,
{
    type Output = u64;
    type Error = BoxError;

    async fn serve(&self, stream: S) -> Result<Self::Output, Self::Error> {
        let (mut reader, _) = tokio::io::split(stream);
        let mut writer = tokio::io::empty();
        tokio::io::copy(&mut reader, &mut writer)
            .await
            .into_box_error()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test_echo() {
        let stream = Builder::new().read(b"one").read(b"two").build();

        DiscardService::new().serve(stream).await.unwrap();
    }
}
