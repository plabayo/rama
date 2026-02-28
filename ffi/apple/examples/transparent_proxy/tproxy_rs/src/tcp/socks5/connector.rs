use rama::{
    Service,
    error::BoxError,
    extensions::ExtensionsMut,
    net::{Protocol, address::ProxyAddress, proxy::ProxyTarget},
    stream::Stream,
};

use crate::tcp::socks5::auth::IngressProxyCredentials;

#[derive(Debug, Clone)]
pub struct Socks5ConnectAcceptor<StreamService>(pub StreamService);

impl<S, StreamService> Service<S> for Socks5ConnectAcceptor<StreamService>
where
    S: Stream + Unpin + ExtensionsMut,
    StreamService: Service<S, Output = (), Error: Into<BoxError>>,
{
    type Output = StreamService::Output;
    type Error = StreamService::Error;

    async fn serve(&self, mut input: S) -> Result<Self::Output, Self::Error> {
        if let Some(ProxyTarget(target)) = input.extensions().get().cloned() {
            let credential = input
                .extensions()
                .get::<IngressProxyCredentials>()
                .map(|c| c.0.clone());

            input.extensions_mut().insert(ProxyAddress {
                protocol: Some(Protocol::SOCKS5),
                address: target,
                credential,
            });
        }

        self.0.serve(input).await
    }
}
