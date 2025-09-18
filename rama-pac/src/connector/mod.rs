use crate::{pac_fetcher::fetch_pac, pac_parser::parse_pac_file};
use rama_core::{Context, Service, error::BoxError};
use rama_http::{Uri, service::client::HttpClientExt};
use rama_net::{
    client::{ConnectorService, EstablishedClientConnection},
    stream::{Socket, Stream},
};
use std::fmt::Debug;

pub struct PACConnector<S, W> {
    pub service: S,
    pub web_client: W,
    pub pac_uri: Uri,
}

impl<S, W> PACConnector<S, W>
where
    W: HttpClientExt + Send + Sync + 'static,
{
    pub fn new(service: S, web_client: W, pac_uri: Uri) -> Self {
        Self {
            service,
            web_client,
            pac_uri,
        }
    }
}

impl<S, W, Request> Service<Request> for PACConnector<S, W>
where
    S: ConnectorService<Request, Connection: Stream + Socket + Unpin, Error: Into<BoxError>>
        + Send
        + Sync
        + 'static,
    W: HttpClientExt + Send + Sync + 'static,
    Request: Send + 'static,
    <W as HttpClientExt>::ExecuteResponse: Into<String>,
    <W as HttpClientExt>::ExecuteError: Debug
{
    type Response = EstablishedClientConnection<S::Connection, Request>;
    type Error = BoxError;

    async fn serve(&self, ctx: Context, req: Request) -> Result<Self::Response, Self::Error> {
        // first get the pac file
        let pac_file = fetch_pac(&self.web_client, self.pac_uri.clone())
            .await
            .unwrap();

        // parse and get back result for the uri form the pac file
        let proxy_options = parse_pac_file(&pac_file);

        // based on the result, either connect to the uri or return error
        // Ok(self.service.connect(ctx, req).await.unwrap())
    }
}
