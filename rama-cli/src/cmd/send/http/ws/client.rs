use rama::{
    Service,
    error::{BoxError, ErrorContext},
    extensions::Extensions,
    http::{
        Request, Response,
        headers::SecWebSocketProtocol,
        ws::handshake::client::{ClientWebSocket, HttpClientWebSocketExt},
    },
    utils::{collections::NonEmptySmallVec, str::NonEmptyStr},
};

pub(super) async fn connect<C>(
    req: Request,
    client: C,
    protocols: Option<NonEmptySmallVec<3, NonEmptyStr>>,
) -> Result<ClientWebSocket, BoxError>
where
    C: Service<Request, Output = Response, Error = BoxError>,
{
    client
        .websocket_with_request(req)
        .maybe_with_protocols(protocols.map(SecWebSocketProtocol))
        .with_per_message_deflate_overwrite_extensions()
        .handshake(Extensions::default())
        .await
        .context("establish WS(S) connection")
}
