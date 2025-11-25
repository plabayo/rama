use rama::{
    Service,
    error::{BoxError, ErrorContext, OpaqueError},
    extensions::Extensions,
    http::{
        Request, Response,
        headers::SecWebSocketProtocol,
        ws::handshake::client::{ClientWebSocket, HttpClientWebSocketExt},
    },
};

pub(super) async fn connect<C>(
    req: Request,
    client: C,
    protocols: Option<Vec<String>>,
) -> Result<ClientWebSocket, OpaqueError>
where
    C: Service<Request, Response = Response, Error = BoxError>,
{
    let mut builder = client.websocket_with_request(req);

    if let Some(mut protocols) = protocols.map(|p| p.into_iter())
        && let Some(first_protocol) = protocols.next()
    {
        builder.set_protocols(
            SecWebSocketProtocol::new(first_protocol).with_additional_protocols(protocols),
        );
    }

    builder
        .with_per_message_deflate_overwrite_extensions()
        .handshake(Extensions::default())
        .await
        .context("establish WS(S) connection")
}
