use rama::{
    Layer, Service,
    http::{
        Request, Response,
        ws::handshake::mitm::{WebSocketRelayDirection, WebSocketRelayInput},
    },
    telemetry::tracing,
};

#[derive(Debug, Clone, Default)]
pub struct DemoTraceTrafficLayer;

impl<S> Layer<S> for DemoTraceTrafficLayer {
    type Service = DemoTraceTrafficService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DemoTraceTrafficService(inner)
    }
}

#[derive(Debug, Clone)]
pub struct DemoTraceTrafficService<S>(S);

impl<S> Service<WebSocketRelayInput> for DemoTraceTrafficService<S>
where
    S: Service<WebSocketRelayInput>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: WebSocketRelayInput) -> Result<Self::Output, Self::Error> {
        let direction = input.direction;
        tracing::debug!(
            "demo traffic logger: relay {} WS msg: {:?}",
            match direction {
                WebSocketRelayDirection::Ingress => "[client->server]",
                WebSocketRelayDirection::Egress => "[server->client]",
            },
            input.message,
        );

        let result = self.0.serve(input).await;

        tracing::debug!(
            "demo traffic logger: relay {} WS msg: reply = {}",
            match direction {
                WebSocketRelayDirection::Ingress => "[client->server]",
                WebSocketRelayDirection::Egress => "[server->client]",
            },
            match result {
                Ok(_) => "ok",
                Err(_) => "err",
            },
        );

        result
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for DemoTraceTrafficService<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let method = req.method().clone();
        let uri = req.uri().clone();
        tracing::debug!("demo traffic logger: http ingress: {method} {uri}: request",);

        let result = self.0.serve(req).await;

        if let Ok(res) = result.as_ref() {
            tracing::debug!(
                "demo traffic logger: http egress: {method} {uri}: response status = {}",
                res.status(),
            );
        } else {
            tracing::debug!("demo traffic logger: http egress: {method} {uri}: error");
        }

        result
    }
}
