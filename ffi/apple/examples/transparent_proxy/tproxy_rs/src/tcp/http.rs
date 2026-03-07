use std::time::Duration;

use rama::{
    Service,
    error::BoxError,
    extensions::ExtensionsMut,
    io::Io,
    net::{
        http::server::peek_http_stream,
        proxy::{StreamBridge, StreamForwardService},
    },
    telemetry::tracing,
};

#[derive(Debug, Clone)]
pub struct OptionalAutoHttpMitmService;

impl<Ingress, Egress> Service<StreamBridge<Ingress, Egress>> for OptionalAutoHttpMitmService
where
    Ingress: Io + Unpin + ExtensionsMut,
    Egress: Io + Unpin + ExtensionsMut,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        StreamBridge {
            left: ingress_stream,
            right: egress_stream,
        }: StreamBridge<Ingress, Egress>,
    ) -> Result<Self::Output, Self::Error> {
        let (maybe_http_version, peek_ingress_stream) =
            peek_http_stream(ingress_stream, Some(Duration::from_mins(2))).await?;

        if let Some(http_version) = maybe_http_version {
            tracing::debug!("detected http version: {http_version:?}");
            // TODO: support RELAY MITM FLOW... in rama in an easy way...
        } else {
            tracing::debug!("no http version detected... foward as non-http traffic (bytes)");
        }

        if let Err(err) = StreamForwardService::default()
            .serve(StreamBridge {
                left: peek_ingress_stream,
                right: egress_stream,
            })
            .await
        {
            tracing::debug!(
                "failed to relay maybe HTTP traffic (TODO: only do this for non-http traffic): {err}"
            );
        }

        Ok(())
    }
}
