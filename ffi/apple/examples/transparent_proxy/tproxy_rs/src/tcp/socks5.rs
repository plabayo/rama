use std::time::Duration;

use rama::{
    Service,
    error::{BoxError, ErrorContext as _},
    net::proxy::{ProxyRequest, ProxyTarget, StreamForwardService},
    proxy::socks5::proxy::mitm::{Socks5MitmHandshakeOutcome, Socks5MitmRelay},
    rt::Executor,
    stream::Stream,
    telemetry::tracing,
};

use crate::utils::executor_from_input;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub(super) struct Socks5IngressService;

impl Socks5IngressService {
    #[inline(always)]
    pub(super) fn new() -> Self {
        Self
    }
}

impl<S> Service<S> for Socks5IngressService
where
    S: Stream + Unpin + rama::extensions::ExtensionsMut,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, mut input: S) -> Result<Self::Output, Self::Error> {
        let Some(ProxyTarget(socks5_proxy_address)) = input.extensions().get().cloned() else {
            tracing::warn!(
                "failed to find socks5 proxy address in input... this is unexpected (rama NE bridge bug!?)"
            );
            return Err(BoxError::from(
                "missing socks5 proxy address (ProxyTarget ext)",
            ));
        };

        let exec = executor_from_input(&input);
        let socks5_relay = Socks5MitmRelay::default();
        match socks5_relay
            .handshake(&mut input, exec, socks5_proxy_address)
            .await?
        {
            Socks5MitmHandshakeOutcome::UnsupportedFlow(egress_stream) => {
                let proxy_req = ProxyRequest {
                    source: input,
                    target: egress_stream,
                };
                if let Err(err) = StreamForwardService::default().serve(proxy_req).await {
                    tracing::debug!(
                        "failed to L4-relay TCP traffic (not compatible with SOCKS5 intercept flow): {err}"
                    );
                }
            }
            Socks5MitmHandshakeOutcome::ContinueInspection(egress_stream) => {
                // TODO: continue inspection flow instead of relay...
                let proxy_req = ProxyRequest {
                    source: input,
                    target: egress_stream,
                };
                if let Err(err) = StreamForwardService::default().serve(proxy_req).await {
                    tracing::debug!(
                        "failed to L4-relay TCP traffic (not compatible with SOCKS5 intercept flow): {err}"
                    );
                }
            }
        }

        Ok(())
    }
}
