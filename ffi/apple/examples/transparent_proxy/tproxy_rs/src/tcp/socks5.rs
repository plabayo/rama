use std::time::Duration;

use rama::{
    Service,
    error::{BoxError, ErrorContext as _},
    io::{BridgeIo, Io},
    net::{
        proxy::{IoForwardService, ProxyTarget},
        user::credentials::DpiProxyCredential,
    },
    proxy::socks5::proxy::mitm::{Socks5MitmHandshakeOutcome, Socks5MitmRelay},
    rt::Executor,
    telemetry::tracing,
};

use crate::{
    tcp::{http::OptionalAutoHttpMitmService, tls::OptionalTlsMitmService},
    utils::executor_from_input,
};

#[derive(Debug, Clone)]
#[non_exhaustive]
pub(super) struct Socks5IngressService {
    opt_tls_mitm_svc: OptionalTlsMitmService<OptionalAutoHttpMitmService>,
}

impl Socks5IngressService {
    #[inline(always)]
    pub(super) fn try_new() -> Result<Self, BoxError> {
        let opt_tls_mitm_svc = OptionalTlsMitmService::try_new(OptionalAutoHttpMitmService)?;
        Ok(Self { opt_tls_mitm_svc })
    }
}

impl<S> Service<S> for Socks5IngressService
where
    S: Io + Unpin + rama::extensions::ExtensionsMut,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, mut ingress_stream: S) -> Result<Self::Output, Self::Error> {
        let Some(ProxyTarget(socks5_proxy_address)) = ingress_stream.extensions().get().cloned()
        else {
            tracing::warn!(
                "failed to find socks5 proxy address in (ingress) stream... this is unexpected (rama NE bridge bug!?)"
            );
            return Err(BoxError::from(
                "missing socks5 proxy address (ProxyTarget ext)",
            ));
        };

        let exec = executor_from_input(&ingress_stream);
        let socks5_relay = Socks5MitmRelay::default();
        let (egress_stream, handshake_outcome) = socks5_relay
            .handshake(&mut ingress_stream, exec, socks5_proxy_address)
            .await?;
        match handshake_outcome {
            Socks5MitmHandshakeOutcome::UnsupportedFlow => {
                tracing::debug!("L4-proxy unsupported SOCKS5 flow");

                if let Err(err) = IoForwardService::default()
                    .serve(BridgeIo(ingress_stream, egress_stream))
                    .await
                {
                    tracing::debug!(
                        "failed to L4-relay TCP traffic (not compatible with SOCKS5 intercept flow): {err}"
                    );
                }
            }
            Socks5MitmHandshakeOutcome::ContinueInspection => {
                if let Err(err) = self
                    .opt_tls_mitm_svc
                    .serve(BridgeIo(ingress_stream, egress_stream))
                    .await
                {
                    tracing::debug!("failed to relay optional TLS traffic (over SOCKS5): {err}");
                }
            }
        }

        Ok(())
    }
}
