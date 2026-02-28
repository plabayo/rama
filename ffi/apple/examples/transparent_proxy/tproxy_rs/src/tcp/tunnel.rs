use std::sync::Arc;

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
    http::server::HttpServer,
    net::{address::DomainTrie, tls::server::SniRequest},
    rt::Executor,
    service::BoxService,
    stream::{HeapReader, PeekStream, Stream},
    tcp::client::service::DefaultForwarder,
    telemetry::tracing,
    tls::boring::server::{TlsAcceptorData, TlsAcceptorLayer},
};

use super::{ECHO_DOMAIN, HIJACK_DOMAIN, http::build_http_request_service};

#[derive(Debug, Clone)]
pub(super) struct TunnelSniService<S> {
    domain_filter: Arc<DomainTrie<()>>,
    forwarder: DefaultForwarder,
    mitm_svc: BoxService<S, (), BoxError>,
}

impl<S> TunnelSniService<S>
where
    S: Stream + Unpin + rama::extensions::ExtensionsMut + Send + 'static,
{
    pub fn new(exec: Executor, mitm_tls_service_data: TlsAcceptorData) -> Self {
        let domain_filter = Arc::new(
            [ECHO_DOMAIN, HIJACK_DOMAIN]
                .into_iter()
                .map(|domain| (domain, ()))
                .collect(),
        );

        let forwarder = DefaultForwarder::ctx(exec.clone());

        let http_svc = build_http_request_service(exec.clone());
        let http_server = HttpServer::auto(exec).service(http_svc);
        let mitm_svc = TlsAcceptorLayer::new(mitm_tls_service_data)
            .with_store_client_hello(true)
            .into_layer(http_server)
            .boxed();

        Self {
            domain_filter,
            forwarder,
            mitm_svc,
        }
    }
}

impl<S> Service<SniRequest<S>> for TunnelSniService<S>
where
    S: Stream + Unpin + rama::extensions::ExtensionsMut + Send + 'static,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        SniRequest { sni, stream }: SniRequest<S>,
    ) -> Result<Self::Output, Self::Error> {
        let Some(domain) = sni else {
            tracing::trace!("tls stream without sni; fallback to bytes forwarding");
            return self
                .forwarder
                .serve(stream)
                .await
                .context("forward stream without SNI/TLS");
        };

        if !self.domain_filter.is_match_exact(&domain) {
            tracing::trace!(
                %domain,
                "tls stream not selected for MITM; fallback to raw forwarding"
            );
            return self
                .forwarder
                .serve(stream)
                .await
                .context("forward TLS stream for non-mitm domain");
        }

        tracing::info!(%domain, "MITM enabled for TLS stream");

        self.mitm_svc
            .serve(stream)
            .await
            .context("serve MITM HTTPS stream")
    }
}
