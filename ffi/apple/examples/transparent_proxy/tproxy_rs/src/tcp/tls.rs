use std::sync::Arc;

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
    extensions::{ExtensionsMut, ExtensionsRef},
    net::{
        address::Domain,
        client::{ConnectorService, EstablishedClientConnection},
        proxy::ProxyTarget,
        tls::server::{ClientHelloRequest, PeekTlsClientHelloService},
    },
    rt::Executor,
    stream::Stream,
    tcp::client::{
        Request as TcpRequest,
        service::{DefaultForwarder, TcpConnector},
    },
    telemetry::tracing,
    tls::boring::{
        client::{TlsConnectorDataBuilder, TlsConnectorLayer},
        server::{TlsAcceptorData, TlsAcceptorLayer},
    },
};

use crate::utils::executor_from_input;

pub(super) fn new_opt_tls_svc<S: Stream + Unpin + ExtensionsMut>()
-> impl Service<S, Output = (), Error = BoxError> {
    PeekTlsClientHelloService::new(OptTlsService)
        .with_fallback(DefaultForwarder::ctx(Executor::default()))
}

#[derive(Debug, Clone)]
struct OptTlsService;

#[derive(Debug, Clone)]
/// SNI found by optional Tls service for tls traffic, if one was found at all,
/// in which case it will be injected in the extensions of the input.
pub struct TargetSni(pub Domain);

impl<S> Service<ClientHelloRequest<S>> for OptTlsService
where
    S: Stream + Unpin + ExtensionsRef,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        ClientHelloRequest {
            stream,
            client_hello,
        }: ClientHelloRequest<S>,
    ) -> Result<Self::Output, Self::Error> {
        let Some(ProxyTarget(dest_address)) = stream.extensions().get().cloned() else {
            tracing::warn!(
                "failed to find tls dest address in input... this is unexpected (rama NE bridge bug!?)"
            );
            return Err(BoxError::from(
                "missing tls target address (ProxyTarget ext)",
            ));
        };

        let maybe_target_sni = client_hello.ext_server_name().cloned().map(TargetSni);

        let mut tls_data: TlsConnectorDataBuilder = client_hello
            .try_into()
            .context("build boring tls connector data from CH")?;
        tls_data.set_store_server_certificate_chain(true);
        let tls_conn_layer = TlsConnectorLayer::secure().with_connector_data(Arc::new(tls_data));

        let exec = executor_from_input(&stream);
        let connector = tls_conn_layer.into_layer(TcpConnector::new(exec));

        let EstablishedClientConnection {
            input: _,
            conn: mut tls_stream,
        } = connector
            .connect(TcpRequest::new_with_extensions(
                dest_address,
                stream.extensions().clone(),
            ))
            .await
            .context("establish egress tls connection")?;

        if let Some(target_sni) = maybe_target_sni {
            tls_stream.extensions_mut().insert(target_sni);
        }

        // TlsAcceptorLayer::new()

        // TODO:
        // - mirror tls acceptor based on:
        //   - server hello from egress
        //   - issued cert based on original cert form server
        // - expect an inner service which receives
        //   { ingress_tls, egress_tls } strream pair...
        //
        // ... this can be used for the HTTPS CONNECT proxy
        // as well as the HTTPS MITM server....
        //
        // non-http traffic will simply be forward proxied (sadly with encrypt-decrypt flow)

        todo!()
    }
}
