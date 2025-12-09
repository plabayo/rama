use rama::{
    Layer, Service,
    dns::{DnsOverwrite, InMemoryDns},
    extensions::ExtensionsMut,
    net::transport::TryRefIntoTransportContext,
    telemetry::tracing,
};

use crate::cmd::send::arg::ResolveArg;
use std::fmt;

#[derive(Debug, Clone)]
pub(in crate::cmd::send) struct OptDnsOverwriteLayer(Option<ResolveArg>);

impl OptDnsOverwriteLayer {
    pub(in crate::cmd::send) fn new(arg: Option<ResolveArg>) -> Self {
        Self(arg)
    }
}

impl<S> Layer<S> for OptDnsOverwriteLayer {
    type Service = OptDnsOverwriteService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OptDnsOverwriteService {
            inner,
            info: self.0.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        OptDnsOverwriteService {
            inner,
            info: self.0,
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::cmd::send) struct OptDnsOverwriteService<S> {
    inner: S,
    info: Option<ResolveArg>,
}

impl<Input, S> Service<Input> for OptDnsOverwriteService<S>
where
    Input: TryRefIntoTransportContext<Error: fmt::Debug> + ExtensionsMut + Send + 'static,
    S: Service<Input>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, mut input: Input) -> Result<Self::Output, Self::Error> {
        let Some(ref info) = self.info else {
            return self.inner.serve(input).await;
        };

        if info.port.is_none()
            || input
                .try_ref_into_transport_ctx()
                .inspect_err(|err| {
                    tracing::error!("failed to fetch transport ctx for input: {err:?}")
                })
                .ok()
                .and_then(|ctx| ctx.host_with_port())
                .map(|hwp| info.port == Some(hwp.port))
                .unwrap_or_default()
        {
            let overwrite: DnsOverwrite = match info.host.clone() {
                Some(domain) => {
                    let mut dns = InMemoryDns::new();
                    dns.insert(domain, info.addresses.clone());
                    dns.into()
                }
                None => info.addresses.clone().into(),
            };
            input.extensions_mut().insert(overwrite);
        }

        self.inner.serve(input).await
    }
}
