// mod certs;
// mod http;
// mod socks5;
// mod tunnel;

use std::convert::Infallible;

use rama::{
    Service, extensions::ExtensionsRef, net::apple::networkextension::TcpFlow, rt::Executor,
    tcp::client::service::DefaultForwarder, telemetry::tracing,
};

// use self::{http::build_entry_router, state::TcpProxyState};

// const ECHO_DOMAIN: &str = "echo.ramaproxy.org";
// const HIJACK_DOMAIN: &str = "tproxy.example.rama.internal";
// const OBSERVED_HEADER_NAME: &str = "x-rama-tproxy-observed";

pub(super) fn new_service() -> impl Service<TcpFlow, Output = (), Error = Infallible> {
    TcpFlowProxyService
}

#[derive(Debug, Clone)]
struct TcpFlowProxyService;

impl Service<TcpFlow> for TcpFlowProxyService {
    type Output = ();
    type Error = Infallible;

    async fn serve(&self, input: TcpFlow) -> Result<Self::Output, Self::Error> {
        let exec = input
            .extensions()
            .get()
            .cloned()
            .map(Executor::graceful)
            .unwrap_or_default();

        if let Err(err) = DefaultForwarder::ctx(exec).serve(input).await {
            tracing::debug!("failed to forward TCP traffic: {err}");
        }

        Ok(())
    }
}
