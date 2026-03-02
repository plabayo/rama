// mod http;
// mod tunnel;

mod socks5;
mod tls;

use std::convert::Infallible;

use rama::{
    Service, extensions::ExtensionsRef, net::apple::networkextension::TcpFlow,
    proxy::socks5::server::Socks5PeekRouter, rt::Executor, tcp::client::service::DefaultForwarder,
    telemetry::tracing,
};

use crate::utils::executor_from_input;

// use self::{http::build_entry_router, state::TcpProxyState};

// const ECHO_DOMAIN: &str = "echo.ramaproxy.org";
// const HIJACK_DOMAIN: &str = "tproxy.example.rama.internal";
// const OBSERVED_HEADER_NAME: &str = "x-rama-tproxy-observed";

pub(super) fn new_service() -> impl Service<TcpFlow, Output = (), Error = Infallible> {
    let exec = Executor::default(); // NOTE: in future would be good if we have access to executor already, somehow...

    let socks5_svc = self::socks5::Socks5IngressService::new();
    TcpFlowProxyService {
        inner: Socks5PeekRouter::new(socks5_svc).with_fallback(DefaultForwarder::ctx(exec)),
    }
}

#[derive(Debug, Clone)]
struct TcpFlowProxyService {
    inner: Socks5PeekRouter<self::socks5::Socks5IngressService, DefaultForwarder>,
}

impl Service<TcpFlow> for TcpFlowProxyService {
    type Output = ();
    type Error = Infallible;

    async fn serve(&self, input: TcpFlow) -> Result<Self::Output, Self::Error> {
        if let Err(err) = self.inner.serve(input).await {
            tracing::debug!("failed to forward TCP traffic: {err}");
        }

        Ok(())
    }
}
