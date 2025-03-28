use rama::http::Request;
use rama::http::client::HttpConnector;
use rama::http::client::http_inspector::HttpsAlpnModifier;
use rama::http::proto::h1::Http1HeaderMap;
use rama::http::server::HttpServer;
use rama::http::{Body, Response};
use rama::http::{HeaderName, HeaderValue};
use rama::net::client::EstablishedClientConnection;
use rama::net::fingerprint::{Ja3, Ja4, Ja4H};
use rama::net::stream::Socket;
use rama::net::tls::ApplicationProtocol;
use rama::net::tls::client::{ClientConfig, ServerVerifyMode};
use rama::net::tls::client::{extract_client_config_from_ctx, parse_client_hello};
use rama::net::tls::server::ServerAuth;
use rama::net::tls::server::ServerConfig;
use rama::rt::Executor;
use rama::service::service_fn;
use rama::tls::boring::client::TlsConnector;
use rama::tls::boring::client::TlsConnectorData;
use rama::tls::boring::server::TlsAcceptorLayer;
use rama::ua::emulate::{
    UserAgentEmulateHttpConnectModifier, UserAgentEmulateHttpRequestModifier, UserAgentEmulateLayer,
};
use rama::ua::profile::HttpProfile;
use rama::ua::profile::UserAgentDatabase;
use rama::ua::profile::{
    Http1Profile, Http1Settings, Http2Profile, Http2Settings, HttpHeadersProfile,
};
use rama::ua::profile::{TlsProfile, UserAgentProfile};
use rama::ua::{PlatformKind, UserAgentKind};
use rama::{Context, Layer, Service};
use std::convert::Infallible;
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, duplex};
use tokio::task::JoinSet;

#[tokio::test]
async fn test_client() {
    async fn server_svc_fn(ctx: Context<()>, _req: Request) -> Result<Response, Infallible> {
        Ok(Response::new(Body::empty()))
    }

    let ctx = Context::default();
    let create_req = || {
        Request::builder()
            .uri("https://www.example.com")
            .body(Body::empty())
            .unwrap()
    };
    let connector = HttpConnector::new(MockConnectorService::new(service_fn(server_svc_fn)));

    let EstablishedClientConnection { ctx, req, conn } =
        connector.serve(ctx, create_req()).await.unwrap();
    for i in 0..100 {
        let x = conn.serve(Context::default(), create_req()).await.unwrap();
    }
}

struct MockConnectorService<S> {
    serve_svc: S,
}

impl<S: fmt::Debug> fmt::Debug for MockConnectorService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockConnectorService")
            .field("serve_svc", &self.serve_svc)
            .finish()
    }
}

impl<S> MockConnectorService<S> {
    fn new(serve_svc: S) -> Self {
        Self { serve_svc }
    }
}

impl<State, S> Service<State, Request> for MockConnectorService<S>
where
    S: Service<State, Request, Response = Response, Error = Infallible> + Clone,
    State: Clone + Send + Sync + 'static,
{
    type Error = S::Error;
    type Response = EstablishedClientConnection<MockSocket, State, Request>;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let (client_socket, server_socket) = new_mock_sockets();

        let server_ctx = ctx.clone();
        let svc = self.serve_svc.clone();

        tokio::spawn(async move {
            let server = HttpServer::auto(Executor::default()).service(svc);
            server.serve(server_ctx, server_socket).await.unwrap();
        });

        Ok(EstablishedClientConnection {
            ctx,
            req,
            conn: client_socket,
        })
    }
}

fn new_mock_sockets() -> (MockSocket, MockSocket) {
    let (client, server) = duplex(1024);
    (MockSocket { stream: client }, MockSocket { stream: server })
}

#[derive(Debug)]
struct MockSocket {
    stream: DuplexStream,
}

impl AsyncRead for MockSocket {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for MockSocket {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl Socket for MockSocket {
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        Ok(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            0,
        )))
    }

    fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        Ok(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            0,
        )))
    }
}
