//! Default rama http backend, permanently forked from Hyper et-al.
//!
//! Crate used by the end-user `rama` crate.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

pub mod client;
pub mod server;

#[cfg(test)]
mod tests {
    use super::{client::HttpConnector, server::HttpServer};
    use futures::future::join;
    use rama_core::{Context, Service, rt::Executor, service::service_fn};
    use rama_http_types::{Body, Request, Response, Version};
    use rama_net::client::MockConnectorService;
    use std::convert::Infallible;

    #[tokio::test]
    async fn test_http11_pipelining() {
        async fn server_svc_fn(_ctx: Context<()>, _req: Request) -> Result<Response, Infallible> {
            Ok(Response::new(Body::from("a random response body")))
        }

        let ctx = Context::default();
        let create_req = || {
            Request::builder()
                .uri("https://www.example.com")
                .version(Version::HTTP_11)
                .body(Body::from("a reandom request body"))
                .unwrap()
        };

        let connector = HttpConnector::new(MockConnectorService::new(|| {
            HttpServer::auto(Executor::default()).service(service_fn(server_svc_fn))
        }));

        let conn = connector.serve(ctx, create_req()).await.unwrap().conn;

        // Http 1.1 should pipeline requests. Pipelining is important when trying to send multiple
        // requests on the same connection. This is something we generally don't do, but we do
        // trigger the same problem when we re-use a connection too fast. However triggering that
        // bug consistently has proven very hard so we trigger this one instead. Both of them
        // should be fixed by waiting for conn.isready().await before trying to send data on the connection.
        // For http1.1 this will result in pipelining (http2 will still be multiplexed)
        let (res1, res2) = join(
            conn.serve(Context::default(), create_req()),
            conn.serve(Context::default(), create_req()),
        )
        .await;

        res1.unwrap();
        res2.unwrap();
    }
}
