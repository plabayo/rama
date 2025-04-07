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
    use rama_net::test_utils::client::MockConnectorService;
    use std::{
        convert::Infallible,
        time::{Duration, Instant},
    };
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_http11_pipelining() {
        let ctx = Context::default();
        let connector = HttpConnector::new(MockConnectorService::new(|| {
            HttpServer::auto(Executor::default()).service(service_fn(server_svc_fn))
        }));

        let conn = connector
            .serve(ctx, create_test_request(Version::HTTP_11))
            .await
            .unwrap()
            .conn;

        // Http 1.1 should pipeline requests. Pipelining is important when trying to send multiple
        // requests on the same connection. This is something we generally don't do, but we do
        // trigger the same problem when we re-use a connection too fast. However triggering that
        // bug consistently has proven very hard so we trigger this one instead. Both of them
        // should be fixed by waiting for conn.isready().await before trying to send data on the connection.
        // For http1.1 this will result in pipelining (http2 will still be multiplexed)
        let start = Instant::now();
        let (res1, res2) = join(
            conn.serve(Context::default(), create_test_request(Version::HTTP_11)),
            conn.serve(Context::default(), create_test_request(Version::HTTP_11)),
        )
        .await;
        let duration = start.elapsed();

        res1.unwrap();
        res2.unwrap();

        assert!(duration > Duration::from_millis(200));
    }

    #[tokio::test]
    async fn test_http2_multiplex() {
        let ctx = Context::default();
        let connector = HttpConnector::new(MockConnectorService::new(|| {
            HttpServer::auto(Executor::default()).service(service_fn(server_svc_fn))
        }));

        let conn = connector
            .serve(ctx, create_test_request(Version::HTTP_2))
            .await
            .unwrap()
            .conn;

        // We have an artificial sleep of 100ms, so multiplexing should be < 200ms
        let start = Instant::now();
        let (res1, res2) = join(
            conn.serve(Context::default(), create_test_request(Version::HTTP_2)),
            conn.serve(Context::default(), create_test_request(Version::HTTP_2)),
        )
        .await;

        let duration = start.elapsed();
        res1.unwrap();
        res2.unwrap();

        assert!(duration < Duration::from_millis(200));
    }

    async fn server_svc_fn(_ctx: Context<()>, _req: Request) -> Result<Response, Infallible> {
        sleep(Duration::from_millis(100)).await;
        Ok(Response::new(Body::from("a random response body")))
    }

    fn create_test_request(version: Version) -> Request {
        Request::builder()
            .uri("https://www.example.com")
            .version(version)
            .body(Body::from("a reandom request body"))
            .unwrap()
    }
}
