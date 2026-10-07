//! HTTP's own write deadline must reach the Apple flow's terminal state,
//! even when it expires before the FFI writer's paused-drain backstop.

use std::{
    convert::Infallible,
    io,
    sync::{Arc, mpsc},
    time::Duration,
};

use parking_lot::Mutex;

use rama::{
    Service,
    http::{
        Body, Request, Response, StatusCode,
        core::{server::conn::http1::Builder, service::RamaHttpService},
    },
    io::BridgeIo,
    net::{
        address::HostWithPort,
        apple::networkextension::{
            NwTcpStream, TcpFlow,
            tproxy::{
                FlowAction, SessionFlowAction, TcpDeliverStatus, TransparentProxyConfig,
                TransparentProxyEngineBuilder, TransparentProxyFlowMeta,
                TransparentProxyFlowProtocol, TransparentProxyHandler,
            },
        },
        conn::LingeringClose,
    },
    rt::Executor,
    service::service_fn,
};

const BODY_LEN: usize = 64 * 1024;

#[derive(Clone)]
struct RejectUpload;

impl TransparentProxyHandler for RejectUpload {
    fn transparent_proxy_config(&self) -> TransparentProxyConfig {
        TransparentProxyConfig::new()
    }

    async fn match_tcp_flow(
        &self,
        _: Executor,
        meta: TransparentProxyFlowMeta,
    ) -> FlowAction<impl Service<BridgeIo<TcpFlow, NwTcpStream>, Output = (), Error = Infallible>>
    {
        FlowAction::Intercept {
            meta,
            service: service_fn(
                |BridgeIo(ingress, _): BridgeIo<TcpFlow, NwTcpStream>| async {
                    let service = service_fn(|_: Request| async {
                        let mut response = Response::new(Body::from(vec![b'r'; BODY_LEN]));
                        *response.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
                        Ok::<_, Infallible>(response)
                    });
                    // Expire before the FFI writer's backstop. As in the
                    // example, the outer service consumes HTTP errors.
                    _ = Builder::new()
                        .with_lingering_close(
                            LingeringClose::new().with_timeout(Duration::from_millis(100)),
                        )
                        .serve_connection(ingress, RamaHttpService::new(service))
                        .await;
                    Ok::<_, Infallible>(())
                },
            ),
        }
    }
}

#[test]
fn http_linger_preserves_apple_response_tails_and_reports_truncation() {
    for blocked in [false, true] {
        let engine =
            TransparentProxyEngineBuilder::new(|_| async { Ok::<_, Infallible>(RejectUpload) })
                .with_tcp_paused_drain_max_wait(Duration::from_secs(10))
                .build()
                .unwrap();
        let accepted = Arc::new(Mutex::new(Vec::new()));
        let sink = accepted.clone();
        let (closed_tx, closed_rx) = mpsc::channel();
        let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
            TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
                .with_remote_endpoint(HostWithPort::example_domain_with_port(80)),
            move |bytes| {
                let mut accepted = sink.lock();
                if blocked && !accepted.is_empty() {
                    return TcpDeliverStatus::Paused;
                }
                accepted.extend_from_slice(bytes);
                TcpDeliverStatus::Accepted
            },
            || {},
            move || {
                _ = closed_tx.send(());
            },
        ) else {
            panic!("expected intercepted flow");
        };
        session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
        assert_eq!(
            session.on_client_bytes(
                b"POST / HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 1000000\r\n\r\nx"
            ),
            TcpDeliverStatus::Accepted
        );
        closed_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("HTTP close must not wait for the FFI paused-drain backstop");
        let terminal = session.terminal_error_code();
        let response = accepted.lock();
        assert!(response.starts_with(b"HTTP/1.1 413"));
        if blocked {
            assert!(response.len() < BODY_LEN);
            assert_eq!(
                io::Error::from_raw_os_error(terminal).kind(),
                io::ErrorKind::ConnectionReset,
                "an incomplete HTTP response must not close the Apple flow in order"
            );
        } else {
            assert_eq!(terminal, 0);
            assert!(response.ends_with(&vec![b'r'; BODY_LEN]));
        }
        drop(response);
        engine.stop(0);
    }
}
