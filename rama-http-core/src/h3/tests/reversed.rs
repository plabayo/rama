use rama_core::rt::{Executor, spawn};
use rama_http_types::{Body, Request, Response, body::util::BodyExt};
use rama_quic_proto::Side;

use super::{LIMIT, Pair};
use crate::h3::{
    client,
    connection::Config,
    server,
    transport::{Connection as _, Reversed},
};

#[tokio::test]
async fn the_quic_client_serves_requests_sent_by_the_quic_server() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::new(None, None).await;
        let served_by_quic_client = Reversed::new(pair.client.clone());
        let sent_by_quic_server = Reversed::new(pair.server.clone());
        assert_eq!(served_by_quic_client.side(), Side::Server);
        assert_eq!(sent_by_quic_server.side(), Side::Client);

        let (mut server, server_driver) =
            server::handshake(served_by_quic_client, Config::default()).unwrap();
        let (mut client, client_driver) =
            client::handshake::<Body, _>(sent_by_quic_server, Config::default(), Executor::new())
                .unwrap();
        let server_driver = spawn(server_driver.run());
        let client_driver = spawn(client_driver.run());
        let serve = spawn(async move {
            for _ in 0..2 {
                let (request, response) = server.accept().await.unwrap().resolve().await.unwrap();
                let path = request.uri().request_target().to_string();
                let body = request.into_body().collect().await.unwrap().to_bytes();
                let mut reply = path.into_bytes();
                reply.extend_from_slice(&body);
                response
                    .send_response(Response::new(Body::from(reply)))
                    .await
                    .unwrap();
            }
        });
        for path in ["/first", "/second"] {
            let response = client
                .send_request(
                    Request::builder()
                        .method("POST")
                        .uri(format!("https://localhost{path}"))
                        .body(Body::from(" from the quic server"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                format!("{path} from the quic server")
            );
        }
        serve.await.unwrap();
        drop(client);
        _ = client_driver.await.unwrap();
        _ = server_driver.await.unwrap();
        pair.close().await;
    })
    .await
    .unwrap();
}
