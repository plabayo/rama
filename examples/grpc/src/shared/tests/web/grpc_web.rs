use base64::Engine as _;

use rama::{
    Layer as _, Service,
    bytes::{Buf as _, BufMut as _, Bytes, BytesMut},
    http::{
        Body, Method, Request, StatusCode, Uri,
        body::util::BodyExt as _,
        client::EasyHttpWebClient,
        grpc::{protobuf::prost::Message as _, web::GrpcWebLayer},
        header::{self, RAMA_ID_HEADER_VALUE, USER_AGENT},
        server::HttpServer,
    },
    net::address::SocketAddress,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing,
};

use super::{Svc, pb::*};

#[tokio::test]
#[tracing_test::traced_test]
async fn binary_request() {
    let server_url = spawn().await;
    let client = EasyHttpWebClient::default();

    let req = build_request(&server_url, "grpc-web", "grpc-web");
    let res = client.serve(req).await.unwrap();
    let content_type = res.headers().get(header::CONTENT_TYPE).unwrap().clone();
    let content_type = content_type.to_str().unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(content_type, "application/grpc-web+proto");

    let (message, trailers) = decode_body(res.into_body(), content_type).await;
    let expected = Output {
        id: 1,
        desc: "one".to_owned(),
    };

    assert_eq!(message, expected);
    assert_eq!(&trailers[..], b"grpc-status:0\r\n");
}

#[tokio::test]
#[tracing_test::traced_test]
async fn text_request() {
    let server_url = spawn().await;
    let client = EasyHttpWebClient::default();

    let req = build_request(&server_url, "grpc-web-text", "grpc-web-text");
    let res = client.serve(req).await.unwrap();
    let content_type = res.headers().get(header::CONTENT_TYPE).unwrap().clone();
    let content_type = content_type.to_str().unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(content_type, "application/grpc-web-text+proto");

    let (message, trailers) = decode_body(res.into_body(), content_type).await;
    let expected = Output {
        id: 1,
        desc: "one".to_owned(),
    };

    assert_eq!(message, expected);
    assert_eq!(&trailers[..], b"grpc-status:0\r\n");
}

async fn spawn() -> String {
    let addr = SocketAddress::local_ipv4(0);
    let listener = TcpListener::bind(addr, Executor::default())
        .await
        .expect("listener");
    let url = format!("http://{}", listener.local_addr().unwrap());

    drop(tokio::spawn(async move {
        let http_svc = GrpcWebLayer::new().into_layer(test_server::TestServer::new(Svc));
        listener
            .serve(HttpServer::auto(Executor::default()).service(http_svc))
            .await;
    }));

    url
}

fn encode_body() -> Bytes {
    let input = Input {
        id: 1,
        desc: "one".to_owned(),
    };

    let mut buf = BytesMut::with_capacity(1024);
    buf.reserve(5);
    unsafe {
        buf.advance_mut(5);
    }

    input.encode(&mut buf).unwrap();

    let len = buf.len() - 5;
    {
        let mut buf = &mut buf[..5];
        buf.put_u8(0);
        buf.put_u32(len as u32);
    }

    buf.split_to(len + 5).freeze()
}

fn build_request(base_uri: &str, content_type: &str, accept: &str) -> Request<Body> {
    use header::{ACCEPT, CONTENT_TYPE, ORIGIN};

    let request_uri = format!("{}/{}/{}", base_uri, "web.Test", "UnaryCall")
        .parse::<Uri>()
        .unwrap();

    let bytes = match content_type {
        "grpc-web" => encode_body(),
        "grpc-web-text" => super::util::base64::STANDARD.encode(encode_body()).into(),
        _ => panic!("invalid content type {content_type}"),
    };

    Request::builder()
        .method(Method::POST)
        .header(CONTENT_TYPE, format!("application/{content_type}"))
        .header(ORIGIN, "http://example.com")
        .header(USER_AGENT, RAMA_ID_HEADER_VALUE.clone())
        .header(ACCEPT, format!("application/{accept}"))
        .uri(request_uri)
        .body(Body::from(bytes))
        .unwrap()
}

async fn decode_body(body: Body, content_type: &str) -> (Output, Bytes) {
    let mut body = body.collect().await.unwrap().to_bytes();

    if content_type == "application/grpc-web-text+proto" {
        body = super::util::base64::STANDARD.decode(body).unwrap().into()
    }

    tracing::info!("{body:?}");

    body.advance(1);
    let len = body.get_u32();
    let msg = Output::decode(&mut body.split_to(len as usize)).expect("decode");
    body.advance(5);

    (msg, body)
}
