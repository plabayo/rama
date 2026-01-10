use std::pin::Pin;

use rama::{
    futures::Stream,
    http::{
        Uri,
        grpc::{Code, Request, Response, Status},
        server::HttpServer,
    },
    rt::Executor,
    stream,
    telemetry::tracing,
};

use crate::tests::integration::pb::{Input1, Output1, test1_client, test1_server};

#[test]
fn max_message_recv_size() {
    // Server recv
    assert_server_recv_max_success(128);
    // 5 is the size of the gRPC header
    assert_server_recv_max_success((4 * 1024 * 1024) - 5);
    // 4mb is the max recv size
    assert_server_recv_max_failure(4 * 1024 * 1024);
    assert_server_recv_max_failure(4 * 1024 * 1024 + 1);
    assert_server_recv_max_failure(8 * 1024 * 1024);

    // Client recv
    assert_client_recv_max_success(128);
    // 5 is the size of the gRPC header
    assert_client_recv_max_success((4 * 1024 * 1024) - 5);
    // 4mb is the max recv size
    assert_client_recv_max_failure(4 * 1024 * 1024);
    assert_client_recv_max_failure(4 * 1024 * 1024 + 1);
    assert_client_recv_max_failure(8 * 1024 * 1024);

    // Custom limit settings
    assert_test_case(TestCase {
        // 5 is the size of the gRPC header
        server_blob_size: 1024 - 5,
        client_recv_max: Some(1024),
        ..Default::default()
    });
    assert_test_case(TestCase {
        server_blob_size: 1024,
        client_recv_max: Some(1024),
        expected_code: Some(Code::OutOfRange),
        ..Default::default()
    });

    assert_test_case(TestCase {
        // 5 is the size of the gRPC header
        client_blob_size: 1024 - 5,
        server_recv_max: Some(1024),
        ..Default::default()
    });
    assert_test_case(TestCase {
        client_blob_size: 1024,
        server_recv_max: Some(1024),
        expected_code: Some(Code::OutOfRange),
        ..Default::default()
    });
}

#[test]
#[tracing_test::traced_test]
fn max_message_send_size() {
    // Check client send limit works
    assert_test_case(TestCase {
        client_blob_size: 4 * 1024 * 1024,
        server_recv_max: Some(usize::MAX),
        ..Default::default()
    });
    assert_test_case(TestCase {
        // 5 is the size of the gRPC header
        client_blob_size: 1024 - 5,
        server_recv_max: Some(usize::MAX),
        client_send_max: Some(1024),
        ..Default::default()
    });

    // Check server send limit works
    assert_test_case(TestCase {
        server_blob_size: 4 * 1024 * 1024,
        client_recv_max: Some(usize::MAX),
        ..Default::default()
    });
    assert_test_case(TestCase {
        // 5 is the gRPC header size
        server_blob_size: 1024 - 5,
        client_recv_max: Some(usize::MAX),
        // Set server send limit to 1024
        server_send_max: Some(1024),
        ..Default::default()
    });
}

#[tokio::test]
async fn response_stream_limit() {
    let client_blob = vec![0; 1];

    struct Svc;

    impl test1_server::Test1 for Svc {
        async fn unary_call(&self, _req: Request<Input1>) -> Result<Response<Output1>, Status> {
            unimplemented!()
        }

        type StreamCallStream =
            Pin<Box<dyn Stream<Item = Result<Output1, Status>> + Send + Sync + 'static>>;

        async fn stream_call(
            &self,
            _req: Request<Input1>,
        ) -> Result<Response<Self::StreamCallStream>, Status> {
            let blob = Output1 {
                buf: vec![0; 6877902],
            };
            let stream = stream::iter(vec![Ok(blob.clone()), Ok(blob.clone())]);

            Ok(Response::new(Box::pin(stream)))
        }
    }

    let svc = test1_server::Test1Server::new(Svc);

    let server = HttpServer::h2(Executor::default()).service(svc);

    let client = test1_client::Test1Client::new(
        super::mock_io_client(move || server.clone()),
        Uri::from_static("http://[::]:50051"),
    )
    .with_max_decoding_message_size(6877902 + 5);

    let req = Request::new(Input1 {
        buf: client_blob.clone(),
    });

    let mut stream = client.stream_call(req).await.unwrap().into_inner();

    while let Some(_b) = stream.message().await.unwrap() {}
}

// Track caller doesn't work on async fn so we extract the async part
// into a sync version and assert the response there using track track_caller
// so that when this does panic it tells us which line in the test failed not
// where we placed the panic call.

#[track_caller]
fn assert_server_recv_max_success(size: usize) {
    let case = TestCase {
        client_blob_size: size,
        server_blob_size: 0,
        ..Default::default()
    };

    assert_test_case(case);
}

#[track_caller]
fn assert_server_recv_max_failure(size: usize) {
    let case = TestCase {
        client_blob_size: size,
        server_blob_size: 0,
        expected_code: Some(Code::OutOfRange),
        ..Default::default()
    };

    assert_test_case(case);
}

#[track_caller]
fn assert_client_recv_max_success(size: usize) {
    let case = TestCase {
        client_blob_size: 0,
        server_blob_size: size,
        ..Default::default()
    };

    assert_test_case(case);
}

#[track_caller]
fn assert_client_recv_max_failure(size: usize) {
    let case = TestCase {
        client_blob_size: 0,
        server_blob_size: size,
        expected_code: Some(Code::OutOfRange),
        ..Default::default()
    };

    assert_test_case(case);
}

#[track_caller]
fn assert_test_case(case: TestCase) {
    let res = max_message_run(&case);

    match (case.expected_code, res) {
        (Some(_), Ok(())) => panic!("Expected failure, but got success"),
        (Some(code), Err(status)) => {
            if status.code() != code {
                panic!("Expected failure, got failure but wrong code, got: {status:?}")
            }
        }

        (None, Err(status)) => panic!("Expected success, but got failure, got: {status:?}"),

        _ => (),
    }
}

#[derive(Default)]
struct TestCase {
    client_blob_size: usize,
    server_blob_size: usize,
    client_recv_max: Option<usize>,
    server_recv_max: Option<usize>,
    client_send_max: Option<usize>,
    server_send_max: Option<usize>,

    expected_code: Option<Code>,
}

#[tokio::main]
async fn max_message_run(case: &TestCase) -> Result<(), Status> {
    let client_blob = vec![0; case.client_blob_size];
    let server_blob = vec![0; case.server_blob_size];

    struct Svc(Vec<u8>);

    impl test1_server::Test1 for Svc {
        async fn unary_call(&self, _req: Request<Input1>) -> Result<Response<Output1>, Status> {
            Ok(Response::new(Output1 {
                buf: self.0.clone(),
            }))
        }

        type StreamCallStream =
            Pin<Box<dyn Stream<Item = Result<Output1, Status>> + Send + Sync + 'static>>;

        async fn stream_call(
            &self,
            _req: Request<Input1>,
        ) -> Result<Response<Self::StreamCallStream>, Status> {
            unimplemented!()
        }
    }

    let mut svc = test1_server::Test1Server::new(Svc(server_blob));

    if let Some(size) = case.server_recv_max {
        svc.set_max_decoding_message_size(size);
    }

    if let Some(size) = case.server_send_max {
        svc.set_max_encoding_message_size(size);
    }

    let server = HttpServer::h2(Executor::default()).service(svc);

    let mut client = test1_client::Test1Client::new(
        super::mock_io_client(move || server.clone()),
        Uri::from_static("http://[::]:50051"),
    );

    if let Some(size) = case.client_recv_max {
        client.set_max_decoding_message_size(size);
    }

    if let Some(size) = case.client_send_max {
        client.set_max_encoding_message_size(size);
    }

    let req = Request::new(Input1 {
        buf: client_blob.clone(),
    });

    client.unary_call(req).await.map(|_| ())
}
