use rama::{
    futures,
    http::{
        grpc::{Request, Response, Status},
        server::HttpServer,
    },
    rt::Executor,
};

use crate::tests::integration::pb::{InputStream, OutputStream, test_stream_server};

type Stream<T> = std::pin::Pin<
    Box<dyn futures::Stream<Item = std::result::Result<T, Status>> + Send + Sync + 'static>,
>;

#[tokio::test]
async fn status_from_server_stream_with_source() {
    struct Svc;

    impl test_stream_server::TestStream for Svc {
        type StreamCallStream = Stream<OutputStream>;

        async fn stream_call(
            &self,
            _: Request<InputStream>,
        ) -> Result<Response<Self::StreamCallStream>, Status> {
            let s = SyncStream(std::ptr::null_mut::<()>());

            Ok(Response::new(Box::pin(s) as Self::StreamCallStream))
        }
    }

    let svc = test_stream_server::TestStreamServer::new(Svc);

    let _ = HttpServer::h2(Executor::new()).service(svc);
}

#[allow(dead_code)]
struct SyncStream(*mut ());

unsafe impl Send for SyncStream {}
unsafe impl Sync for SyncStream {}

impl futures::Stream for SyncStream {
    type Item = Result<OutputStream, Status>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        unimplemented!()
    }
}
