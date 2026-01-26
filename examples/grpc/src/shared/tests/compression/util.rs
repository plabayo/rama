use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{self, AtomicUsize},
    },
    task::{Context, Poll, ready},
};

use pin_project_lite::pin_project;

use rama::{
    Service,
    bytes::{Buf, Bytes},
    error::{BoxError, OpaqueError},
    http::{
        self, Body, StreamingBody,
        body::{Frame, SizeHint, util::BodyExt as _},
        client::EasyHttpWebClient,
        grpc::{Status, codec::CompressionEncoding},
        layer::map_request_body::MapRequestBodyLayer,
    },
    net::test_utils::client::{MockConnectorService, MockSocket},
    rt::Executor,
    service::BoxService,
};

macro_rules! parametrized_tests {
    ($fn_name:ident, $($test_name:ident: $input:expr),+ $(,)?) => {
        rama::utils::macros::paste! {
            $(
                #[tokio::test(flavor = "multi_thread")]
                async fn [<$fn_name _ $test_name>]() {
                    let input = $input;
                    $fn_name(input).await;
                }
            )+
        }
    }
}
pub(crate) use parametrized_tests;

pin_project! {
    /// A body that tracks how many bytes passes through it
    pub struct CountBytesBody<B> {
        #[pin]
        pub inner: B,
        pub counter: Arc<AtomicUsize>,
    }
}

impl<B> StreamingBody for CountBytesBody<B>
where
    B: StreamingBody<Data = Bytes>,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        let counter: Arc<AtomicUsize> = this.counter.clone();
        match ready!(this.inner.poll_frame(cx)) {
            Some(Ok(chunk)) => {
                println!("response body chunk size = {}", frame_data_length(&chunk));
                counter.fetch_add(frame_data_length(&chunk), atomic::Ordering::SeqCst);
                Poll::Ready(Some(Ok(chunk)))
            }
            x => Poll::Ready(x),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn frame_data_length(frame: &Frame<Bytes>) -> usize {
    if let Some(data) = frame.data_ref() {
        data.len()
    } else {
        0
    }
}

pin_project! {
    struct ChannelBody<T> {
        #[pin]
        rx: tokio::sync::mpsc::Receiver<Frame<T>>,
    }
}

impl<T> ChannelBody<T> {
    pub(super) fn new() -> (tokio::sync::mpsc::Sender<Frame<T>>, Self) {
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        (tx, Self { rx })
    }
}

impl<T> StreamingBody for ChannelBody<T>
where
    T: Buf,
{
    type Data = T;
    type Error = Status;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let frame = ready!(self.project().rx.poll_recv(cx));
        Poll::Ready(frame.map(Ok))
    }
}

pub(super) fn measure_request_body_size_layer(
    bytes_sent_counter: Arc<AtomicUsize>,
) -> MapRequestBodyLayer<impl Fn(Body) -> Body + Clone> {
    MapRequestBodyLayer::new(move |mut body: Body| {
        let (tx, new_body) = ChannelBody::new();

        let bytes_sent_counter = bytes_sent_counter.clone();
        tokio::spawn(async move {
            while let Some(chunk) = body.frame().await {
                let chunk = chunk.unwrap();
                println!("request body chunk size = {}", frame_data_length(&chunk));
                bytes_sent_counter.fetch_add(frame_data_length(&chunk), atomic::Ordering::SeqCst);
                tx.send(chunk).await.unwrap();
            }
        });

        Body::new(new_body)
    })
}

pub(super) type WebClient = BoxService<http::Request, http::Response, OpaqueError>;

pub(super) fn mock_io_client<F, Server>(make_server: F) -> WebClient
where
    F: Fn() -> Server + Send + Sync + 'static,
    Server: Service<MockSocket, Error: Into<BoxError>>,
{
    EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(MockConnectorService::new(make_server))
        .without_tls_proxy_support()
        .without_proxy_support()
        .without_tls_support()
        .with_default_http_connector::<Body>(Executor::default())
        .try_with_default_connection_pool()
        .unwrap()
        .build_client()
        .boxed()
}

#[derive(Clone)]
pub(super) struct AssertRightEncoding {
    encoding: CompressionEncoding,
}

#[allow(dead_code)]
impl AssertRightEncoding {
    pub(super) fn new(encoding: CompressionEncoding) -> Self {
        Self { encoding }
    }

    pub(super) fn call<B: StreamingBody>(self, req: http::Request<B>) -> http::Request<B> {
        let expected = match self.encoding {
            CompressionEncoding::Gzip => "gzip",
            CompressionEncoding::Zstd => "zstd",
            CompressionEncoding::Deflate => "deflate",
            _ => panic!("unexpected encoding {:?}", self.encoding),
        };
        assert_eq!(req.headers().get("grpc-encoding").unwrap(), expected);

        req
    }
}
