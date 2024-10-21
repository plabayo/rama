use rama::{
    error::BoxError,
    http::layer::traffic_writer::{
        BidirectionalMessage, BidirectionalWriter, RequestWriterLayer, ResponseWriterLayer,
        WriterMode,
    },
    rt::Executor,
};
use tokio::{io::stdout, sync::mpsc::Sender};

#[derive(Debug, Clone)]
pub(super) enum WriterKind {
    Stdout,
}

pub(super) async fn create_traffic_writers(
    executor: &Executor,
    kind: WriterKind,
    all: bool,
    request_mode: Option<WriterMode>,
    response_mode: Option<WriterMode>,
) -> Result<
    (
        RequestWriterLayer<BidirectionalWriter<Sender<BidirectionalMessage>>>,
        ResponseWriterLayer<BidirectionalWriter<Sender<BidirectionalMessage>>>,
    ),
    BoxError,
> {
    let writer = match kind {
        WriterKind::Stdout => stdout(),
    };
    let bidirectional_writer = if all {
        BidirectionalWriter::new(executor, writer, 32, request_mode, response_mode)
    } else {
        BidirectionalWriter::last(executor, writer, request_mode, response_mode)
    };

    Ok((
        RequestWriterLayer::new(bidirectional_writer.clone()),
        ResponseWriterLayer::new(bidirectional_writer),
    ))
}
