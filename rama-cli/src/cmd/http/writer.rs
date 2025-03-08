use rama::{
    combinators::Either,
    error::BoxError,
    http::layer::traffic_writer::{
        BidirectionalMessage, BidirectionalWriter, RequestWriterInspector, ResponseWriterLayer,
        WriterMode,
    },
    rt::Executor,
};
use std::path::PathBuf;
use tokio::{fs::OpenOptions, io::stdout, sync::mpsc::Sender};

#[derive(Debug, Clone)]
pub(super) enum WriterKind {
    Stdout,
    File(PathBuf),
}

pub(super) async fn create_traffic_writers(
    executor: &Executor,
    kind: WriterKind,
    all: bool,
    request_mode: Option<WriterMode>,
    response_mode: Option<WriterMode>,
) -> Result<
    (
        RequestWriterInspector<BidirectionalWriter<Sender<BidirectionalMessage>>>,
        ResponseWriterLayer<BidirectionalWriter<Sender<BidirectionalMessage>>>,
    ),
    BoxError,
> {
    let writer = match kind {
        WriterKind::Stdout => Either::A(stdout()),
        WriterKind::File(path) => Either::B(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?,
        ),
    };

    let bidirectional_writer = if all {
        BidirectionalWriter::new(executor, writer, 32, request_mode, response_mode)
    } else {
        BidirectionalWriter::last(executor, writer, request_mode, response_mode)
    };

    Ok((
        RequestWriterInspector::new(bidirectional_writer.clone()),
        ResponseWriterLayer::new(bidirectional_writer),
    ))
}
