use rama::{
    error::BoxError,
    http::layer::traffic_writer::{
        BidirectionalMessage, BidirectionalWriter, RequestWriterLayer, ResponseWriterLayer,
        WriterMode,
    },
    rt::Executor,
    service::util::combinators::Either,
};
use std::path::PathBuf;
use tokio::{fs::File, io::stdout, sync::mpsc::Sender};

#[derive(Debug, Clone)]
pub enum WriterKind {
    Stdout,
    File(PathBuf),
}

pub async fn create_traffic_writers(
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
        WriterKind::Stdout => Either::A(stdout()),
        WriterKind::File(path) => Either::B(File::create(path).await?),
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
