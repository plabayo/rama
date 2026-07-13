use std::future::Future;
use std::pin::Pin;

use rama_core::futures::future::pending;
use rama_core::futures::{Stream, TryStreamExt as _};
use rama_core::stream::wrappers::UnboundedReceiverStream;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tokio::time::sleep;

use crate::Result;
use crate::context::get_context;
use crate::context::timeout::Timeout;
use crate::io::{StreamIo, StreamReceiver, StreamSender};
use crate::service::{
    ClientStreamingMethod, DuplexStreamingMethod, ServerStreamingMethod, UnaryMethod,
};
use crate::types::encoding::BufExt;
use crate::types::flags::Flags;
use crate::types::protos::raw_bytes::RawBytes;
use crate::types::protos::{Data, Status};

pub trait MethodHandler {
    fn handle<'a>(
        &'a self,
        flags: Flags,
        payload: RawBytes,
        stream: &'a mut StreamIo,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
}

macro_rules! join_first {
    ($($e:expr),* $(,)?) => { tokio::select! {
        $(res = $e => res),+
    } };
}

impl<
    Input: prost::Message + Default,
    Output: prost::Message + Default,
    FutOut: Future<Output = Result<Output>> + Send,
    F: Fn(Input) -> FutOut + Send + Sync,
> MethodHandler for UnaryMethod<Input, Output, F>
{
    fn handle<'a>(
        &'a self,
        flags: Flags,
        payload: RawBytes,
        stream: &'a mut StreamIo,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if !flags.is_empty() {
                // Unary methods should have empty flags
                return Err(Status::invalid_request_flags(Flags::empty(), flags));
            }

            let payload: Input = payload.decode().map_err(Status::failed_to_decode)?;

            let fut = (self.method)(payload);

            let output = handle_server_unary(&stream.tx, fut);
            let monitor = monitor_client_stream(&mut stream.rx);

            join_first! {
                output,
                monitor,
                handle_timeout(),
            }
        })
    }
}

impl<
    Input: prost::Message + Default,
    Output: prost::Message + Default,
    StrmOut: Stream<Item = Result<Output>> + Send,
    F: Fn(Input) -> StrmOut + Send + Sync,
> MethodHandler for ServerStreamingMethod<Input, Output, F>
{
    fn handle<'a>(
        &'a self,
        flags: Flags,
        payload: RawBytes,
        stream: &'a mut StreamIo,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if flags.bits() != Flags::REMOTE_CLOSED.bits() {
                // REMOTE_CLOSED must be set (as the client is not a stream)
                // NO_DATA must not be set, as we need to parse a payload
                return Err(Status::invalid_request_flags(Flags::REMOTE_CLOSED, flags));
            }

            let payload: Input = payload.decode().map_err(Status::failed_to_decode)?;

            let output_strm = (self.method)(payload);

            let output = handle_server_stream(&stream.tx, output_strm);
            let monitor = monitor_client_stream(&mut stream.rx);

            join_first! {
                output,
                monitor,
                handle_timeout(),
            }
        })
    }
}

impl<
    Input: prost::Message + Default,
    Output: prost::Message + Default,
    FutOut: Future<Output = Result<Output>> + Send,
    F: Fn(UnboundedReceiverStream<Input>) -> FutOut + Send + Sync,
> MethodHandler for ClientStreamingMethod<Input, Output, F>
{
    fn handle<'a>(
        &'a self,
        flags: Flags,
        payload: RawBytes,
        stream: &'a mut StreamIo,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if flags.bits() != Flags::REMOTE_OPEN.bits() {
                // Per the ttRPC spec, a non-unary request from a still-sending client carries
                // exactly REMOTE_OPEN. Stream data arrives in subsequent Data frames, not the
                // request payload (which is empty), so NO_DATA is a Data-frame-only flag, it must
                // not be set here.
                return Err(Status::invalid_request_flags(Flags::REMOTE_OPEN, flags));
            }

            let () = payload.decode().map_err(Status::failed_to_decode)?;

            let (input_tx, input_strm) = make_input_stream();

            let output_fut = (self.method)(input_strm);

            // `drive_client_input` owns `rx` alone: it feeds the client's stream data, then
            // watches for a post-close protocol violation. `output` writes on `tx`. `output`
            // completing implies the input was consumed, so it's the completion condition and
            // `drive_client_input` rides along as the violation detector.
            let output = handle_server_unary(&stream.tx, output_fut);
            let input = drive_client_input(&mut stream.rx, input_tx);

            join_first! {
                output,
                input,
                handle_timeout(),
            }
        })
    }
}

impl<
    Input: prost::Message + Default,
    Output: prost::Message + Default,
    StrmOut: Stream<Item = Result<Output>> + Send,
    F: Fn(UnboundedReceiverStream<Input>) -> StrmOut + Send + Sync,
> MethodHandler for DuplexStreamingMethod<Input, Output, F>
{
    fn handle<'a>(
        &'a self,
        flags: Flags,
        payload: RawBytes,
        stream: &'a mut StreamIo,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if flags.bits() != Flags::REMOTE_OPEN.bits() {
                // Per the ttRPC spec, a non-unary request from a still-sending client carries
                // exactly REMOTE_OPEN. Stream data arrives in subsequent Data frames, not the
                // request payload (which is empty), so NO_DATA is a Data-frame-only flag, it must
                // not be set here.
                return Err(Status::invalid_request_flags(Flags::REMOTE_OPEN, flags));
            }

            let () = payload.decode().map_err(Status::failed_to_decode)?;

            let (input_tx, input_strm) = make_input_stream();

            let output_strm = (self.method)(input_strm);

            // See `ClientStreamingMethod`: `drive_client_input` owns `rx`, `output` writes on
            // `tx`; `output` completing (its stream drained) is the completion condition.
            let output = handle_server_stream(&stream.tx, output_strm);
            let input = drive_client_input(&mut stream.rx, input_tx);

            join_first! {
                output,
                input,
                handle_timeout(),
            }
        })
    }
}

fn make_input_stream<Input>() -> (UnboundedSender<Input>, UnboundedReceiverStream<Input>) {
    let (tx, rx) = unbounded_channel::<Input>();
    let strm = UnboundedReceiverStream::new(rx);
    (tx, strm)
}

async fn drive_client_input<Input: prost::Message + Default>(
    rx: &mut StreamReceiver,
    tx: UnboundedSender<Input>,
) -> Result<()> {
    // Feed the client's input stream until it signals REMOTE_CLOSED.
    while let Some(frame) = rx.recv().await {
        let Data { payload } = frame
            .message
            .decode::<Data>()
            .map_err(Status::failed_to_decode)?;

        if frame.flags.contains(Flags::NO_DATA) {
            payload.ensure_empty().map_err(Status::failed_to_decode)?;
        } else {
            _ = tx.send(payload.decode().map_err(Status::failed_to_decode)?);
        }

        if frame.flags.contains(Flags::REMOTE_CLOSED) {
            break;
        }
    }

    // End the handler's input stream (so it can produce its response), then treat any further
    // frame from the client as a protocol violation.
    drop(tx);
    if rx.recv().await.is_some() {
        return Err(Status::stream_closed(rx.id()));
    }
    Ok(())
}

async fn monitor_client_stream(rx: &mut StreamReceiver) -> Result<()> {
    if rx.recv().await.is_some() {
        return Err(Status::stream_closed(rx.id()));
    }
    Ok(())
}

async fn handle_server_stream<Output: prost::Message + Default>(
    tx: &StreamSender,
    strm: impl Stream<Item = Result<Output>>,
) -> Result<()> {
    tokio::pin!(strm);

    while let Some(data) = strm.try_next().await? {
        tx.data(data).await.map_err(Status::send_error)?;
    }

    tx.close_data().await.map_err(Status::send_error)?;

    Ok(())
}

async fn handle_server_unary<Output: prost::Message + Default>(
    tx: &StreamSender,
    fut: impl Future<Output = Result<Output>>,
) -> Result<()> {
    let response = fut.await?;
    tx.respond(response).await.map_err(Status::send_error)?;
    Ok(())
}

async fn handle_timeout() -> Result<()> {
    let t = get_context().timeout;
    match t {
        Timeout::Duration(t) => sleep(t).await,
        Timeout::None => pending::<()>().await,
    }
    Err(Status::timeout())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::MessageIo;
    use crate::service::Service;
    use crate::types::frame::StreamFrame;
    use crate::types::protos::{Request, Response};
    use std::sync::Arc;

    /// A service whose one unary method blocks forever, so the `output` branch never wins the
    /// race — any client protocol violation is detected deterministically by the monitor.
    struct BlockingService;

    impl Service for BlockingService {
        fn methods(&self) -> Vec<(&'static str, Arc<dyn MethodHandler + Send + Sync>)> {
            vec![(
                "/echo.Blocking/Wait",
                Arc::new(UnaryMethod::new(|_input: ()| async move {
                    pending::<Result<()>>().await
                })),
            )]
        }
    }

    /// The server's per-call monitor must reject a client that sends an unexpected frame during
    /// a (unary) call. The method blocks forever, so the monitor is the only branch
    /// that can complete, making this deterministic.
    #[tokio::test]
    async fn server_rejects_unexpected_frame_during_unary_call() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        tokio::spawn(async move {
            let mut server = crate::ServerConnection::new(server_io);
            server.register(BlockingService);
            _ = server.start().await;
        });

        // Raw client: drive frames directly so we can misbehave.
        let mut tasks = tokio::task::JoinSet::<std::io::Result<()>>::new();
        let mut io = MessageIo::new(&mut tasks, client_io, 64);
        let id = 1u32;

        io.tx
            .send(
                id,
                StreamFrame {
                    flags: Flags::empty(),
                    message: Request {
                        service: "echo.Blocking".to_owned(),
                        method: "Wait".to_owned(),
                        payload: (),
                        metadata: vec![],
                        timeout_nano: 0,
                    },
                },
            )
            .await
            .expect("send request");

        // An unexpected extra frame on the same stream — a protocol violation.
        io.tx
            .send(
                id,
                StreamFrame {
                    flags: Flags::empty(),
                    message: Data { payload: () },
                },
            )
            .await
            .expect("send extra frame");

        let (_id, frame) = io.rx.recv().await.expect("a response frame");
        let response: Response = frame.message.decode().expect("decode response");
        let status = response.status.unwrap_or_default();
        assert_ne!(
            status.code,
            crate::Code::Ok as i32,
            "expected an error status from the violation monitor"
        );
    }
}
