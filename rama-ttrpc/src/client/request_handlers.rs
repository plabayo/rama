use std::borrow::Cow;
use std::future::{Future, pending};

use rama_core::futures::async_stream::try_stream_fn;
use rama_core::futures::future::FusedFuture as _;
use rama_core::futures::{FutureExt as _, Stream, StreamExt as _};
use rama_core::stream::wrappers::UnboundedReceiverStream;
use tokio::pin;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tokio::sync::oneshot;
use tokio::time::sleep;

use crate::context::timeout::Timeout;
use crate::io::{StreamReceiver, StreamSender};
use crate::types::encoding::BufExt;
use crate::types::flags::Flags;
use crate::types::frame::StreamFrame;
use crate::types::protos::{Data, Request, Response};
use crate::{Client, Code, Result, Status};

pub trait RequestHandler {
    fn handle_unary_request<
        Input: prost::Message + Default + 'static,
        Output: prost::Message + Default + 'static,
    >(
        &self,
        service: &'static str,
        method: &'static str,
        payload: Input,
    ) -> impl Future<Output = Result<Output>> + Send;

    fn handle_server_streaming_request<
        Input: prost::Message + Default + 'static,
        Output: prost::Message + Default + 'static,
    >(
        &self,
        service: &'static str,
        method: &'static str,
        payload: Input,
    ) -> impl Stream<Item = Result<Output>> + Send;

    fn handle_client_streaming_request<
        Input: prost::Message + Default + 'static,
        Output: prost::Message + Default + 'static,
    >(
        &self,
        service: &'static str,
        method: &'static str,
        input: impl Stream<Item = Input> + Send,
    ) -> impl Future<Output = Result<Output>> + Send;

    fn handle_duplex_streaming_request<
        Input: prost::Message + Default + 'static,
        Output: prost::Message + Default + 'static,
    >(
        &self,
        service: &'static str,
        method: &'static str,
        input: impl Stream<Item = Input> + Send,
    ) -> impl Stream<Item = Result<Output>> + Send;
}

macro_rules! try_join_all {
    ($($e:expr),* $(,)?) => { async {
        tokio::try_join! { $($e),* }.map(|_| ())
    } };
}

macro_rules! join_first {
    ($($e:expr),* $(,)?) => { tokio::select! {
        $(res = $e => res),+
    } };
}

impl RequestHandler for Client {
    async fn handle_unary_request<
        Input: prost::Message + Default + 'static,
        Output: prost::Message + Default + 'static,
    >(
        &self,
        service: &'static str,
        method: &'static str,
        payload: Input,
    ) -> Result<Output> {
        let (output_tx, output_rx) = oneshot::channel();
        let metadata = self.context.metadata.keyvalue_iter().collect();
        let timeout = self.context.timeout;

        let frame = StreamFrame {
            flags: Flags::empty(),
            message: Request {
                service: Cow::Borrowed(service),
                method: Cow::Borrowed(method),
                payload,
                metadata,
                timeout_nano: timeout.as_nanos(),
            },
        };

        let fut = self.spawn_stream(frame, move |res, stream| async move {
            res.await.map_err(Status::send_error)?;

            // The client reads its one response; any trailing frames are the server's concern
            // and we've already got our answer.
            let mut rx = stream.split().1;

            join_first! {
                handle_server_unary(&mut rx, output_tx),
                handle_timeout(timeout),
            }
        });

        tokio::select! {
            Err(err) = fut => Err(err),
            Ok(val) = output_rx => Ok(val),
            else => Err(Status::channel_closed()),
        }
    }

    fn handle_server_streaming_request<
        Input: prost::Message + Default + 'static,
        Output: prost::Message + Default + 'static,
    >(
        &self,
        service: &'static str,
        method: &'static str,
        payload: Input,
    ) -> impl Stream<Item = Result<Output>> + Send {
        let (output_tx, mut output_rx) = unbounded_channel();
        let metadata = self.context.metadata.keyvalue_iter().collect();
        let timeout = self.context.timeout;

        let frame = StreamFrame {
            flags: Flags::REMOTE_CLOSED,
            message: Request {
                service: Cow::Borrowed(service),
                method: Cow::Borrowed(method),
                payload,
                metadata,
                timeout_nano: timeout.as_nanos(),
            },
        };

        let fut = self.spawn_stream(frame, move |res, stream| async move {
            res.await.map_err(Status::send_error)?;

            let mut rx = stream.split().1;

            join_first! {
                handle_server_stream(&mut rx, output_tx),
                handle_timeout(timeout),
            }
        });

        try_stream_fn(move |mut yielder| async move {
            let fut = fut.fuse();
            pin!(fut);
            loop {
                let next = tokio::select! {
                    Err(err) = &mut fut, if !fut.is_terminated() => Err(err),
                    Some(val) = output_rx.recv() => Ok(val),
                    else => break,
                };
                yielder.yield_ok(next?).await;
            }
            Ok(())
        })
    }

    async fn handle_client_streaming_request<
        Input: prost::Message + Default + 'static,
        Output: prost::Message + Default + 'static,
    >(
        &self,
        service: &'static str,
        method: &'static str,
        input: impl Stream<Item = Input> + Send,
    ) -> Result<Output> {
        let (output_tx, output_rx) = oneshot::channel();
        let (input, input_fut) = handle_input_stream(input);
        let metadata = self.context.metadata.keyvalue_iter().collect();
        let timeout = self.context.timeout;

        let frame = StreamFrame {
            // Per the ttRPC spec, a still-sending client sets only REMOTE_OPEN; the request
            // payload is empty and stream data follows in Data frames (NO_DATA is Data-only).
            flags: Flags::REMOTE_OPEN,
            message: Request {
                service: Cow::Borrowed(service),
                method: Cow::Borrowed(method),
                payload: (),
                metadata,
                timeout_nano: timeout.as_nanos(),
            },
        };

        let fut = self.spawn_stream(frame, move |res, stream| async move {
            res.await.map_err(Status::send_error)?;

            let (tx, mut rx) = stream.split();

            let input = handle_client_stream(&tx, input);
            let output = handle_server_unary(&mut rx, output_tx);

            join_first! {
                try_join_all! {
                    input,
                    output,
                },
                handle_timeout(timeout),
            }
        });

        tokio::select! {
            Err(err) = input_fut => Err(err),
            Err(err) = fut => Err(err),
            Ok(val) = output_rx => Ok(val),
            else => Err(Status::channel_closed()),
        }
    }

    fn handle_duplex_streaming_request<
        Input: prost::Message + Default + 'static,
        Output: prost::Message + Default + 'static,
    >(
        &self,
        service: &'static str,
        method: &'static str,
        input: impl Stream<Item = Input> + Send,
    ) -> impl Stream<Item = Result<Output>> + Send {
        let (output_tx, mut output_rx) = unbounded_channel::<Output>();
        let (input, input_fut) = handle_input_stream(input);
        let metadata = self.context.metadata.keyvalue_iter().collect();
        let timeout = self.context.timeout;

        let frame = StreamFrame {
            // Per the ttRPC spec, a still-sending client sets only REMOTE_OPEN; the request
            // payload is empty and stream data follows in Data frames (NO_DATA is Data-only).
            flags: Flags::REMOTE_OPEN,
            message: Request {
                service: Cow::Borrowed(service),
                method: Cow::Borrowed(method),
                payload: (),
                metadata,
                timeout_nano: timeout.as_nanos(),
            },
        };

        let fut = self.spawn_stream(frame, move |res, stream| async move {
            res.await.map_err(Status::send_error)?;

            let (tx, mut rx) = stream.split();

            let input = handle_client_stream(&tx, input);
            let output = handle_server_stream(&mut rx, output_tx);

            join_first! {
                try_join_all! {
                    input,
                    output,
                },
                handle_timeout(timeout),
            }
        });

        try_stream_fn(move |mut yielder| async move {
            let fut = fut.fuse();
            let input_fut = input_fut.fuse();
            pin!(fut);
            pin!(input_fut);
            loop {
                let next = tokio::select! {
                    _ = &mut input_fut, if !input_fut.is_terminated() => continue,
                    Err(err) = &mut fut, if !fut.is_terminated() => Err(err),
                    Some(val) = output_rx.recv() => Ok(val),
                    else => break,
                };
                yielder.yield_ok(next?).await;
            }
            Ok(())
        })
    }
}

async fn handle_client_stream<Input: prost::Message + Default>(
    tx: &StreamSender,
    strm: impl Stream<Item = Input>,
) -> Result<()> {
    struct CloseGuard<'a>(&'a StreamSender);
    impl<'a> Drop for CloseGuard<'a> {
        fn drop(&mut self) {
            self.0.close_data();
        }
    }

    let _guard = CloseGuard(tx);

    tokio::pin!(strm);
    while let Some(data) = strm.next().await {
        tx.data(data).await.map_err(Status::send_error)?;
    }

    Ok(())
}

async fn handle_server_unary<Output: prost::Message + Default>(
    rx: &mut StreamReceiver,
    tx: oneshot::Sender<Output>,
) -> Result<()> {
    let Some(frame) = rx.recv().await else {
        return Err(Status::channel_closed());
    };
    if !frame.flags.is_valid_response_frame() {
        return Err(Status::invalid_frame_flags(frame.flags));
    }
    let response: Response = frame.message.decode().map_err(Status::failed_to_decode)?;
    let status = response.status.unwrap_or_default();
    if status.code != Code::Ok as i32 {
        return Err(status);
    }
    _ = tx.send(
        response
            .payload
            .decode()
            .map_err(Status::failed_to_decode)?,
    );
    Ok(())
}

async fn handle_server_stream<Output: prost::Message + Default>(
    rx: &mut StreamReceiver,
    tx: UnboundedSender<Output>,
) -> Result<()> {
    while let Some(frame) = rx.recv().await {
        if let Ok(response) = frame.message.decode::<Response>() {
            if !frame.flags.is_valid_response_frame() {
                return Err(Status::invalid_frame_flags(frame.flags));
            }
            response
                .payload
                .ensure_empty()
                .map_err(Status::failed_to_decode)?;
            let status = response.status.unwrap_or_default();
            // A final `Response` terminates the stream. An OK status is normal termination (the
            // spec permits a final empty OK response after streamed data), not an error.
            if status.code != Code::Ok as i32 {
                return Err(status);
            }
            return Ok(());
        }

        if !frame.flags.is_valid_data_frame() {
            return Err(Status::invalid_frame_flags(frame.flags));
        }
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

    Ok(())
}

async fn handle_timeout(t: Timeout) -> Result<()> {
    match t {
        Timeout::Duration(t) => sleep(t).await,
        Timeout::None => pending::<()>().await,
    }
    Err(Status::timeout())
}

fn handle_input_stream<T: Send>(
    input: impl Stream<Item = T> + Send,
) -> (
    UnboundedReceiverStream<T>,
    impl Future<Output = Result<()>> + Send,
) {
    let (tx, rx) = unbounded_channel();
    let fut = async move {
        pin!(input);
        while let Some(val) = input.next().await {
            _ = tx.send(val);
            // `tx.send` on an unbounded channel is synchronous, so an always-ready input
            // stream would never yield and could monopolize the runtime, starving the
            // concurrently driven network and timeout branches. Cooperatively yield once this
            // task's scheduler budget is spent.
            tokio::task::coop::consume_budget().await;
        }
        Ok(())
    };

    let input = UnboundedReceiverStream::new(rx);

    (input, fut)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_forwarding_does_not_monopolize_single_threaded_runtime() {
        let (done_tx, done_rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("build current-thread runtime");
            rt.block_on(async {
                let input = rama_core::futures::stream::repeat(0u8);
                let (recv, input_fut) = handle_input_stream(input);
                // Keep the receiver alive so the sender stays open.
                let _recv = recv;

                tokio::select! {
                    biased;
                    _ = input_fut => {}
                    _ = async {
                        for _ in 0..500 {
                            tokio::task::yield_now().await;
                        }
                    } => {}
                }
            });
            _ = done_tx.send(());
        });

        assert!(
            done_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .is_ok(),
            "input forwarding monopolized the single-threaded runtime"
        );
    }

    /// The ttRPC spec lets a server end a non-unary stream with a final OK `Response` (rather
    /// than a `Data(REMOTE_CLOSED)`). The client must treat that as clean termination, not turn
    /// it into `Err(Status { code: Ok })`.
    #[tokio::test]
    async fn server_stream_terminal_ok_response_ends_stream_cleanly() {
        use crate::io::StreamIo;
        use crate::server::method_handlers::MethodHandler;
        use crate::service::Service;
        use crate::types::protos::raw_bytes::RawBytes;
        use crate::{Client, ServerConnection};
        use rama_core::futures::StreamExt as _;
        use std::pin::Pin;
        use std::sync::Arc;

        #[derive(Clone, PartialEq, ::prost::Message)]
        struct Item {
            #[prost(uint32, tag = "1")]
            n: u32,
        }

        struct FinalOkService;
        impl Service for FinalOkService {
            fn methods(&self) -> Vec<(&'static str, Arc<dyn MethodHandler + Send + Sync>)> {
                vec![("/echo.Svc/Stream", Arc::new(FinalOkHandler))]
            }
        }

        struct FinalOkHandler;
        impl MethodHandler for FinalOkHandler {
            fn handle<'a>(
                &'a self,
                _flags: Flags,
                _payload: RawBytes,
                stream: &'a mut StreamIo,
            ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
                Box::pin(async move {
                    stream
                        .tx
                        .data(Item { n: 7 })
                        .await
                        .map_err(Status::send_error)?;
                    // Terminate the stream with a final OK Response instead of Data(REMOTE_CLOSED).
                    stream.tx.respond(()).await.map_err(Status::send_error)?;
                    Ok(())
                })
            }
        }

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut server = ServerConnection::new(server_io);
            server.register(FinalOkService);
            _ = server.start().await;
        });
        let client = Client::new(client_io);

        let stream = client.handle_server_streaming_request::<(), Item>("echo.Svc", "Stream", ());
        let got: Vec<Result<Item>> = Box::pin(stream).collect().await;

        let items: Vec<Item> = got
            .into_iter()
            .map(|r| r.expect("a terminal OK response must not surface as an error"))
            .collect();
        assert_eq!(items, vec![Item { n: 7 }]);
    }
}
