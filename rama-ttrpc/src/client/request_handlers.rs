use std::borrow::Cow;
use std::future::{Future, pending};

use rama_core::futures::async_stream::try_stream_fn;
use rama_core::futures::future::FusedFuture as _;
use rama_core::futures::{FutureExt as _, Stream, StreamExt as _};
use rama_core::stream::wrappers::ReceiverStream;
use tokio::pin;
use tokio::sync::mpsc::{Sender, channel};
use tokio::sync::oneshot;

use crate::io::{StreamReceiver, StreamSender};
use crate::types::encoding::BufExt;
use crate::types::flags::Flags;
use crate::types::frame::StreamFrame;
use crate::types::message::MessageType;
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
        let deadline = timeout.deadline();

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
                handle_timeout(deadline),
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
        let (output_tx, mut output_rx) = channel(crate::io::DEFAULT_MAX_BUFFERED_FRAMES);
        let metadata = self.context.metadata.keyvalue_iter().collect();
        let timeout = self.context.timeout;
        let deadline = timeout.deadline();

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
                handle_timeout(deadline),
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
        let deadline = timeout.deadline();

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
                handle_timeout(deadline),
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
        let (output_tx, mut output_rx) = channel::<Output>(crate::io::DEFAULT_MAX_BUFFERED_FRAMES);
        let (input, input_fut) = handle_input_stream(input);
        let metadata = self.context.metadata.keyvalue_iter().collect();
        let timeout = self.context.timeout;
        let deadline = timeout.deadline();

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
                handle_timeout(deadline),
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
    // Response-frame flags carry no meaning; like the Go client (containerd/ttrpc client.go
    // `RecvMsg` never reads them on Response frames) they are ignored.
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
    tx: Sender<Output>,
) -> Result<()> {
    while let Some(frame) = rx.recv().await {
        if frame.message.ty == MessageType::Response {
            let response: Response = frame.message.decode().map_err(Status::failed_to_decode)?;
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

        // Anything but Data fails the decode's type check, the per-call protocol error the Go
        // client also raises (containerd/ttrpc client.go `RecvMsg` default arm). Only the
        // REMOTE_CLOSED/NO_DATA flag bits are interpreted; other bits are ignored like Go.
        let Data { payload } = frame
            .message
            .decode::<Data>()
            .map_err(Status::failed_to_decode)?;

        if frame.flags.contains(Flags::NO_DATA) {
            payload.ensure_empty().map_err(Status::failed_to_decode)?;
        } else if tx
            .send(payload.decode().map_err(Status::failed_to_decode)?)
            .await
            .is_err()
        {
            // The consumer dropped the returned stream; stop reading (also applies backpressure
            // when the consumer is merely slow, since the bounded send awaits).
            return Ok(());
        }

        if frame.flags.contains(Flags::REMOTE_CLOSED) {
            break;
        }
    }

    Ok(())
}

async fn handle_timeout(deadline: Option<tokio::time::Instant>) -> Result<()> {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => pending::<()>().await,
    }
    Err(Status::timeout())
}

fn handle_input_stream<T: Send>(
    input: impl Stream<Item = T> + Send,
) -> (ReceiverStream<T>, impl Future<Output = Result<()>> + Send) {
    let (tx, rx) = channel(crate::io::DEFAULT_MAX_BUFFERED_FRAMES);
    let fut = async move {
        pin!(input);
        while let Some(val) = input.next().await {
            // Bounded send: awaits (backpressuring the input) when the wire side is slow, and
            // errors once the receiver is gone. This also yields on a full channel, so an
            // always-ready input can no longer monopolize the runtime.
            if tx.send(val).await.is_err() {
                break;
            }
        }
        Ok(())
    };

    let input = ReceiverStream::new(rx);

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
