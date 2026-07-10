use std::future::{Future, pending};

use rama_core::futures::async_stream::try_stream_fn;
use rama_core::futures::future::FusedFuture as _;
use rama_core::futures::{FutureExt as _, Stream, StreamExt as _};
use rama_core::stream::wrappers::UnboundedReceiverStream;
use tokio::pin;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tokio::sync::{RwLock, oneshot};
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
        service: String,
        method: String,
        payload: Input,
    ) -> impl Future<Output = Result<Output>> + Send;

    fn handle_server_streaming_request<
        Input: prost::Message + Default + 'static,
        Output: prost::Message + Default + 'static,
    >(
        &self,
        service: String,
        method: String,
        payload: Input,
    ) -> impl Stream<Item = Result<Output>> + Send;

    fn handle_client_streaming_request<
        Input: prost::Message + Default + 'static,
        Output: prost::Message + Default + 'static,
    >(
        &self,
        service: String,
        method: String,
        input: impl Stream<Item = Input> + Send,
    ) -> impl Future<Output = Result<Output>> + Send;

    fn handle_duplex_streaming_request<
        Input: prost::Message + Default + 'static,
        Output: prost::Message + Default + 'static,
    >(
        &self,
        service: String,
        method: String,
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
        service: String,
        method: String,
        payload: Input,
    ) -> Result<Output> {
        let (output_tx, output_rx) = oneshot::channel();
        let metadata = self.context.metadata.keyvalue_iter().collect();
        let timeout = self.context.timeout;

        let frame = StreamFrame {
            flags: Flags::empty(),
            message: Request {
                service,
                method,
                payload,
                metadata,
                timeout_nano: timeout.as_nanos(),
            },
        };

        let fut = self.spawn_stream(frame, move |res, mut stream| async move {
            res.await.map_err(Status::send_error)?;

            let rx = RwLock::new(&mut stream.rx);

            let output = handle_server_unary(&rx, output_tx);
            let monitor = monitor_server_stream(&rx);
            let timeout = handle_timeout(timeout);

            join_first! {
                try_join_all! {
                    output,
                },
                monitor,
                timeout,
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
        service: String,
        method: String,
        payload: Input,
    ) -> impl Stream<Item = Result<Output>> + Send {
        let (output_tx, mut output_rx) = unbounded_channel();
        let metadata = self.context.metadata.keyvalue_iter().collect();
        let timeout = self.context.timeout;

        let frame = StreamFrame {
            flags: Flags::REMOTE_CLOSED,
            message: Request {
                service,
                method,
                payload,
                metadata,
                timeout_nano: timeout.as_nanos(),
            },
        };

        let fut = self.spawn_stream(frame, move |res, mut stream| async move {
            res.await.map_err(Status::send_error)?;

            let rx = RwLock::new(&mut stream.rx);

            let output = handle_server_stream(&rx, output_tx);
            let monitor = monitor_server_stream(&rx);
            let timeout = handle_timeout(timeout);

            join_first! {
                try_join_all! {
                    output,
                },
                monitor,
                timeout,
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
        service: String,
        method: String,
        input: impl Stream<Item = Input> + Send,
    ) -> Result<Output> {
        let (output_tx, output_rx) = oneshot::channel();
        let (input, input_fut) = handle_input_stream(input);
        let metadata = self.context.metadata.keyvalue_iter().collect();
        let timeout = self.context.timeout;

        let frame = StreamFrame {
            flags: Flags::REMOTE_OPEN | Flags::NO_DATA,
            message: Request {
                service,
                method,
                payload: (),
                metadata,
                timeout_nano: timeout.as_nanos(),
            },
        };

        let fut = self.spawn_stream(frame, move |res, mut stream| async move {
            res.await.map_err(Status::send_error)?;

            let rx = RwLock::new(&mut stream.rx);

            let input = handle_client_stream(&stream.tx, input);
            let output = handle_server_unary(&rx, output_tx);
            let monitor = monitor_server_stream(&rx);
            let timeout = handle_timeout(timeout);

            join_first! {
                try_join_all! {
                    input,
                    output,
                },
                monitor,
                timeout,
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
        service: String,
        method: String,
        input: impl Stream<Item = Input> + Send,
    ) -> impl Stream<Item = Result<Output>> + Send {
        let (output_tx, mut output_rx) = unbounded_channel::<Output>();
        let (input, input_fut) = handle_input_stream(input);
        let metadata = self.context.metadata.keyvalue_iter().collect();
        let timeout = self.context.timeout;

        let frame = StreamFrame {
            flags: Flags::REMOTE_OPEN | Flags::NO_DATA,
            message: Request {
                service,
                method,
                payload: (),
                metadata,
                timeout_nano: timeout.as_nanos(),
            },
        };

        let fut = self.spawn_stream(frame, move |res, mut stream| async move {
            res.await.map_err(Status::send_error)?;

            let rx = RwLock::new(&mut stream.rx);

            let input = handle_client_stream(&stream.tx, input);
            let output = handle_server_stream(&rx, output_tx);
            let monitor = monitor_server_stream(&rx);
            let timeout = handle_timeout(timeout);

            join_first! {
                try_join_all! {
                    input,
                    output,
                },
                monitor,
                timeout,
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

fn handle_server_unary<'a, Output: prost::Message + Default + 'a>(
    rx: &'a RwLock<&'a mut StreamReceiver>,
    tx: oneshot::Sender<Output>,
) -> impl Future<Output = Result<()>> + Send + 'a {
    #[expect(
        clippy::unwrap_used,
        reason = "try_write runs synchronously before any await on a lock owned solely by this handler, so it cannot be contended"
    )]
    let mut rx = rx.try_write().unwrap();
    async move {
        let Some(frame) = rx.recv().await else {
            return Err(Status::channel_closed());
        };
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
}

fn handle_server_stream<'a, Output: prost::Message + Default + 'a>(
    rx: &'a RwLock<&'a mut StreamReceiver>,
    tx: UnboundedSender<Output>,
) -> impl Future<Output = Result<()>> + Send + 'a {
    #[expect(
        clippy::unwrap_used,
        reason = "try_write runs synchronously before any await on a lock owned solely by this handler, so it cannot be contended"
    )]
    let mut rx = rx.try_write().unwrap();
    async move {
        while let Some(frame) = rx.recv().await {
            if let Ok(response) = frame.message.decode::<Response>() {
                response
                    .payload
                    .ensure_empty()
                    .map_err(Status::failed_to_decode)?;
                let status = response.status.unwrap_or_default();
                return Err(status);
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
}

async fn monitor_server_stream(rx: &RwLock<&mut StreamReceiver>) -> Result<()> {
    let mut rx = rx.write().await;
    if rx.recv().await.is_some() {
        return Err(Status::stream_closed(rx.id()));
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
        }
        Ok(())
    };

    let input = UnboundedReceiverStream::new(rx);

    (input, fut)
}
