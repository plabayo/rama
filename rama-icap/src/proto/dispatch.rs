use std::task::{Context, Poll};
use futures_core::Stream;
use rama_core::error::BoxError;

use crate::{Error, Result};
use super::{
    conn::Conn,
    IcapMessage,
};

/// ICAP message dispatcher
pub(crate) struct Dispatcher<D> {
    conn: Conn,
    dispatch: D,
    message: Option<IcapMessage>,
    body_stream: Option<Box<dyn Stream<Item = Result<Bytes, Error>> + Send>>,
}

pub(crate) trait Dispatch {
    fn dispatch(&mut self, message: IcapMessage) -> Result<Option<IcapMessage>>;
    fn on_error(&mut self, err: &Error) -> Option<IcapMessage>;
}

impl Dispatcher
{
    pub(crate) fn new(dispatch: D, conn: Conn) -> Self {
        Self {
            conn,
            dispatch,
            message: None,
            body_stream: None,
        }
    }

    fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        loop {
            if let Some(message) = self.message.take() {
                match self.dispatch.dispatch(message)? {
                    Some(response) => {
                        self.conn.write_message(response)?;
                    }
                    None => {
                        continue;
                    }
                }
            }

            match self.conn.read_message(cx)? {
                Poll::Ready(Some(message)) => {
                    self.message = Some(message);
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }

    fn poll_write(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if let Some(stream) = self.body_stream.as_mut() {
            while let Poll::Ready(Some(chunk)) = Pin::new(stream).poll_next(cx) {
                self.conn.write_chunk(chunk)?;
            }
        }

        self.conn.poll_flush(cx)
    }
}

/// ICAP client dispatcher
pin_project_lite::pin_project! {
    pub(crate) struct Client<B> {
        callback: Option<crate::client::dispatch::Callback<IcapMessage, IcapMessage>>,
        #[pin]
        rx: ClientRx<B>,
        rx_closed: bool,
    }
}

type ClientRx<B> = crate::client::dispatch::Receiver<IcapMessage, IcapMessage>;

impl<B> Client<B> {
    pub(crate) fn new(rx: ClientRx<B>) -> Self {
        Client {
            callback: None,
            rx,
            rx_closed: false,
        }
    }
}

impl<B> Dispatch for Client<B>
where
    B: Body<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
{
    fn dispatch(&mut self, message: IcapMessage) -> Result<Option<IcapMessage>> {
        // 处理接收到的 ICAP 消息
        if let Some(callback) = self.callback.take() {
            callback.send(Ok((message, Body::empty())));
        }
        Ok(None)
    }

    fn on_error(&mut self, err: &Error) -> Option<IcapMessage> {
        // 处理错误情况
        if let Some(callback) = self.callback.take() {
            callback.send(Err(err.clone().into()));
        }
        None
    }

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ()>> {
        // 检查是否准备好处理新的请求
        if self.callback.is_some() {
            // 还有未完成的请求
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_msg(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<IcapMessage, Error>>> {
        // 轮询新的请求
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some((msg, cb))) => {
                match cb.poll_canceled(cx) {
                    Poll::Ready(()) => {
                        trace!("request canceled");
                        Poll::Ready(None)
                    }
                    Poll::Pending => {
                        self.callback = Some(cb);
                        Poll::Ready(Some(Ok(msg)))
                    }
                }
            }
            Poll::Ready(None) => {
                trace!("client tx closed");
                self.rx_closed = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    // 測試用的分發器
    struct TestDispatch;

    impl Dispatch for TestDispatch {
        fn dispatch(&mut self, message: IcapMessage) -> Result<Option<IcapMessage>> {
            Ok(Some(message))
        }

        fn on_error(&mut self, _err: &Error) -> Option<IcapMessage> {
            None
        }
    }
}