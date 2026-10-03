use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, ReadBuf};

pub(crate) enum Step {
    Data(&'static [u8]),
    Pending,
    Err(std::io::ErrorKind),
}

/// Reader that plays back a script, then reads EOF.
pub(crate) struct ScriptReader(VecDeque<Step>);

impl ScriptReader {
    pub(crate) fn new(steps: impl IntoIterator<Item = Step>) -> Self {
        Self(steps.into_iter().collect())
    }
}

impl AsyncRead for ScriptReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.0.pop_front() {
            None => Poll::Ready(Ok(())),
            Some(Step::Pending) => Poll::Pending,
            Some(Step::Err(kind)) => Poll::Ready(Err(kind.into())),
            Some(Step::Data(data)) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.0.push_front(Step::Data(&data[n..]));
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

pub(crate) fn poll_read_once<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> Poll<std::io::Result<usize>> {
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut read_buf = ReadBuf::new(buf);
    Pin::new(reader)
        .poll_read(&mut cx, &mut read_buf)
        .map_ok(|()| read_buf.filled().len())
}
