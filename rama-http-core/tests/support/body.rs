//! Frame fixtures shared by body-layer transport tests.

use rama_core::bytes::Bytes;
use rama_http::{StreamingBody, body::Frame};
use std::{
    collections::VecDeque,
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndStreamFraming {
    LastData,
    EmptyData,
}

impl EndStreamFraming {
    pub(crate) const ALL: [Self; 2] = [Self::LastData, Self::EmptyData];

    pub(crate) fn body(self, data: Bytes) -> Frames {
        let mut frames = VecDeque::from([Frame::data(data)]);
        if self == Self::EmptyData {
            frames.push_back(Frame::data(Bytes::new()));
        }
        Frames(frames)
    }
}

pub(crate) struct Frames(pub(crate) VecDeque<Frame<Bytes>>);

impl StreamingBody for Frames {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.0.pop_front().map(Ok))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_empty()
    }
}
