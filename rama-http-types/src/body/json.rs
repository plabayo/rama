//! Adopted from
//! <https://github.com/resyncgg/json-stream/blob/ee03a562e851074171d29ee68a5c511c1c451fa4/src/lib.rs>
//!
//! Original license: <https://github.com/resyncgg/json-stream/blob/ee03a562e851074171d29ee68a5c511c1c451fa4/LICENSE>
//! by https://github.com/resyncgg

use std::{
    collections::VecDeque,
    ops::Deref,
    pin::Pin,
    task::{Context, Poll, ready},
};

use pin_project_lite::pin_project;

use rama_core::{futures::stream::Stream, telemetry::tracing};
use serde::de::DeserializeOwned;
use serde_json::Deserializer;

// should be 2^n - 1 for VecDeque to work efficiently
const DEFAULT_BUFFER_CAPACITY: usize = 1024 * 16 - 1; // 256KB
/// The default buffer capacity for the [`JsonStream`]. This is the maximum amount of bytes that
/// will be buffered before the stream is terminated, by default.
const DEFAULT_MAX_BUFFER_CAPACITY: usize = 1024 * 1024 * 8 - 1; // 8 MB

pin_project! {
    /// A [`Stream`] implementation that can be used to parse Newline Delimited JSON values from a byte stream.
    /// It does so by buffering bytes internally and parsing them as they are received.
    /// This means that the stream will not yield values until a full JSON value has been received.
    ///
    /// After a full JSON value has been parsed and yielded, the stream will delete the bytes that were used
    /// to parse the value from the internal buffer. This means that the stream will not use more memory than
    /// is necessary to contain the maximum buffer size specified) as well as any JSON values previously
    /// parsed but not yet yielded.
    pub struct JsonStream<T, S> {
        #[pin]
        stream: S,
        entry_buffer: Vec<T>,
        byte_buffer: VecDeque<u8>,
        finished: bool,
        max_buffer_capacity: usize,
    }
}

impl<T, S: Unpin> JsonStream<T, S> {
    /// Create a new [`JsonStream`] with the default buffer capacity.
    pub fn new(stream: S) -> Self {
        Self::new_with_max_capacity(stream, DEFAULT_MAX_BUFFER_CAPACITY)
    }

    /// Create a new [`JsonStream`] with a custom maximum buffer capacity.
    ///
    /// The maximum buffer capacity is the maximum amount of bytes that will be buffered before the
    /// stream is terminated. This is to prevent malformed streams from causing the server to run out
    /// of memory.
    ///
    /// As a rule of thumb, this number should be at least as large as the largest entry in the stream.
    /// Additionally, it's best if it's a power of 2 minus 1 (e.g. 1023, 2047, 4095, etc.) as this
    /// allows the internal buffer to be more efficient. This is not a requirement, however.
    ///
    /// Lastly, it is not guaranteed that this is the maximum amount of memory that will be used by
    /// the stream. This is because the internal buffer _may_ allocate 2x the amount of bytes specified
    /// as well as waste some space in the buffer.
    pub fn new_with_max_capacity(stream: S, max_capacity: usize) -> Self {
        Self {
            stream,
            entry_buffer: Vec::new(),
            byte_buffer: VecDeque::with_capacity(std::cmp::min(
                DEFAULT_BUFFER_CAPACITY,
                max_capacity,
            )),
            finished: false,
            max_buffer_capacity: max_capacity,
        }
    }

    /// Controls how large the internal buffer can grow in bytes. If the buffer grows larger than this
    /// the stream is terminated as it is assumed that the stream is malformed. If this number is too
    /// large, a malformed stream can cause the server to run out of memory.
    ///
    /// As a rule of thumb, this number should be at least as large as the largest entry in the stream.
    ///
    /// The default value is 8 MB.
    pub fn set_max_buffer_size(&mut self, max_capacity: usize) {
        self.max_buffer_capacity = max_capacity;
    }

    /// Marks this stream as "finished" which means that no more entries will be read from the
    /// underlying stream. While this stream is likely going to be dropped soon, we might as well
    /// clear memory we do not need to use.
    fn finish(mut self: Pin<&mut Self>) {
        self.finished = true;
        self.entry_buffer.clear();
        self.entry_buffer.shrink_to_fit();
        self.byte_buffer.clear();
        self.byte_buffer.shrink_to_fit();
    }
}

impl<T: DeserializeOwned, S, B, E> Stream for JsonStream<T, S>
where
    T: DeserializeOwned,
    B: Deref<Target = [u8]>,
    S: Stream<Item = Result<B, E>> + Unpin,
{
    type Item = Result<T, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // efficiently check if we should stop
        if self.finished {
            return Poll::Ready(None);
        }

        let mut this = self.as_mut().project();

        loop {
            // if we have an entry, we should return it immediately
            if let Some(entry) = this.entry_buffer.pop() {
                return Poll::Ready(Some(Ok(entry)));
            }

            // try to fetch the next chunk
            let next_chunk = match ready!(this.stream.as_mut().poll_next(cx)) {
                Some(Ok(chunk)) => chunk,
                Some(Err(err)) => {
                    self.finish();
                    return Poll::Ready(Some(Err(err)));
                }
                None => {
                    self.finish();
                    return Poll::Ready(None);
                }
            };

            // if there is no room for this chunk, we should give up
            match this.byte_buffer.len().checked_add(next_chunk.len()) {
                Some(new_size) if new_size > DEFAULT_MAX_BUFFER_CAPACITY => {
                    // no room for this chunk
                    self.finish();
                    return Poll::Ready(None);
                }
                None => {
                    // overflow occurred
                    self.finish();
                    return Poll::Ready(None);
                }
                _ => {}
            }

            // room is available, so let's add the chunk
            this.byte_buffer.extend(&*next_chunk);

            // because we inserted more data into the VecDeque, we need to reassure the layout of it
            this.byte_buffer.make_contiguous();
            // we know that all of the data will be located in the first slice
            let (buffer, _) = this.byte_buffer.as_slices();
            let mut json_iter = Deserializer::from_slice(buffer).into_iter::<T>();
            let mut last_read_pos = 0;

            // read each entry from the buffer
            loop {
                match json_iter.next() {
                    Some(Ok(entry)) => {
                        last_read_pos = json_iter.byte_offset();
                        this.entry_buffer.push(entry);
                    }
                    // if there was an error, log it but move on because this could be a partial entry
                    Some(Err(err)) => {
                        tracing::trace!(err = ?err, "failed to parse json entry");
                        break;
                    }
                    // nothing left then we move on
                    None => break,
                }
            }

            // remove the read bytes - this is very efficient as it's a ring buffer
            let _ = this.byte_buffer.drain(..last_read_pos);
            // realign the buffer to the beginning so we can get contiguous slices
            // we want to do this with all of the read bytes removed because this operation becomes a memcpy
            // if we waited until after we added bytes again, it could devolve into a much slower operation
            this.byte_buffer.make_contiguous();
        }
    }
}
