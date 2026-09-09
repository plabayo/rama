use std::io::{BufWriter, Write as _};

use rama::{
    bytes::Bytes,
    error::{BoxError, ErrorContext as _},
    futures::{Stream, StreamExt as _, async_stream::stream_fn},
    stream::io::{ReaderStream, SyncIoBridge},
    utils::{guard::DropGuard, octets::kib},
};
use serde::Serialize;

pub(super) const JSON_BUFFER_SIZE: usize = kib(16);

/// Serialize typed views without retaining their complete JSON representation.
/// Work starts on the first body poll. A slow reader applies backpressure through
/// the bounded pipe; dropping it interrupts the blocking writer on its next write.
pub(super) fn json_bytes<T>(
    value: T,
    newline: bool,
) -> impl Stream<Item = Result<Bytes, BoxError>> + Send
where
    T: Serialize + Send + 'static,
{
    stream_fn(move |mut output| async move {
        let (writer, reader) = tokio::io::duplex(JSON_BUFFER_SIZE);
        let task = tokio::task::spawn_blocking(move || -> Result<(), BoxError> {
            let mut writer = BufWriter::with_capacity(JSON_BUFFER_SIZE, SyncIoBridge::new(writer));
            serde_json::to_writer(&mut writer, &value).context("serialize inspector view")?;
            if newline {
                writer
                    .write_all(b"\n")
                    .context("finish inspector JSON line")?;
            }
            writer.flush().context("flush inspector view")
        });
        let abort = task.abort_handle();
        // Skip queued work when its consumer disconnects. A writer that already
        // started instead stops when the reader below closes the bounded pipe.
        let _cancel = DropGuard::new(move || abort.abort());
        let mut reader = ReaderStream::with_capacity(reader, JSON_BUFFER_SIZE);
        while let Some(chunk) = reader.next().await {
            match chunk {
                Ok(bytes) => output.yield_item(Ok(bytes)).await,
                Err(error) => {
                    output.yield_item(Err(error.into())).await;
                    return;
                }
            }
        }
        let result = task
            .await
            .context("join inspector JSON writer")
            .and_then(|result| result);
        if let Err(error) = result {
            output.yield_item(Err(error)).await;
        }
    })
}
