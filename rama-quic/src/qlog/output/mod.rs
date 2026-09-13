use super::QlogEventView;
use rama_utils::str::arcstr::ArcStr;
use std::{io, time::Instant};

/// Metadata shared by the events in a recorder's output.
#[derive(Debug, Clone)]
pub struct TraceInfo {
    /// Short label for the output trace. Static labels can use `arcstr!`.
    pub title: Option<ArcStr>,
    /// Optional context for the trace, shared across metadata clones.
    pub description: Option<ArcStr>,
    /// Monotonic epoch used to express event timestamps as elapsed milliseconds.
    pub start_time: Instant,
}

/// Asynchronous storage, invoked by the recording task after event admission.
/// Methods may wait for I/O. Synchronous computation and destruction must finish promptly.
/// An error ends the recorder; partially written records are never retried automatically.
/// One task owns the output exclusively; `Send` permits executor migration.
/// Implementations remain concrete inside the task, without boxing a future per event.
pub trait QlogOutput: Send + 'static {
    /// Initialize output once, before processing events or flush requests.
    fn begin(&mut self, info: &TraceInfo) -> impl Future<Output = io::Result<()>> + Send;

    /// Write one observation in admission order; an error terminates recording.
    fn event(&mut self, event: &QlogEventView<'_>) -> impl Future<Output = io::Result<()>> + Send;

    /// Flush buffered output after all earlier admitted commands.
    fn flush(&mut self) -> impl Future<Output = io::Result<()>> + Send;

    /// Finalize output after draining accepted events. Defaults to flushing.
    fn finish(&mut self) -> impl Future<Output = io::Result<()>> + Send {
        self.flush()
    }
}

/// Streaming asynchronous serialization of borrowed events to caller-provided output.
/// Encoders can suspend at I/O backpressure without blocking an executor thread.
pub trait QlogEncoder: Send {
    /// Write trace metadata before the first event.
    fn begin<W: tokio::io::AsyncWrite + Unpin + Send>(
        &mut self,
        info: &TraceInfo,
        output: &mut W,
    ) -> impl Future<Output = io::Result<()>> + Send;

    /// Encode one borrowed observation, awaiting destination capacity as needed.
    fn event<W: tokio::io::AsyncWrite + Unpin + Send>(
        &mut self,
        info: &TraceInfo,
        event: &QlogEventView<'_>,
        output: &mut W,
    ) -> impl Future<Output = io::Result<()>> + Send;

    /// Write format-specific closing data. The owning output flushes the destination afterwards.
    fn finish<W: tokio::io::AsyncWrite + Unpin + Send>(
        &mut self,
        _output: &mut W,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async { Ok(()) }
    }
}

mod async_json;
pub use async_json::AsyncJsonSeqEncoder as JsonSeqEncoder;

/// Combine an asynchronous writer with a streaming encoder.
/// Buffering is optional: callers can supply an `AsyncWrite` buffer when small writes are costly.
pub struct EncodedWriter<W, E> {
    writer: W,
    encoder: E,
    info: Option<TraceInfo>,
}

impl<W, E> EncodedWriter<W, E> {
    /// Pair a destination and encoder; initialization occurs when recording starts.
    pub fn new(writer: W, encoder: E) -> Self {
        Self {
            writer,
            encoder,
            info: None,
        }
    }
}

impl<W, E> QlogOutput for EncodedWriter<W, E>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    E: QlogEncoder + 'static,
{
    async fn begin(&mut self, info: &TraceInfo) -> io::Result<()> {
        self.encoder.begin(info, &mut self.writer).await?;
        self.info = Some(info.clone());
        Ok(())
    }

    async fn event(&mut self, event: &QlogEventView<'_>) -> io::Result<()> {
        self.encoder
            .event(
                self.info
                    .as_ref()
                    .ok_or_else(|| io::Error::other("qlog output was not initialized"))?,
                event,
                &mut self.writer,
            )
            .await
    }

    async fn flush(&mut self) -> io::Result<()> {
        tokio::io::AsyncWriteExt::flush(&mut self.writer).await
    }

    async fn finish(&mut self) -> io::Result<()> {
        self.encoder.finish(&mut self.writer).await?;
        tokio::io::AsyncWriteExt::flush(&mut self.writer).await
    }
}

#[cfg(test)]
pub(crate) mod reference;
