//! Bounded typed metadata followed by an unencoded payload in one atomic record.

use std::{
    io::Write,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, ReadBuf};

use rama_core::futures::future::BoxFuture;
use rama_inspect::storage::Reader;
use serde::de::DeserializeOwned;

use super::*;

const MAX_METADATA: usize = rama_utils::octets::kib(64);

/// An adapter-owned record. Metadata must fit in 64 KiB; payloads stay raw and
/// stream separately. Implementations should return an existing `Bytes` handle
/// from `payload`, without allocating another payload buffer.
pub trait CapturedRecord: Send + Sync + Sized + 'static {
    type Metadata: Serialize + DeserializeOwned + Send + Sync;

    fn metadata(&self) -> Self::Metadata;

    fn payload(&self) -> Bytes;

    fn from_parts(metadata: Self::Metadata, payload: Bytes) -> Self;

    /// Search typed metadata and streamed payload without materializing the record.
    fn matches_stream(
        record: CapturedRecordStream<Self::Metadata>,
        needle: &str,
    ) -> impl Future<Output = Result<bool, BoxError>> + Send;
}

/// Typed metadata and a reader over the raw payload. Downloads, exporters and
/// protocol consumers can pipe this reader directly without a decode buffer.
pub struct CapturedRecordStream<M> {
    pub metadata: M,
    pub payload: Reader,
}

impl<M> CapturedRecordStream<M> {
    /// Explicitly materialize an owned record, for APIs such as message replay.
    /// Streaming consumers should read `payload` instead.
    pub async fn into_record<T: CapturedRecord<Metadata = M>>(mut self) -> Result<T, BoxError> {
        let mut payload = Vec::new();
        self.payload.read_to_end(&mut payload).await?;
        Ok(T::from_parts(self.metadata, Bytes::from(payload)))
    }
}

struct MetadataWriter(Vec<u8>);

impl Write for MetadataWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > (MAX_METADATA + 4).saturating_sub(self.0.len()) {
            return Err(std::io::Error::other(
                "capture attachment metadata exceeds limit",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) fn encode<T: CapturedRecord>(record: &T) -> Result<(AppendRecord, u64), BoxError> {
    encode_parts(&record.metadata(), record.payload())
}

pub(super) fn encode_parts(
    metadata: &impl Serialize,
    payload: Bytes,
) -> Result<(AppendRecord, u64), BoxError> {
    let mut header = MetadataWriter(vec![0; 4]);
    serde_json::to_writer(&mut header, metadata)?;
    let length = (header.0.len() - 4) as u32;
    header.0[..4].copy_from_slice(&length.to_be_bytes());
    let size = (header.0.len() as u64)
        .checked_add(payload.len() as u64)
        .context("capture attachment length overflow")?;
    Ok((
        AppendRecord::new(
            std::io::Cursor::new(Bytes::from(header.0)).chain(std::io::Cursor::new(payload)),
        ),
        size,
    ))
}

pub(super) async fn read<M: DeserializeOwned>(
    mut reader: Reader,
) -> Result<CapturedRecordStream<M>, BoxError> {
    let length = reader.read_u32().await? as usize;
    if length > MAX_METADATA {
        return Err(std::io::Error::other("capture attachment metadata exceeds limit").into());
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).await?;
    Ok(CapturedRecordStream {
        metadata: serde_json::from_slice(&bytes)?,
        payload: reader,
    })
}

pub(super) type SearchRecord = for<'a> fn(Reader, &'a str) -> BoxFuture<'a, Result<bool, BoxError>>;

pub(super) fn search<T: CapturedRecord>(
    reader: Reader,
    needle: &str,
) -> BoxFuture<'_, Result<bool, BoxError>> {
    Box::pin(async move { T::matches_stream(read(reader).await?, needle).await })
}

// Keep capture budgets charged while an adapter payload reader pins storage.
pub(super) struct PinnedRecordReader {
    pub reader: Reader,
    pub _entry: Arc<CapturedExchange>,
}

impl AsyncRead for PinnedRecordReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.reader.as_mut().poll_read(cx, buffer)
    }
}
