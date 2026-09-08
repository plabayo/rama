//! Authenticated encryption layered over any record storage service.
//!
//! Records are encoded as independently authenticated 64 KiB chunks followed by
//! an authenticated terminator. Readers authenticate each chunk before exposing
//! plaintext. Neither direction buffers the whole record. Range reads address
//! plaintext and currently scan/authenticate the preceding chunks.

use crate::dep::boring::{rand::rand_bytes, symm};
use parking_lot::RwLock;
use rama_core::{Layer, futures::async_stream::stream_fn, stream::io::StreamReader};
use rama_core::{Service, bytes::Bytes, error::BoxError};
use rama_inspect::storage::{
    AppendRecord, Collection, CreateCollection, ListRecords, ReadRecord, Reader, RecordId,
};
use std::collections::BTreeMap;
use std::{fmt, sync::Arc};
use tokio::io::AsyncReadExt;

const CHUNK: usize = rama_utils::octets::kib(64);
const MAGIC: &[u8; 8] = b"RMINSP\x01\0";

/// Per-instance AES-256-GCM key. Debug output never reveals the key.
#[derive(Clone)]
pub struct EncryptLayer {
    key: Arc<[u8; 32]>,
}
impl fmt::Debug for EncryptLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptLayer").finish_non_exhaustive()
    }
}
impl EncryptLayer {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key: Arc::new(key) }
    }
    pub fn random() -> Result<Self, BoxError> {
        let mut key = [0; 32];
        rand_bytes(&mut key)?;
        Ok(Self::new(key))
    }
}
impl<S> Layer<S> for EncryptLayer {
    type Service = EncryptStore<S>;
    fn layer(&self, inner: S) -> Self::Service {
        EncryptStore {
            inner,
            key: self.key.clone(),
        }
    }
}
/// Storage service produced by [`EncryptLayer`].
#[derive(Clone)]
pub struct EncryptStore<S> {
    inner: S,
    key: Arc<[u8; 32]>,
}
impl<S: fmt::Debug> fmt::Debug for EncryptStore<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptStore")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}
impl<S> Service<CreateCollection> for EncryptStore<S>
where
    S: Service<CreateCollection, Output = Collection, Error = BoxError>,
{
    type Output = Collection;
    type Error = BoxError;
    async fn serve(&self, input: CreateCollection) -> Result<Collection, BoxError> {
        let inner = self.inner.serve(input).await?;
        Ok(Collection::new(EncryptedCollection {
            inner,
            key: self.key.clone(),
            id: input.id,
            records: Arc::new(RwLock::new(BTreeMap::new())),
        }))
    }
}
#[derive(Clone)]
struct EncryptedCollection {
    inner: Collection,
    key: Arc<[u8; 32]>,
    id: u64,
    // Keep the expected stream identity outside the ciphertext. Substituting a
    // different valid record in the same collection must fail authentication.
    records: Arc<RwLock<BTreeMap<RecordId, [u8; 16]>>>,
}
fn aad(collection: u64, stream: &[u8; 16], sequence: u64, end: bool) -> Vec<u8> {
    let mut value = Vec::with_capacity(41);
    value.extend_from_slice(MAGIC);
    value.extend_from_slice(&collection.to_be_bytes());
    value.extend_from_slice(stream);
    value.extend_from_slice(&sequence.to_be_bytes());
    value.push(u8::from(end));
    value
}
fn invalid(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}
impl Service<AppendRecord> for EncryptedCollection {
    type Output = RecordId;
    type Error = BoxError;
    async fn serve(&self, mut input: AppendRecord) -> Result<RecordId, BoxError> {
        let mut identity = [0; 16];
        rand_bytes(&mut identity)?;
        let key = self.key.clone();
        let collection = self.id;
        let stream = stream_fn(move |mut output| async move {
            let mut header = MAGIC.to_vec();
            header.extend_from_slice(&identity);
            output
                .yield_item(Ok::<_, std::io::Error>(Bytes::from(header)))
                .await;
            let mut buffer = vec![0; CHUNK];
            let mut sequence = 0u64;
            loop {
                let count = match input.source.read(&mut buffer).await {
                    Ok(count) => count,
                    Err(error) => {
                        output.yield_item(Err(error)).await;
                        return;
                    }
                };
                let result = (|| -> Result<Bytes, std::io::Error> {
                    let mut nonce = [0; 12];
                    rand_bytes(&mut nonce).map_err(std::io::Error::other)?;
                    let mut tag = [0; 16];
                    let ciphertext = symm::encrypt_aead(
                        symm::Cipher::aes_256_gcm(),
                        key.as_ref(),
                        Some(&nonce),
                        &aad(collection, &identity, sequence, count == 0),
                        &buffer[..count],
                        &mut tag,
                    )
                    .map_err(std::io::Error::other)?;
                    let mut frame = Vec::with_capacity(32 + ciphertext.len());
                    frame.extend_from_slice(&(count as u32).to_be_bytes());
                    frame.extend_from_slice(&nonce);
                    frame.extend_from_slice(&tag);
                    frame.extend_from_slice(&ciphertext);
                    Ok(Bytes::from(frame))
                })();
                let failed = result.is_err();
                output.yield_item(result).await;
                if failed || count == 0 {
                    return;
                }
                if let Some(next) = sequence.checked_add(1) {
                    sequence = next;
                } else {
                    output
                        .yield_item(Err(invalid("encrypted sequence overflow")))
                        .await;
                    return;
                }
            }
        });
        let id = self
            .inner
            .serve(AppendRecord::new(StreamReader::new(Box::pin(stream))))
            .await?;
        // No await after the inner append publishes its record.
        self.records.write().insert(id, identity);
        Ok(id)
    }
}
impl Service<ReadRecord> for EncryptedCollection {
    type Output = Reader;
    type Error = BoxError;
    async fn serve(&self, input: ReadRecord) -> Result<Reader, BoxError> {
        let expected = self
            .records
            .read()
            .get(&input.id)
            .copied()
            .ok_or_else(|| invalid("encrypted record not found"))?;
        let mut reader = self.inner.read(input.id).await?;
        let key = self.key.clone();
        let collection = self.id;
        let stream = stream_fn(move |mut output| async move {
            let result = async {
                let mut header = [0; 24];
                reader.read_exact(&mut header).await?;
                if &header[..8] != MAGIC || header[8..] != expected {
                    return Err(invalid("encrypted record identity mismatch"));
                }
                let mut sequence = 0u64;
                loop {
                    let length = reader.read_u32().await? as usize;
                    if length > CHUNK {
                        return Err(invalid("encrypted chunk exceeds limit"));
                    }
                    let mut nonce = [0; 12];
                    let mut tag = [0; 16];
                    let mut ciphertext = vec![0; length];
                    reader.read_exact(&mut nonce).await?;
                    reader.read_exact(&mut tag).await?;
                    reader.read_exact(&mut ciphertext).await?;
                    let plaintext = symm::decrypt_aead(
                        symm::Cipher::aes_256_gcm(),
                        key.as_ref(),
                        Some(&nonce),
                        &aad(collection, &expected, sequence, length == 0),
                        &ciphertext,
                        &tag,
                    )
                    .map_err(std::io::Error::other)?;
                    if length == 0 {
                        let mut trailing = [0];
                        if reader.read(&mut trailing).await? != 0 {
                            return Err(invalid("trailing encrypted record content"));
                        }
                        return Ok::<(), std::io::Error>(());
                    }
                    output.yield_item(Ok(Bytes::from(plaintext))).await;
                    sequence = sequence
                        .checked_add(1)
                        .ok_or_else(|| invalid("encrypted sequence overflow"))?;
                }
            }
            .await;
            if let Err(error) = result {
                output.yield_item(Err(error)).await;
            }
        });
        rama_inspect::storage::range_reader(
            Box::pin(StreamReader::new(Box::pin(stream))),
            input.range,
        )
        .await
    }
}
impl Service<ListRecords> for EncryptedCollection {
    type Output = Vec<RecordId>;
    type Error = BoxError;
    async fn serve(&self, _: ListRecords) -> Result<Vec<RecordId>, BoxError> {
        Ok(self.records.read().keys().copied().collect())
    }
}

#[cfg(test)]
mod tests;
