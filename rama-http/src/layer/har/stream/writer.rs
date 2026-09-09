use rama_core::error::BoxError;
use serde::Serialize;
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Writes typed fields of a HAR object, with a reusable serialization buffer.
/// Protocol extensions use this to append their own typed values or streams.
pub struct HarObjectWriter<'a, W> {
    writer: &'a mut W,
    first: bool,
    buffer: Vec<u8>,
}

impl<W: AsyncWrite + Unpin> HarObjectWriter<'_, W> {
    pub async fn begin(writer: &mut W) -> Result<HarObjectWriter<'_, W>, BoxError> {
        writer.write_all(b"{").await?;
        Ok(HarObjectWriter {
            writer,
            first: true,
            buffer: Vec::new(),
        })
    }

    async fn name(&mut self, name: &'static str) -> Result<(), BoxError> {
        self.buffer.clear();
        if !self.first {
            self.buffer.push(b',');
        }
        self.first = false;
        serde_json::to_writer(&mut self.buffer, name)?;
        self.buffer.push(b':');
        self.writer.write_all(&self.buffer).await?;
        Ok(())
    }

    pub async fn field<T: Serialize + ?Sized>(
        &mut self,
        name: &'static str,
        value: &T,
    ) -> Result<(), BoxError> {
        self.name(name).await?;
        self.value(value).await
    }

    async fn value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), BoxError> {
        self.buffer.clear();
        serde_json::to_writer(&mut self.buffer, value)?;
        self.writer.write_all(&self.buffer).await?;
        Ok(())
    }

    /// Serialize an array one typed element at a time, reusing scratch space.
    pub async fn array<T: Serialize>(
        &mut self,
        name: &'static str,
        values: &[T],
    ) -> Result<(), BoxError> {
        self.name(name).await?;
        self.writer.write_all(b"[").await?;
        for (index, value) in values.iter().enumerate() {
            if index != 0 {
                self.writer.write_all(b",").await?;
            }
            self.value(value).await?;
        }
        self.writer.write_all(b"]").await?;
        Ok(())
    }

    /// Start a streamed field. The caller must write exactly one JSON value;
    /// subsequent fields and the enclosing object remain managed by this writer.
    pub async fn streamed_field(&mut self, name: &'static str) -> Result<&mut W, BoxError> {
        self.name(name).await?;
        Ok(self.writer)
    }

    pub async fn finish(self) -> Result<(), BoxError> {
        self.writer.write_all(b"}").await?;
        Ok(())
    }
}
