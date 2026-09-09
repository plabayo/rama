//! Bounded form-to-JSON conversion, including percent escapes split across reads.

use rama_core::error::BoxError;
use rama_utils::{
    hex::decode_pair,
    octets::kib,
    str::utf8::{self, DecodeError, REPLACEMENT_CHARACTER},
};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

use super::string::escaped;

const CHUNK: usize = kib(8);

pub(super) async fn write_params<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut reader: impl AsyncBufRead + Unpin,
) -> Result<(), BoxError> {
    writer.write_all(b"[").await?;
    let mut first = true;
    let mut encoded = Vec::new();
    loop {
        match reader.fill_buf().await?.first() {
            None => break,
            Some(b'&') => {
                reader.consume(1);
                continue;
            }
            _ => {}
        }
        if !first {
            writer.write_all(b",").await?;
        }
        first = false;
        writer.write_all(b"{\"name\":").await?;
        let delimiter = write_part(writer, &mut reader, true, &mut encoded).await?;
        writer.write_all(b",\"value\":").await?;
        if delimiter == Some(b'=') {
            write_part(writer, &mut reader, false, &mut encoded).await?;
        } else {
            writer.write_all(b"\"\"").await?;
        }
        writer
            .write_all(b",\"fileName\":null,\"contentType\":null,\"comment\":null}")
            .await?;
    }
    writer.write_all(b"]").await?;
    Ok(())
}

struct Decoder {
    bytes: [u8; CHUNK + 4],
    len: usize,
    percent: [u8; 2],
    pending: usize,
}

impl Decoder {
    fn push(&mut self, byte: u8) {
        self.bytes[self.len] = byte;
        self.len += 1;
    }

    fn raw(&mut self, byte: u8) {
        if self.pending != 0 {
            if self.pending == 1 && byte.is_ascii_hexdigit() {
                self.percent[1] = byte;
                self.pending = 2;
                return;
            }
            if self.pending == 2
                && let Some(decoded) = decode_pair(self.percent[1], byte)
            {
                self.push(decoded);
                self.pending = 0;
                return;
            }
            self.finish_escape();
        }
        match byte {
            b'%' => {
                self.percent[0] = b'%';
                self.pending = 1;
            }
            b'+' => self.push(b' '),
            byte => self.push(byte),
        }
    }

    fn finish_escape(&mut self) {
        for index in 0..self.pending {
            self.push(self.percent[index]);
        }
        self.pending = 0;
    }

    async fn flush<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        end: bool,
        encoded: &mut Vec<u8>,
    ) -> Result<(), BoxError> {
        let mut start = 0;
        while start < self.len {
            match utf8::decode(&self.bytes[start..self.len]) {
                Ok(text) => {
                    escaped(writer, text, encoded).await?;
                    start = self.len;
                }
                Err(DecodeError::Invalid {
                    valid_prefix,
                    remaining_input,
                    ..
                }) => {
                    escaped(writer, valid_prefix, encoded).await?;
                    escaped(writer, REPLACEMENT_CHARACTER, encoded).await?;
                    start = self.len - remaining_input.len();
                }
                Err(DecodeError::Incomplete { valid_prefix, .. }) => {
                    escaped(writer, valid_prefix, encoded).await?;
                    if end {
                        escaped(writer, REPLACEMENT_CHARACTER, encoded).await?;
                        start = self.len;
                    } else {
                        start += valid_prefix.len();
                        break;
                    }
                }
            }
        }
        self.bytes.copy_within(start..self.len, 0);
        self.len -= start;
        Ok(())
    }
}

async fn write_part<W: AsyncWrite + Unpin>(
    writer: &mut W,
    reader: &mut (impl AsyncBufRead + Unpin),
    name: bool,
    encoded: &mut Vec<u8>,
) -> Result<Option<u8>, BoxError> {
    writer.write_all(b"\"").await?;
    let mut decoder = Decoder {
        bytes: [0; CHUNK + 4],
        len: 0,
        percent: [0; 2],
        pending: 0,
    };
    let delimiter = loop {
        let bytes = reader.fill_buf().await?;
        if bytes.is_empty() {
            break None;
        }
        let mut consumed = 0;
        let mut delimiter = None;
        for &byte in bytes {
            consumed += 1;
            if byte == b'&' || (name && byte == b'=') {
                delimiter = Some(byte);
                break;
            }
            decoder.raw(byte);
            if decoder.len >= CHUNK {
                break;
            }
        }
        reader.consume(consumed);
        if delimiter.is_some() {
            break delimiter;
        }
        if decoder.len >= CHUNK {
            decoder.flush(writer, false, encoded).await?;
        }
    };
    decoder.finish_escape();
    decoder.flush(writer, true, encoded).await?;
    writer.write_all(b"\"").await?;
    Ok(delimiter)
}

#[cfg(test)]
mod tests;
