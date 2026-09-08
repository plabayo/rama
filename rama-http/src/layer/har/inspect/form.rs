//! Bounded form-to-JSON conversion, including percent escapes split across reads.
use super::streaming::escaped;
use rama_core::error::BoxError;
use rama_utils::octets::kib;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const CHUNK: usize = kib(8);

pub(super) async fn write_params<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut reader: impl AsyncBufRead + Unpin,
) -> Result<(), BoxError> {
    writer.write_all(b"[").await?;
    let mut first = true;
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
        let delimiter = write_part(writer, &mut reader, true).await?;
        writer.write_all(b",\"value\":").await?;
        if delimiter == Some(b'=') {
            write_part(writer, &mut reader, false).await?;
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
            if byte.is_ascii_hexdigit() {
                if self.pending == 1 {
                    self.percent[1] = byte;
                    self.pending = 2;
                } else {
                    self.push((hex(self.percent[1]) << 4) | hex(byte));
                    self.pending = 0;
                }
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
    ) -> Result<(), BoxError> {
        let mut start = 0;
        while start < self.len {
            match std::str::from_utf8(&self.bytes[start..self.len]) {
                Ok(text) => {
                    escaped(writer, text).await?;
                    start = self.len;
                }
                Err(error) => {
                    let valid = start + error.valid_up_to();
                    escaped(writer, std::str::from_utf8(&self.bytes[start..valid])?).await?;
                    if let Some(invalid) = error.error_len() {
                        escaped(writer, "\u{fffd}").await?;
                        start = valid + invalid;
                    } else if end {
                        escaped(writer, "\u{fffd}").await?;
                        start = self.len;
                    } else {
                        start = valid;
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
fn hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => byte - b'A' + 10,
    }
}
async fn write_part<W: AsyncWrite + Unpin>(
    writer: &mut W,
    reader: &mut (impl AsyncBufRead + Unpin),
    name: bool,
) -> Result<Option<u8>, BoxError> {
    writer.write_all(b"\"").await?;
    let mut decoder = Decoder {
        bytes: [0; CHUNK + 4],
        len: 0,
        percent: [0; 2],
        pending: 0,
    };
    let delimiter = loop {
        if reader.fill_buf().await?.is_empty() {
            break None;
        }
        let byte = reader.read_u8().await?;
        if byte == b'&' || (name && byte == b'=') {
            break Some(byte);
        }
        decoder.raw(byte);
        if decoder.len >= CHUNK {
            decoder.flush(writer, false).await?;
        }
    };
    decoder.finish_escape();
    decoder.flush(writer, true).await?;
    writer.write_all(b"\"").await?;
    Ok(delimiter)
}
