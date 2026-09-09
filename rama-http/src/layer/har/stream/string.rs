use base64::{Engine as _, engine::general_purpose::STANDARD};
use rama_core::error::BoxError;
use rama_utils::hex::encode_byte_upper;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::CHUNK;

/// Stream one JSON string, escaping UTF-8 or encoding binary without a body-sized buffer.
pub async fn write_json_string<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut reader: impl AsyncRead + Unpin,
    utf8: bool,
) -> Result<(), BoxError> {
    writer.write_all(b"\"").await?;
    let mut buffer = [0; CHUNK + 3];
    // Allocate the reusable encoding buffer only for binary content. Keeping
    // it off the future also avoids inflating every caller's async state.
    let mut encoded = if utf8 {
        Vec::new()
    } else {
        vec![0; (CHUNK + 3).div_ceil(3) * 4]
    };
    let mut pending = 0;
    loop {
        let read = reader.read(&mut buffer[pending..CHUNK]).await?;
        let end = pending + read;
        if utf8 {
            let valid = match std::str::from_utf8(&buffer[..end]) {
                Ok(fragment) => {
                    escaped(writer, fragment).await?;
                    end
                }
                Err(error) if error.error_len().is_none() && read != 0 => {
                    escaped(writer, std::str::from_utf8(&buffer[..error.valid_up_to()])?).await?;
                    error.valid_up_to()
                }
                Err(error) => return Err(error.into()),
            };
            pending = end - valid;
            buffer.copy_within(valid..end, 0);
        } else {
            let complete = if read == 0 { end } else { end / 3 * 3 };
            let count = STANDARD.encode_slice(&buffer[..complete], &mut encoded)?;
            writer.write_all(&encoded[..count]).await?;
            pending = end - complete;
            buffer.copy_within(complete..end, 0);
        }
        if read == 0 {
            break;
        }
    }
    writer.write_all(b"\"").await?;
    Ok(())
}

pub(super) async fn escaped<W: AsyncWrite + Unpin>(
    writer: &mut W,
    text: &str,
) -> Result<(), BoxError> {
    let mut start = 0;
    for (index, byte) in text.bytes().enumerate() {
        if byte < 0x20 || byte == b'"' || byte == b'\\' {
            writer.write_all(&text.as_bytes()[start..index]).await?;
            match byte {
                b'"' => writer.write_all(b"\\\"").await?,
                b'\\' => writer.write_all(b"\\\\").await?,
                _ => {
                    let hex = encode_byte_upper(byte);
                    writer
                        .write_all(&[b'\\', b'u', b'0', b'0', hex[0], hex[1]])
                        .await?;
                }
            }
            start = index + 1;
        }
    }
    writer.write_all(&text.as_bytes()[start..]).await?;
    Ok(())
}
