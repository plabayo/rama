use base64::{Engine as _, engine::general_purpose::STANDARD};
use rama_core::error::BoxError;
use rama_utils::str::utf8::{self, DecodeError, Incomplete};
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
    // Reuse bounded scratch space for Serde escaping or base64 encoding.
    let mut encoded = if utf8 {
        Vec::with_capacity(CHUNK + 2)
    } else {
        vec![0; (CHUNK + 3).div_ceil(3) * 4]
    };
    let mut pending = 0;
    let mut incomplete = Incomplete::empty();
    loop {
        let read = reader.read(&mut buffer[pending..CHUNK]).await?;
        let end = pending + read;
        if utf8 {
            let mut bytes = &buffer[..read];
            if !incomplete.is_empty() {
                match incomplete.try_complete(bytes) {
                    Some((Ok(fragment), remaining)) => {
                        escaped(writer, fragment, &mut encoded).await?;
                        bytes = remaining;
                    }
                    Some((Err(_), _)) => return Err("invalid UTF-8 in a text HAR body".into()),
                    None if read != 0 => continue,
                    None => return Err("incomplete UTF-8 at the end of a text HAR body".into()),
                }
            }
            match utf8::decode(bytes) {
                Ok(fragment) => {
                    escaped(writer, fragment, &mut encoded).await?;
                }
                Err(DecodeError::Incomplete {
                    valid_prefix,
                    incomplete_suffix,
                }) => {
                    escaped(writer, valid_prefix, &mut encoded).await?;
                    incomplete = incomplete_suffix;
                }
                Err(DecodeError::Invalid { .. }) => {
                    return Err("invalid UTF-8 in a text HAR body".into());
                }
            }
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

/// Use Serde's JSON escaping on bounded fragments, retaining the outer string
/// delimiter across reads. Scratch space is shared across the entire body/form.
pub(super) async fn escaped<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut text: &str,
    buffer: &mut Vec<u8>,
) -> Result<(), BoxError> {
    while !text.is_empty() {
        // A control byte expands to at most six JSON bytes. Keep each encoded
        // write within CHUNK even when every input byte needs escaping.
        let end = text.floor_char_boundary(CHUNK / 6);
        let (fragment, rest) = text.split_at(end);
        buffer.clear();
        serde_json::to_writer(&mut *buffer, fragment)?;
        writer.write_all(&buffer[1..buffer.len() - 1]).await?;
        text = rest;
    }
    Ok(())
}
