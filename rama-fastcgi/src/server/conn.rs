//! Connection-level FastCGI framing: reading requests and writing responses.

use rama_core::bytes::{Bytes, BytesMut};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf};
use tokio::sync::mpsc;

use crate::proto::{
    BeginRequestBody, EndRequestBody, FCGI_MAX_CONTENT_LEN, FCGI_NULL_REQUEST_ID, ProtocolError,
    ProtocolStatus, RecordHeader, RecordType, Role, UnknownTypeBody,
    params::{NvPairRef, decode_params, encode_params},
};

use super::{Error, types::FastCgiResponse};

// ---------------------------------------------------------------------------
// Phase 1: read FCGI_BEGIN_REQUEST + FCGI_PARAMS
// ---------------------------------------------------------------------------

/// Read the opening records of a FastCGI request: `FCGI_BEGIN_REQUEST`
/// followed by all `FCGI_PARAMS` records.
///
/// Returns `None` on a clean EOF before any records arrive.
/// Management records (`request_id == 0`) are handled in-place and the loop
/// continues; `FCGI_ABORT_REQUEST` arriving before params are complete is
/// responded to and `Ok(None)` is returned.
pub(super) async fn read_begin_and_params<R, W>(
    reader: &mut R,
    writer: &mut W,
) -> Result<Option<(u16, Role, bool, Vec<(Bytes, Bytes)>)>, Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // ── FCGI_BEGIN_REQUEST ────────────────────────────────────────────────
    let request_id;
    let begin;
    loop {
        let header = match RecordHeader::read_from(reader).await {
            Ok(h) => h,
            Err(_) => return Ok(None), // clean EOF
        };

        if header.request_id == FCGI_NULL_REQUEST_ID {
            handle_management_record(reader, writer, header).await?;
            continue;
        }

        if header.record_type != RecordType::BeginRequest {
            return Err(Error::protocol(ProtocolError::unexpected_byte(
                1,
                header.record_type.into(),
            )));
        }
        if header.content_length != 8 {
            return Err(Error::protocol(ProtocolError::unexpected_byte(4, 0)));
        }

        request_id = header.request_id;
        begin = BeginRequestBody::read_from(reader)
            .await
            .map_err(Error::protocol)?;
        skip_padding(reader, header.padding_length)
            .await
            .map_err(Error::io)?;
        break;
    }

    // ── FCGI_PARAMS ───────────────────────────────────────────────────────
    let mut params_buf = BytesMut::new();
    loop {
        let hdr = read_header(reader).await?;

        if hdr.request_id != request_id {
            return Err(Error::protocol(ProtocolError::unexpected_byte(2, 0)));
        }

        match hdr.record_type {
            RecordType::AbortRequest => {
                skip_padding(reader, hdr.padding_length)
                    .await
                    .map_err(Error::io)?;
                write_abort_end_request(writer, request_id)
                    .await
                    .map_err(Error::io)?;
                return Ok(None);
            }
            RecordType::Params => {
                if hdr.content_length == 0 {
                    skip_padding(reader, hdr.padding_length)
                        .await
                        .map_err(Error::io)?;
                    break;
                }
                read_content_into(
                    reader,
                    hdr.content_length,
                    hdr.padding_length,
                    &mut params_buf,
                )
                .await
                .map_err(Error::io)?;
            }
            other => {
                return Err(Error::protocol(ProtocolError::unexpected_byte(
                    1,
                    other.into(),
                )));
            }
        }
    }

    let params: Vec<(Bytes, Bytes)> = decode_params(&params_buf)
        .map(|(n, v)| (Bytes::copy_from_slice(n), Bytes::copy_from_slice(v)))
        .collect();

    Ok(Some((request_id, begin.role, begin.keep_conn, params)))
}

// ---------------------------------------------------------------------------
// Phase 2: background task — stream STDIN (+ DATA) records into channels
// ---------------------------------------------------------------------------

/// Background task: reads `FCGI_STDIN` (and `FCGI_DATA` for Filter) records
/// from the split `ReadHalf` and forwards chunks to the inner service via mpsc
/// channels.
///
/// Drops `stdin_tx` (and `data_tx`) on return so the body streams report EOF
/// to the service. Returns the `ReadHalf` plus a flag indicating whether
/// `FCGI_ABORT_REQUEST` was received.
pub(super) async fn read_body_records<IO>(
    mut reader: ReadHalf<IO>,
    request_id: u16,
    stdin_tx: mpsc::Sender<Result<Bytes, io::Error>>,
    data_tx: Option<mpsc::Sender<Result<Bytes, io::Error>>>,
) -> io::Result<(ReadHalf<IO>, bool)>
where
    IO: AsyncRead,
{
    let aborted =
        read_stream_records(&mut reader, request_id, RecordType::Stdin, &stdin_tx).await?;
    drop(stdin_tx);

    if aborted {
        return Ok((reader, true));
    }

    if let Some(ref dtx) = data_tx {
        let aborted =
            read_stream_records(&mut reader, request_id, RecordType::Data, dtx).await?;
        drop(data_tx);
        if aborted {
            return Ok((reader, true));
        }
    }

    Ok((reader, false))
}

/// Read records of type `expected` from `reader` until an empty terminator
/// record arrives, forwarding each non-empty chunk via `tx`.
///
/// Returns `true` if `FCGI_ABORT_REQUEST` was received. In that case an
/// `io::ErrorKind::ConnectionAborted` error is sent through `tx` before
/// returning so the service observes the abort.
async fn read_stream_records<R>(
    reader: &mut R,
    request_id: u16,
    expected: RecordType,
    tx: &mpsc::Sender<Result<Bytes, io::Error>>,
) -> io::Result<bool>
where
    R: AsyncRead + Unpin,
{
    loop {
        let hdr = RecordHeader::read_from(reader)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if hdr.request_id != request_id && hdr.request_id != FCGI_NULL_REQUEST_ID {
            let total = hdr.content_length as usize + hdr.padding_length as usize;
            if total > 0 {
                let mut discard = vec![0u8; total];
                reader.read_exact(&mut discard).await?;
            }
            continue;
        }

        match hdr.record_type {
            rt if rt == expected => {
                if hdr.content_length == 0 {
                    skip_padding(reader, hdr.padding_length).await?;
                    return Ok(false);
                }
                let mut chunk = BytesMut::zeroed(hdr.content_length as usize);
                reader.read_exact(&mut chunk).await?;
                skip_padding(reader, hdr.padding_length).await?;
                let _ = tx.send(Ok(chunk.freeze())).await;
            }
            RecordType::AbortRequest if hdr.request_id == request_id => {
                skip_padding(reader, hdr.padding_length).await?;
                let _ = tx
                    .send(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "FCGI_ABORT_REQUEST",
                    )))
                    .await;
                return Ok(true);
            }
            _ => {
                let total = hdr.content_length as usize + hdr.padding_length as usize;
                if total > 0 {
                    let mut discard = vec![0u8; total];
                    reader.read_exact(&mut discard).await?;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 4: write the response
// ---------------------------------------------------------------------------

/// Write a complete FastCGI response, streaming `response.stdout` in chunks.
pub(super) async fn write_response<W>(
    w: &mut W,
    request_id: u16,
    response: FastCgiResponse,
) -> Result<(), io::Error>
where
    W: AsyncWrite + Unpin,
{
    let mut stdout = response.stdout;
    let mut chunk_buf = [0u8; 8192];

    loop {
        let n = stdout.read(&mut chunk_buf).await?;
        if n == 0 {
            break;
        }
        let chunk_len = n.min(FCGI_MAX_CONTENT_LEN) as u16;
        let hdr = RecordHeader::new(RecordType::Stdout, request_id, chunk_len);
        hdr.write_to(w).await?;
        w.write_all(&chunk_buf[..chunk_len as usize]).await?;
    }

    let hdr = RecordHeader::new(RecordType::Stdout, request_id, 0);
    hdr.write_to(w).await?;

    write_end_request(
        w,
        request_id,
        EndRequestBody {
            app_status: response.app_status,
            protocol_status: ProtocolStatus::RequestComplete,
        },
    )
    .await
}

pub(super) async fn write_abort_end_request<W>(
    w: &mut W,
    request_id: u16,
) -> Result<(), io::Error>
where
    W: AsyncWrite + Unpin,
{
    write_end_request(
        w,
        request_id,
        EndRequestBody {
            app_status: 0,
            protocol_status: ProtocolStatus::RequestComplete,
        },
    )
    .await
}

async fn write_end_request<W>(
    w: &mut W,
    request_id: u16,
    body: EndRequestBody,
) -> Result<(), io::Error>
where
    W: AsyncWrite + Unpin,
{
    let hdr = RecordHeader::new(RecordType::EndRequest, request_id, 8);
    hdr.write_to(w).await?;
    body.write_to(w).await
}

// ---------------------------------------------------------------------------
// Management records
// ---------------------------------------------------------------------------

async fn handle_management_record<R, W>(
    reader: &mut R,
    writer: &mut W,
    header: RecordHeader,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match header.record_type {
        RecordType::GetValues => {
            let mut query_buf = vec![0u8; header.content_length as usize];
            reader.read_exact(&mut query_buf).await.map_err(Error::io)?;
            skip_padding(reader, header.padding_length)
                .await
                .map_err(Error::io)?;

            let mut pairs: Vec<NvPairRef<'static>> = Vec::new();
            for (name, _) in decode_params(&query_buf) {
                match name {
                    b"FCGI_MAX_CONNS" => pairs.push(NvPairRef::new(b"FCGI_MAX_CONNS", b"1")),
                    b"FCGI_MAX_REQS" => pairs.push(NvPairRef::new(b"FCGI_MAX_REQS", b"1")),
                    b"FCGI_MPXS_CONNS" => {
                        pairs.push(NvPairRef::new(b"FCGI_MPXS_CONNS", b"0"))
                    }
                    _ => {}
                }
            }

            let body = encode_params(pairs.into_iter());
            let hdr =
                RecordHeader::management(RecordType::GetValuesResult, body.len() as u16);
            hdr.write_to(writer).await.map_err(Error::io)?;
            if !body.is_empty() {
                writer.write_all(&body).await.map_err(Error::io)?;
            }
        }
        _ => {
            let mut discard = vec![0u8; header.content_length as usize];
            reader.read_exact(&mut discard).await.map_err(Error::io)?;
            skip_padding(reader, header.padding_length)
                .await
                .map_err(Error::io)?;

            let body = UnknownTypeBody {
                unknown_type: header.record_type.into(),
            };
            let hdr = RecordHeader::management(RecordType::UnknownType, 8);
            hdr.write_to(writer).await.map_err(Error::io)?;
            body.write_to(writer).await.map_err(Error::io)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Low-level I/O helpers
// ---------------------------------------------------------------------------

async fn read_header<R>(r: &mut R) -> Result<RecordHeader, Error>
where
    R: AsyncRead + Unpin,
{
    RecordHeader::read_from(r).await.map_err(Error::protocol)
}

async fn skip_padding<R>(r: &mut R, padding_length: u8) -> Result<(), io::Error>
where
    R: AsyncRead + Unpin,
{
    if padding_length > 0 {
        let mut pad = [0u8; 255];
        r.read_exact(&mut pad[..padding_length as usize]).await?;
    }
    Ok(())
}

async fn read_content_into<R>(
    r: &mut R,
    content_length: u16,
    padding_length: u8,
    buf: &mut BytesMut,
) -> Result<(), io::Error>
where
    R: AsyncRead + Unpin,
{
    let start = buf.len();
    buf.resize(start + content_length as usize, 0);
    r.read_exact(&mut buf[start..]).await?;
    skip_padding(r, padding_length).await
}
