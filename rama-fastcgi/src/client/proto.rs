//! FastCGI wire protocol: sending requests and reading responses.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use rama_core::bytes::{Bytes, BytesMut};

use crate::proto::{
    BeginRequestBody, EndRequestBody, FCGI_MAX_CONTENT_LEN, FCGI_NULL_REQUEST_ID, ProtocolStatus,
    RecordHeader, RecordType, Role, UnknownTypeBody,
    params::NvPairRef,
};

use super::{
    error::{ClientError, ClientErrorKind},
    types::{FastCgiClientRequest, FastCgiClientResponse},
};

/// Send a FastCGI request on an existing stream and return the response.
///
/// `request_id` must be non-zero. If `keep_conn` is true, the `FCGI_KEEP_CONN` flag
/// is set in `FCGI_BEGIN_REQUEST` and the connection is not closed by the application.
pub async fn send_on<IO>(
    stream: &mut IO,
    request_id: u16,
    request: FastCgiClientRequest,
    keep_conn: bool,
) -> Result<FastCgiClientResponse, ClientError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let begin_body = BeginRequestBody {
        role: Role::Responder,
        keep_conn,
    };
    let hdr = RecordHeader::new(RecordType::BeginRequest, request_id, 8);
    hdr.write_to(stream).await.map_err(ClientError::io)?;
    begin_body.write_to(stream).await.map_err(ClientError::io)?;

    send_params(stream, request_id, &request.params).await?;
    send_stream(stream, request_id, RecordType::Stdin, &request.stdin).await?;

    read_response(stream, request_id).await
}

async fn send_params<W>(
    w: &mut W,
    request_id: u16,
    params: &[(Bytes, Bytes)],
) -> Result<(), ClientError>
where
    W: AsyncWrite + Unpin,
{
    if params.is_empty() {
        let hdr = RecordHeader::new(RecordType::Params, request_id, 0);
        return hdr.write_to(w).await.map_err(ClientError::io);
    }

    let mut buf = BytesMut::new();
    for (name, value) in params {
        let pair_ref = NvPairRef::new(name.as_ref(), value.as_ref());
        let needed = pair_ref.encoded_len();
        if !buf.is_empty() && buf.len() + needed > FCGI_MAX_CONTENT_LEN {
            flush_params_chunk(w, request_id, &buf.split().freeze()).await?;
        }
        pair_ref.write_to_buf(&mut buf);
    }
    if !buf.is_empty() {
        flush_params_chunk(w, request_id, &buf.freeze()).await?;
    }

    let hdr = RecordHeader::new(RecordType::Params, request_id, 0);
    hdr.write_to(w).await.map_err(ClientError::io)
}

async fn flush_params_chunk<W>(w: &mut W, request_id: u16, data: &[u8]) -> Result<(), ClientError>
where
    W: AsyncWrite + Unpin,
{
    let hdr = RecordHeader::new(RecordType::Params, request_id, data.len() as u16);
    hdr.write_to(w).await.map_err(ClientError::io)?;
    w.write_all(data).await.map_err(ClientError::io)
}

async fn send_stream<W>(
    w: &mut W,
    request_id: u16,
    record_type: RecordType,
    data: &[u8],
) -> Result<(), ClientError>
where
    W: AsyncWrite + Unpin,
{
    if !data.is_empty() {
        let mut offset = 0;
        while offset < data.len() {
            let chunk = (data.len() - offset).min(FCGI_MAX_CONTENT_LEN);
            let hdr = RecordHeader::new(record_type, request_id, chunk as u16);
            hdr.write_to(w).await.map_err(ClientError::io)?;
            w.write_all(&data[offset..offset + chunk])
                .await
                .map_err(ClientError::io)?;
            offset += chunk;
        }
    }
    let hdr = RecordHeader::new(record_type, request_id, 0);
    hdr.write_to(w).await.map_err(ClientError::io)
}

async fn read_response<IO>(
    stream: &mut IO,
    request_id: u16,
) -> Result<FastCgiClientResponse, ClientError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut stdout = BytesMut::new();
    let mut app_status = 0u32;

    loop {
        let hdr = RecordHeader::read_from(stream)
            .await
            .map_err(ClientError::protocol)?;

        if hdr.request_id == FCGI_NULL_REQUEST_ID {
            handle_management_response(stream, &hdr).await?;
            continue;
        }

        if hdr.request_id != request_id {
            discard_content(stream, hdr.content_length, hdr.padding_length).await?;
            continue;
        }

        match hdr.record_type {
            RecordType::Stdout => {
                if hdr.content_length == 0 {
                    skip_padding(stream, hdr.padding_length).await?;
                } else {
                    let start = stdout.len();
                    stdout.resize(start + hdr.content_length as usize, 0);
                    stream
                        .read_exact(&mut stdout[start..])
                        .await
                        .map_err(ClientError::io)?;
                    skip_padding(stream, hdr.padding_length).await?;
                }
            }
            RecordType::Stderr => {
                discard_content(stream, hdr.content_length, hdr.padding_length).await?;
            }
            RecordType::EndRequest => {
                if hdr.content_length >= 8 {
                    let body = EndRequestBody::read_from(stream)
                        .await
                        .map_err(ClientError::protocol)?;
                    skip_padding(stream, hdr.padding_length).await?;
                    match body.protocol_status {
                        ProtocolStatus::RequestComplete => {}
                        ProtocolStatus::Overloaded => {
                            return Err(ClientError {
                                kind: ClientErrorKind::Overloaded,
                                source: None,
                            });
                        }
                        ProtocolStatus::CantMpxConn => {
                            return Err(ClientError {
                                kind: ClientErrorKind::CantMpxConn,
                                source: None,
                            });
                        }
                        ProtocolStatus::UnknownRole => {
                            return Err(ClientError {
                                kind: ClientErrorKind::UnknownRole,
                                source: None,
                            });
                        }
                        ProtocolStatus::Unknown(_) => {}
                    }
                    app_status = body.app_status;
                } else {
                    discard_content(stream, hdr.content_length, hdr.padding_length).await?;
                }
                return Ok(FastCgiClientResponse {
                    stdout: stdout.freeze(),
                    app_status,
                });
            }
            _ => {
                discard_content(stream, hdr.content_length, hdr.padding_length).await?;
            }
        }
    }
}

async fn handle_management_response<IO>(
    stream: &mut IO,
    hdr: &RecordHeader,
) -> Result<(), ClientError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    match hdr.record_type {
        RecordType::GetValues => {
            discard_content(stream, hdr.content_length, hdr.padding_length).await?;
            let resp = RecordHeader::management(RecordType::GetValuesResult, 0);
            resp.write_to(stream).await.map_err(ClientError::io)?;
        }
        RecordType::UnknownType => {
            if hdr.content_length >= 8 {
                let _body = UnknownTypeBody::read_from(stream)
                    .await
                    .map_err(ClientError::protocol)?;
            } else {
                discard_content(stream, hdr.content_length, hdr.padding_length).await?;
            }
        }
        _ => {
            discard_content(stream, hdr.content_length, hdr.padding_length).await?;
        }
    }
    Ok(())
}

async fn discard_content<R>(r: &mut R, len: u16, padding: u8) -> Result<(), ClientError>
where
    R: AsyncRead + Unpin,
{
    let total = len as usize + padding as usize;
    if total > 0 {
        let mut discard = vec![0u8; total];
        r.read_exact(&mut discard).await.map_err(ClientError::io)?;
    }
    Ok(())
}

async fn skip_padding<R>(r: &mut R, padding_length: u8) -> Result<(), ClientError>
where
    R: AsyncRead + Unpin,
{
    if padding_length > 0 {
        let mut pad = [0u8; 255];
        r.read_exact(&mut pad[..padding_length as usize])
            .await
            .map_err(ClientError::io)?;
    }
    Ok(())
}
