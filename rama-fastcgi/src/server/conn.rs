//! Connection-level FastCGI framing: reading requests and writing responses.

use rama_core::bytes::{Bytes, BytesMut};
use rama_core::io::discard;
use rama_core::telemetry::tracing;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf};
use tokio::sync::mpsc;

use crate::proto::{
    BeginRequestBody, EndRequestBody, FCGI_MAX_CONTENT_LEN, FCGI_NULL_REQUEST_ID, ProtocolError,
    ProtocolStatus, RecordHeader, RecordType, Role, UnknownTypeBody,
    params::{NvPairRef, decode_params, encode_params},
};

use super::{Error, options::ServerOptions, types::FastCgiResponse};

/// Output of the begin/params reading phase.
pub(super) struct BeginParams {
    pub request_id: u16,
    pub role: Role,
    pub keep_conn: bool,
    pub params: Vec<(Bytes, Bytes)>,
}

// ---------------------------------------------------------------------------
// Phase 1: read FCGI_BEGIN_REQUEST + FCGI_PARAMS
// ---------------------------------------------------------------------------

/// Read the opening records of a FastCGI request: `FCGI_BEGIN_REQUEST`
/// followed by all `FCGI_PARAMS` records.
///
/// Returns `None` on a clean EOF, an idle read timeout before any records
/// arrive, or `FCGI_ABORT_REQUEST` received before params are complete.
/// In the latter two cases the appropriate response has been written to
/// `writer` already.
pub(super) async fn read_begin_and_params<R, W>(
    reader: &mut R,
    writer: &mut W,
    options: &ServerOptions,
) -> Result<Option<BeginParams>, Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let Some((request_id, begin)) = read_begin_record(reader, writer, options).await? else {
        return Ok(None);
    };
    let Some(params) = read_params_stream(reader, writer, request_id, options).await? else {
        return Ok(None);
    };
    Ok(Some(BeginParams {
        request_id,
        role: begin.role,
        keep_conn: begin.keep_conn,
        params,
    }))
}

/// Read records until a `FCGI_BEGIN_REQUEST` arrives, handling management
/// records (request_id == 0) in-place. Returns `Ok(None)` on clean EOF.
async fn read_begin_record<R, W>(
    reader: &mut R,
    writer: &mut W,
    options: &ServerOptions,
) -> Result<Option<(u16, BeginRequestBody)>, Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let header = match RecordHeader::read_from(reader).await {
            Ok(h) => h,
            Err(_eof_or_io) => return Ok(None),
        };

        if header.request_id == FCGI_NULL_REQUEST_ID {
            handle_management_record(reader, writer, header).await?;
            continue;
        }

        if header.record_type != RecordType::BeginRequest {
            tracing::debug!(
                rid = header.request_id,
                record_type = ?header.record_type,
                "fastcgi server: unexpected record type while awaiting BEGIN_REQUEST"
            );
            return Err(Error::protocol(ProtocolError::unexpected_byte(
                1,
                header.record_type.into(),
            )));
        }
        if options.strict_begin_body_size {
            if header.content_length != 8 {
                return Err(Error::protocol(ProtocolError::unexpected_byte(4, 0)));
            }
        } else if header.content_length < 8 {
            return Err(Error::protocol(ProtocolError::unexpected_byte(4, 0)));
        }

        let begin = BeginRequestBody::read_from(reader)
            .await
            .map_err(Error::protocol)?;
        // Tolerate forward-compat: BeginRequestBody is 8 bytes today, but a
        // future revision might extend it. Drop any surplus content silently.
        if header.content_length > 8 {
            discard(reader, (header.content_length - 8) as u64)
                .await
                .map_err(Error::io)?;
        }
        skip_padding(reader, header.padding_length)
            .await
            .map_err(Error::io)?;

        tracing::trace!(
            rid = header.request_id,
            role = ?begin.role,
            keep_conn = begin.keep_conn,
            "fastcgi server: BEGIN_REQUEST received"
        );
        return Ok(Some((header.request_id, begin)));
    }
}

/// Read `FCGI_PARAMS` records for `request_id` until an empty terminator,
/// returning the decoded name/value pairs. Returns `Ok(None)` if an
/// `FCGI_ABORT_REQUEST` was observed (and an END_REQUEST was written).
async fn read_params_stream<R, W>(
    reader: &mut R,
    writer: &mut W,
    request_id: u16,
    options: &ServerOptions,
) -> Result<Option<Vec<(Bytes, Bytes)>>, Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut params_buf = BytesMut::new();
    loop {
        let hdr = RecordHeader::read_from(reader)
            .await
            .map_err(Error::protocol)?;

        if hdr.request_id == FCGI_NULL_REQUEST_ID {
            handle_management_record(reader, writer, hdr).await?;
            continue;
        }

        if hdr.request_id != request_id {
            handle_foreign_request_id(reader, writer, &hdr, options).await?;
            continue;
        }

        match hdr.record_type {
            RecordType::AbortRequest => {
                skip_padding(reader, hdr.padding_length)
                    .await
                    .map_err(Error::io)?;
                tracing::debug!(
                    rid = request_id,
                    "fastcgi server: FCGI_ABORT_REQUEST received during PARAMS phase"
                );
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
                if params_buf.len().saturating_add(hdr.content_length as usize)
                    > options.max_params_bytes
                {
                    let total = params_buf.len() + hdr.content_length as usize;
                    tracing::debug!(
                        rid = request_id,
                        cap = options.max_params_bytes,
                        total,
                        "fastcgi server: PARAMS exceeded max_params_bytes"
                    );
                    return Err(Error::protocol(ProtocolError::content_too_large(total)));
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
                tracing::debug!(
                    rid = request_id,
                    record_type = ?other,
                    "fastcgi server: unexpected record type during PARAMS phase"
                );
                return Err(Error::protocol(ProtocolError::unexpected_byte(
                    1,
                    other.into(),
                )));
            }
        }
    }

    let params_bytes: Bytes = params_buf.freeze();
    let params: Vec<(Bytes, Bytes)> = decode_params(&params_bytes)
        .map(|(n, v)| (params_bytes.slice_ref(n), params_bytes.slice_ref(v)))
        .collect();
    Ok(Some(params))
}

/// Handle a record whose request_id does not match the current request:
/// reply with `FCGI_END_REQUEST{CantMpxConn}` for a concurrent BEGIN
/// (when enabled), and drop everything else on the floor.
async fn handle_foreign_request_id<R, W>(
    reader: &mut R,
    writer: &mut W,
    hdr: &RecordHeader,
    options: &ServerOptions,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if hdr.record_type == RecordType::BeginRequest {
        drain_record_body(reader, hdr).await.map_err(Error::io)?;
        if options.respond_cant_mpx_conn {
            tracing::debug!(
                rid = hdr.request_id,
                "fastcgi server: rejecting concurrent BEGIN_REQUEST with FCGI_CANT_MPX_CONN"
            );
            write_end_request(writer, hdr.request_id, EndRequestBody::cant_mpx_conn())
                .await
                .map_err(Error::io)?;
        }
    } else {
        tracing::trace!(
            rid = hdr.request_id,
            record_type = ?hdr.record_type,
            "fastcgi server: dropping stray record for unknown request id"
        );
        drain_record_body(reader, hdr).await.map_err(Error::io)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 2: background task — stream STDIN (+ DATA) records into channels
// ---------------------------------------------------------------------------

/// Background task: reads `FCGI_STDIN` (and `FCGI_DATA` for Filter) records
/// from the split `ReadHalf` and forwards chunks to the inner service via mpsc
/// channels.
pub(super) async fn read_body_records<IO>(
    mut reader: ReadHalf<IO>,
    request_id: u16,
    stdin_tx: mpsc::Sender<Result<Bytes, io::Error>>,
    data_tx: Option<mpsc::Sender<Result<Bytes, io::Error>>>,
    options: ServerOptions,
) -> io::Result<(ReadHalf<IO>, bool)>
where
    IO: AsyncRead,
{
    let aborted = read_stream_records(
        &mut reader,
        request_id,
        RecordType::Stdin,
        &stdin_tx,
        options.max_stdin_bytes,
    )
    .await?;
    drop(stdin_tx);

    if aborted {
        return Ok((reader, true));
    }

    if let Some(ref dtx) = data_tx {
        let aborted = read_stream_records(
            &mut reader,
            request_id,
            RecordType::Data,
            dtx,
            options.max_data_bytes,
        )
        .await?;
        drop(data_tx);
        if aborted {
            return Ok((reader, true));
        }
    }

    Ok((reader, false))
}

async fn read_stream_records<R>(
    reader: &mut R,
    request_id: u16,
    expected: RecordType,
    tx: &mpsc::Sender<Result<Bytes, io::Error>>,
    max_bytes: Option<u64>,
) -> io::Result<bool>
where
    R: AsyncRead + Unpin,
{
    let mut received: u64 = 0;
    loop {
        let hdr = RecordHeader::read_from(reader)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if hdr.request_id != request_id && hdr.request_id != FCGI_NULL_REQUEST_ID {
            drain_record_body(reader, &hdr).await?;
            continue;
        }

        match hdr.record_type {
            rt if rt == expected => {
                if hdr.content_length == 0 {
                    skip_padding(reader, hdr.padding_length).await?;
                    return Ok(false);
                }
                if let Some(cap) = max_bytes
                    && received.saturating_add(hdr.content_length as u64) > cap
                {
                    if tx
                        .send(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "fastcgi: stdin/data exceeds configured cap",
                        )))
                        .await
                        .is_err()
                    {
                        tracing::debug!(
                            "fastcgi server: body channel closed before cap error could be reported"
                        );
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "fastcgi: stdin/data exceeds configured cap",
                    ));
                }
                let mut chunk = BytesMut::zeroed(hdr.content_length as usize);
                reader.read_exact(&mut chunk).await?;
                skip_padding(reader, hdr.padding_length).await?;
                received = received.saturating_add(hdr.content_length as u64);
                if tx.send(Ok(chunk.freeze())).await.is_err() {
                    tracing::debug!(
                        "fastcgi server: body channel closed by service; dropping {} buffered bytes \
                         and continuing to drain peer",
                        hdr.content_length
                    );
                    // Keep draining the stream to EOS so the connection
                    // can be reused (keep_conn) or closed cleanly.
                }
            }
            RecordType::AbortRequest if hdr.request_id == request_id => {
                skip_padding(reader, hdr.padding_length).await?;
                if tx
                    .send(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "FCGI_ABORT_REQUEST",
                    )))
                    .await
                    .is_err()
                {
                    tracing::debug!(
                        "fastcgi server: body channel closed before abort could be reported"
                    );
                }
                return Ok(true);
            }
            _ => {
                drain_record_body(reader, &hdr).await?;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 4: write the response
// ---------------------------------------------------------------------------

/// Write a complete FastCGI response, streaming `response.stderr` then
/// `response.stdout`.
///
/// The spec allows STDERR and STDOUT to be interleaved; writing all STDERR
/// up front keeps the writer single-pass and matches typical CGI usage.
pub(super) async fn write_response<W>(
    w: &mut W,
    request_id: u16,
    response: FastCgiResponse,
    _options: &ServerOptions,
) -> Result<(), io::Error>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];

    // STDERR stream (may be empty).
    let mut stderr = response.stderr;
    let mut emitted_stderr = false;
    loop {
        let n = stderr.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        emitted_stderr = true;
        let chunk_len = n.min(FCGI_MAX_CONTENT_LEN) as u16;
        let hdr = RecordHeader::new(RecordType::Stderr, request_id, chunk_len);
        hdr.write_to(w).await?;
        w.write_all(&buf[..chunk_len as usize]).await?;
    }
    if emitted_stderr {
        let hdr = RecordHeader::new(RecordType::Stderr, request_id, 0);
        hdr.write_to(w).await?;
    }

    // STDOUT stream
    let mut stdout = response.stdout;
    loop {
        let n = stdout.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let chunk_len = n.min(FCGI_MAX_CONTENT_LEN) as u16;
        let hdr = RecordHeader::new(RecordType::Stdout, request_id, chunk_len);
        hdr.write_to(w).await?;
        w.write_all(&buf[..chunk_len as usize]).await?;
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

pub(super) async fn write_abort_end_request<W>(w: &mut W, request_id: u16) -> Result<(), io::Error>
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
    if header.record_type == RecordType::GetValues {
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
                b"FCGI_MPXS_CONNS" => pairs.push(NvPairRef::new(b"FCGI_MPXS_CONNS", b"0")),
                _ => {}
            }
        }

        let body = encode_params(pairs).map_err(Error::protocol)?;
        let hdr = RecordHeader::management(RecordType::GetValuesResult, body.len() as u16);
        hdr.write_to(writer).await.map_err(Error::io)?;
        if !body.is_empty() {
            writer.write_all(&body).await.map_err(Error::io)?;
        }
    } else {
        drain_record_body(reader, &header)
            .await
            .map_err(Error::io)?;

        let body = UnknownTypeBody {
            unknown_type: header.record_type.into(),
        };
        let hdr = RecordHeader::management(RecordType::UnknownType, 8);
        hdr.write_to(writer).await.map_err(Error::io)?;
        body.write_to(writer).await.map_err(Error::io)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Low-level I/O helpers
// ---------------------------------------------------------------------------

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

async fn drain_record_body<R>(r: &mut R, hdr: &RecordHeader) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    discard(r, hdr.content_length as u64 + hdr.padding_length as u64).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::params::NvPair;

    /// Encode a complete client-side BEGIN+PARAMS+STDIN(EOF) request into a buffer.
    async fn write_request(role: Role, params: &[(&[u8], &[u8])], stdin: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        // BEGIN_REQUEST
        let hdr = RecordHeader::new(RecordType::BeginRequest, 1, 8);
        hdr.write_to(&mut out).await.unwrap();
        BeginRequestBody {
            role,
            keep_conn: false,
        }
        .write_to(&mut out)
        .await
        .unwrap();
        // PARAMS
        let mut pbuf = Vec::new();
        for (n, v) in params {
            NvPair::new(n.to_vec(), v.to_vec())
                .write_to(&mut pbuf)
                .await
                .unwrap();
        }
        let hdr = RecordHeader::new(RecordType::Params, 1, pbuf.len() as u16);
        hdr.write_to(&mut out).await.unwrap();
        out.extend_from_slice(&pbuf);
        // PARAMS terminator
        let hdr = RecordHeader::new(RecordType::Params, 1, 0);
        hdr.write_to(&mut out).await.unwrap();
        // STDIN
        if !stdin.is_empty() {
            let hdr = RecordHeader::new(RecordType::Stdin, 1, stdin.len() as u16);
            hdr.write_to(&mut out).await.unwrap();
            out.extend_from_slice(stdin);
        }
        let hdr = RecordHeader::new(RecordType::Stdin, 1, 0);
        hdr.write_to(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn test_read_begin_and_params_round_trip() {
        let bytes = write_request(
            Role::Responder,
            &[(b"REQUEST_METHOD", b"GET"), (b"SCRIPT_NAME", b"/index")],
            b"",
        )
        .await;
        let mut reader = std::io::Cursor::new(bytes);
        let mut writer = Vec::new();
        let opts = ServerOptions::default();
        let begin = read_begin_and_params(&mut reader, &mut writer, &opts)
            .await
            .unwrap()
            .expect("got begin");
        assert_eq!(begin.request_id, 1);
        assert_eq!(begin.role, Role::Responder);
        assert!(!begin.keep_conn);
        assert_eq!(begin.params.len(), 2);
        assert_eq!(&begin.params[0].0[..], b"REQUEST_METHOD");
        assert_eq!(&begin.params[0].1[..], b"GET");
        // Server should not have written anything yet (no response).
        assert!(writer.is_empty());
    }

    #[tokio::test]
    async fn test_max_params_bytes_enforced() {
        // 16 KiB of params at default cap (1 MiB) → OK.
        let huge_value: Vec<u8> = vec![b'x'; 16 * 1024];
        let bytes = write_request(Role::Responder, &[(b"BIG", &huge_value)], b"").await;
        let mut reader = std::io::Cursor::new(bytes);
        let mut writer = Vec::new();
        let opts = ServerOptions {
            max_params_bytes: 1024, // cap below the request size
            ..ServerOptions::default()
        };
        let res = read_begin_and_params(&mut reader, &mut writer, &opts).await;
        assert!(res.is_err(), "expected cap to reject oversize params");
    }

    #[tokio::test]
    async fn test_management_get_values_response() {
        // Construct a GET_VALUES record asking for FCGI_MPXS_CONNS, then a BEGIN.
        let mut out = Vec::new();
        let mut qbuf = Vec::new();
        NvPair::new(b"FCGI_MPXS_CONNS".as_slice(), b"".as_slice())
            .write_to(&mut qbuf)
            .await
            .unwrap();
        let hdr = RecordHeader::management(RecordType::GetValues, qbuf.len() as u16);
        hdr.write_to(&mut out).await.unwrap();
        out.extend_from_slice(&qbuf);
        // Then a BEGIN to terminate the loop with a real request.
        let rest = write_request(Role::Responder, &[(b"REQUEST_METHOD", b"GET")], b"").await;
        out.extend_from_slice(&rest);

        let mut reader = std::io::Cursor::new(out);
        let mut writer: Vec<u8> = Vec::new();
        let opts = ServerOptions::default();
        let begin = read_begin_and_params(&mut reader, &mut writer, &opts)
            .await
            .unwrap()
            .expect("got begin");
        assert_eq!(begin.request_id, 1);
        // The writer should have a GET_VALUES_RESULT record reporting MPXS=0.
        assert!(
            !writer.is_empty(),
            "expected GET_VALUES_RESULT to be written"
        );
        // First 8 bytes are the response header; ensure record type is correct.
        assert_eq!(writer[1], u8::from(RecordType::GetValuesResult));
    }

    #[tokio::test]
    async fn test_abort_during_params_phase_replies_end_request() {
        // BEGIN_REQUEST then immediately ABORT_REQUEST.
        let mut out = Vec::new();
        let hdr = RecordHeader::new(RecordType::BeginRequest, 1, 8);
        hdr.write_to(&mut out).await.unwrap();
        BeginRequestBody {
            role: Role::Responder,
            keep_conn: false,
        }
        .write_to(&mut out)
        .await
        .unwrap();
        let hdr = RecordHeader::new(RecordType::AbortRequest, 1, 0);
        hdr.write_to(&mut out).await.unwrap();

        let mut reader = std::io::Cursor::new(out);
        let mut writer: Vec<u8> = Vec::new();
        let opts = ServerOptions::default();
        let res = read_begin_and_params(&mut reader, &mut writer, &opts)
            .await
            .unwrap();
        assert!(res.is_none(), "abort returns None");
        // Server should have written an END_REQUEST record.
        assert!(!writer.is_empty());
        assert_eq!(writer[1], u8::from(RecordType::EndRequest));
    }
}
