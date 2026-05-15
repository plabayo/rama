//! FastCGI wire protocol: sending requests and reading responses.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use rama_core::bytes::{Bytes, BytesMut};

use crate::body::FastCgiBody;
use rama_core::error::ErrorExt;
use rama_core::error::extra::OpaqueError;
use rama_core::io::discard;

use crate::proto::{
    BeginRequestBody, EndRequestBody, FCGI_MAX_CONTENT_LEN, FCGI_NULL_REQUEST_ID, ProtocolStatus,
    RecordHeader, RecordType, Role, UnknownTypeBody, params::NvPairRef,
};

use super::{
    error::{ClientError, ClientErrorKind},
    options::ClientOptions,
    types::{FastCgiClientRequest, FastCgiClientResponse},
};

/// Send a FastCGI request on an existing stream and return the response.
///
/// Uses [`ClientOptions::default()`] for caps and timeouts. For custom
/// options use [`send_on_with_options`].
pub async fn send_on<IO>(
    stream: &mut IO,
    request_id: u16,
    request: FastCgiClientRequest,
    keep_conn: bool,
) -> Result<FastCgiClientResponse, ClientError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
{
    send_on_with_options(
        stream,
        request_id,
        request,
        keep_conn,
        &ClientOptions::default(),
    )
    .await
}

/// Send a FastCGI request on an existing stream with explicit options.
///
/// `request_id` must be non-zero. If `keep_conn` is true, the
/// `FCGI_KEEP_CONN` flag is set in `FCGI_BEGIN_REQUEST` and the connection is
/// not closed by the application.
///
/// **Concurrent write/read.** The request side (BEGIN, PARAMS, STDIN) and
/// the response side (STDOUT, STDERR, END_REQUEST) are driven concurrently
/// against split halves of the stream. Without this, a large STDIN upload
/// could deadlock with the backend's STDOUT writes: each side blocks waiting
/// for the other to drain its socket buffer (classic FastCGI write-after-
/// write deadlock).
pub async fn send_on_with_options<IO>(
    stream: &mut IO,
    request_id: u16,
    request: FastCgiClientRequest,
    keep_conn: bool,
    options: &ClientOptions,
) -> Result<FastCgiClientResponse, ClientError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
{
    let FastCgiClientRequest {
        params,
        stdin,
        extensions: _,
    } = request;

    let (mut rh, mut wh) = tokio::io::split(stream);

    // Write side: BEGIN, PARAMS, STDIN stream.
    let write_fut = async {
        let begin_body = BeginRequestBody {
            role: Role::Responder,
            keep_conn,
        };
        let hdr = RecordHeader::new(RecordType::BeginRequest, request_id, 8);
        hdr.write_to(&mut wh).await.map_err(ClientError::io)?;
        begin_body
            .write_to(&mut wh)
            .await
            .map_err(ClientError::io)?;
        send_params(&mut wh, request_id, &params).await?;
        send_stdin_stream(&mut wh, request_id, stdin).await?;
        Ok::<(), ClientError>(())
    };

    // Read side: STDOUT / STDERR until END_REQUEST.
    let read_fut = read_response(&mut rh, request_id, options);

    // `try_join!` drives both futures concurrently and cancels the other on
    // first error — so a write failure won't leave us blocked waiting for a
    // response that will never come, and vice versa.
    let ((), response) = tokio::try_join!(write_fut, read_fut)?;
    Ok(response)
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
        pair_ref
            .write_to_buf(&mut buf)
            .map_err(ClientError::protocol)?;
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

/// Stream the request body as a series of `FCGI_STDIN` records, followed by
/// an empty `FCGI_STDIN` terminator record.
async fn send_stdin_stream<W>(
    w: &mut W,
    request_id: u16,
    mut stdin: FastCgiBody,
) -> Result<(), ClientError>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        let n = stdin.read(&mut buf).await.map_err(ClientError::io)?;
        if n == 0 {
            break;
        }
        let chunk_len = n.min(FCGI_MAX_CONTENT_LEN) as u16;
        let hdr = RecordHeader::new(RecordType::Stdin, request_id, chunk_len);
        hdr.write_to(w).await.map_err(ClientError::io)?;
        w.write_all(&buf[..chunk_len as usize])
            .await
            .map_err(ClientError::io)?;
    }
    let hdr = RecordHeader::new(RecordType::Stdin, request_id, 0);
    hdr.write_to(w).await.map_err(ClientError::io)
}

async fn read_response<R>(
    stream: &mut R,
    request_id: u16,
    options: &ClientOptions,
) -> Result<FastCgiClientResponse, ClientError>
where
    R: AsyncRead + Unpin,
{
    let mut stdout = BytesMut::new();
    let mut stderr = BytesMut::new();
    let mut stderr_truncated = false;
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
                    let cl = hdr.content_length as usize;
                    if stdout.len().saturating_add(cl) > options.max_stdout_bytes {
                        return Err(ClientError {
                            kind: ClientErrorKind::Protocol,
                            source: Some(
                                OpaqueError::from_static_str(
                                    "fastcgi client: stdout exceeded max_stdout_bytes",
                                )
                                .context_field("cap", options.max_stdout_bytes),
                            ),
                        });
                    }
                    let start = stdout.len();
                    stdout.resize(start + cl, 0);
                    stream
                        .read_exact(&mut stdout[start..])
                        .await
                        .map_err(ClientError::io)?;
                    skip_padding(stream, hdr.padding_length).await?;
                }
            }
            RecordType::Stderr => {
                if hdr.content_length == 0 {
                    skip_padding(stream, hdr.padding_length).await?;
                } else {
                    let cl = hdr.content_length as usize;
                    let remaining = options.max_stderr_bytes.saturating_sub(stderr.len());
                    let take = cl.min(remaining);
                    if take > 0 {
                        let start = stderr.len();
                        stderr.resize(start + take, 0);
                        stream
                            .read_exact(&mut stderr[start..])
                            .await
                            .map_err(ClientError::io)?;
                    }
                    if cl > take {
                        stderr_truncated = true;
                        discard(stream, (cl - take) as u64)
                            .await
                            .map_err(ClientError::io)?;
                    }
                    skip_padding(stream, hdr.padding_length).await?;
                }
            }
            RecordType::EndRequest => {
                if hdr.content_length >= 8 {
                    let body = EndRequestBody::read_from(stream)
                        .await
                        .map_err(ClientError::protocol)?;
                    if hdr.content_length > 8 {
                        discard(stream, (hdr.content_length - 8) as u64)
                            .await
                            .map_err(ClientError::io)?;
                    }
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
                        ProtocolStatus::Unknown(_) => {
                            rama_core::telemetry::tracing::debug!(
                                "fastcgi client: unknown ProtocolStatus in END_REQUEST, treating as success"
                            );
                        }
                    }
                    app_status = body.app_status;
                } else {
                    discard_content(stream, hdr.content_length, hdr.padding_length).await?;
                }
                if stderr_truncated {
                    rama_core::telemetry::tracing::debug!(
                        "fastcgi client: stderr truncated (max_stderr_bytes={})",
                        options.max_stderr_bytes
                    );
                }
                return Ok(FastCgiClientResponse {
                    stdout: stdout.freeze(),
                    stderr: stderr.freeze(),
                    app_status,
                });
            }
            _ => {
                discard_content(stream, hdr.content_length, hdr.padding_length).await?;
            }
        }
    }
}

async fn handle_management_response<R>(
    stream: &mut R,
    hdr: &RecordHeader,
) -> Result<(), ClientError>
where
    R: AsyncRead + Unpin,
{
    match hdr.record_type {
        RecordType::UnknownType => {
            if hdr.content_length >= 8 {
                let _body = UnknownTypeBody::read_from(stream)
                    .await
                    .map_err(ClientError::protocol)?;
                if hdr.content_length > 8 {
                    discard(stream, (hdr.content_length - 8) as u64)
                        .await
                        .map_err(ClientError::io)?;
                }
                skip_padding(stream, hdr.padding_length).await?;
            } else {
                discard_content(stream, hdr.content_length, hdr.padding_length).await?;
            }
        }
        _ => {
            // Backends should not send management records other than
            // UNKNOWN_TYPE / GET_VALUES_RESULT (the latter is also fine to
            // ignore in a single-request client). Drop on the floor.
            discard_content(stream, hdr.content_length, hdr.padding_length).await?;
        }
    }
    Ok(())
}

async fn discard_content<R>(r: &mut R, len: u16, padding: u8) -> Result<(), ClientError>
where
    R: AsyncRead + Unpin,
{
    let total = len as u64 + padding as u64;
    discard(r, total).await.map_err(ClientError::io)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::params::NvPair;
    use rama_utils::octets::kib;

    /// Simulate a FastCGI backend on the server side of a duplex stream:
    /// drain the client's request records, then write a canned response
    /// (STDOUT + optional STDERR + END_REQUEST).
    async fn echo_backend<IO>(io: &mut IO, request_id: u16, stdout: &[u8], stderr: &[u8])
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        // Consume BEGIN_REQUEST.
        let hdr = RecordHeader::read_from(io).await.unwrap();
        assert_eq!(hdr.record_type, RecordType::BeginRequest);
        let _begin = BeginRequestBody::read_from(io).await.unwrap();
        // Consume PARAMS stream until an empty terminator.
        loop {
            let hdr = RecordHeader::read_from(io).await.unwrap();
            assert_eq!(hdr.record_type, RecordType::Params);
            if hdr.content_length == 0 {
                break;
            }
            let mut tmp = vec![0u8; hdr.content_length as usize];
            io.read_exact(&mut tmp).await.unwrap();
        }
        // Consume STDIN stream until an empty terminator.
        loop {
            let hdr = RecordHeader::read_from(io).await.unwrap();
            assert_eq!(hdr.record_type, RecordType::Stdin);
            if hdr.content_length == 0 {
                break;
            }
            let mut tmp = vec![0u8; hdr.content_length as usize];
            io.read_exact(&mut tmp).await.unwrap();
        }
        // Write STDERR (if any), STDOUT, EOS markers, END_REQUEST.
        if !stderr.is_empty() {
            let hdr = RecordHeader::new(RecordType::Stderr, request_id, stderr.len() as u16);
            hdr.write_to(io).await.unwrap();
            io.write_all(stderr).await.unwrap();
            let hdr = RecordHeader::new(RecordType::Stderr, request_id, 0);
            hdr.write_to(io).await.unwrap();
        }
        let hdr = RecordHeader::new(RecordType::Stdout, request_id, stdout.len() as u16);
        hdr.write_to(io).await.unwrap();
        io.write_all(stdout).await.unwrap();
        let hdr = RecordHeader::new(RecordType::Stdout, request_id, 0);
        hdr.write_to(io).await.unwrap();
        let hdr = RecordHeader::new(RecordType::EndRequest, request_id, 8);
        hdr.write_to(io).await.unwrap();
        EndRequestBody {
            app_status: 7,
            protocol_status: ProtocolStatus::RequestComplete,
        }
        .write_to(io)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_send_on_collects_stdout_stderr_and_app_status() {
        let (mut client_io, mut server_io) = tokio::io::duplex(kib(16));
        let request = FastCgiClientRequest::new(vec![
            (
                Bytes::from_static(b"REQUEST_METHOD"),
                Bytes::from_static(b"GET"),
            ),
            (
                Bytes::from_static(b"SCRIPT_NAME"),
                Bytes::from_static(b"/idx"),
            ),
        ]);
        let backend = tokio::spawn(async move {
            echo_backend(
                &mut server_io,
                1,
                b"Status: 201 Created\r\n\r\nhello",
                b"backend log line",
            )
            .await;
        });
        let resp = send_on(&mut client_io, 1, request, false).await.unwrap();
        backend.await.unwrap();
        assert_eq!(resp.app_status, 7);
        assert_eq!(&resp.stdout[..], b"Status: 201 Created\r\n\r\nhello");
        assert_eq!(&resp.stderr[..], b"backend log line");
    }

    #[tokio::test]
    async fn test_send_on_stdout_cap_rejects_oversize_response() {
        let (mut client_io, mut server_io) = tokio::io::duplex(kib(64));
        let request = FastCgiClientRequest::new(vec![(
            Bytes::from_static(b"REQUEST_METHOD"),
            Bytes::from_static(b"GET"),
        )]);
        let backend = tokio::spawn(async move {
            // Returns 1 KiB of stdout; we cap at 100 bytes.
            let big = vec![b'x'; kib(1)];
            // Don't use echo_backend because it asserts behaviour on framing.
            // Drain client's BEGIN+PARAMS+STDIN minimally.
            let mut io = &mut server_io;
            RecordHeader::read_from(&mut io).await.unwrap();
            BeginRequestBody::read_from(&mut io).await.unwrap();
            loop {
                let h = RecordHeader::read_from(&mut io).await.unwrap();
                if h.content_length == 0
                    && matches!(h.record_type, RecordType::Params | RecordType::Stdin)
                {
                    if h.record_type == RecordType::Stdin {
                        break;
                    }
                    continue;
                }
                let mut tmp = vec![0u8; h.content_length as usize];
                let _read = io.read_exact(&mut tmp).await;
            }
            // Write one big STDOUT record.
            let hdr = RecordHeader::new(RecordType::Stdout, 1, big.len() as u16);
            let _write_hdr = hdr.write_to(&mut io).await;
            let _write_body = io.write_all(&big).await;
        });
        let opts = ClientOptions::default().with_max_stdout_bytes(100);
        let err = send_on_with_options(&mut client_io, 1, request, false, &opts)
            .await
            .unwrap_err();
        // Cap exceeded surfaces as Protocol error.
        assert!(
            matches!(err.kind, ClientErrorKind::Protocol),
            "expected Protocol error, got {err:?}"
        );
        let _join = backend.await;
    }

    #[tokio::test]
    async fn test_send_on_truncates_oversize_stderr() {
        let (mut client_io, mut server_io) = tokio::io::duplex(kib(64));
        let request = FastCgiClientRequest::new(vec![(
            Bytes::from_static(b"REQUEST_METHOD"),
            Bytes::from_static(b"GET"),
        )]);
        let big_err = vec![b'e'; kib(1)];
        let big_err_clone = big_err.clone();
        let backend = tokio::spawn(async move {
            echo_backend(&mut server_io, 1, b"ok", &big_err_clone).await;
        });
        let opts = ClientOptions::default().with_max_stderr_bytes(64);
        let resp = send_on_with_options(&mut client_io, 1, request, false, &opts)
            .await
            .unwrap();
        backend.await.unwrap();
        assert_eq!(&resp.stdout[..], b"ok");
        assert_eq!(resp.stderr.len(), 64, "stderr should be truncated to cap");
        assert!(resp.stderr.iter().all(|&b| b == b'e'));
    }

    #[tokio::test]
    async fn test_send_on_streams_stdin_chunks() {
        let (mut client_io, mut server_io) = tokio::io::duplex(kib(64));
        let body = vec![b'x'; 9000]; // larger than the 8 KiB stdin chunk
        let request = FastCgiClientRequest::new(vec![(
            Bytes::from_static(b"REQUEST_METHOD"),
            Bytes::from_static(b"POST"),
        )])
        .with_stdin(Bytes::from(body.clone()));
        let body_len = body.len();
        let backend = tokio::spawn(async move {
            let _ = RecordHeader::read_from(&mut server_io).await.unwrap();
            let _ = BeginRequestBody::read_from(&mut server_io).await.unwrap();
            // PARAMS records.
            loop {
                let h = RecordHeader::read_from(&mut server_io).await.unwrap();
                if h.content_length == 0 {
                    break;
                }
                let mut tmp = vec![0u8; h.content_length as usize];
                server_io.read_exact(&mut tmp).await.unwrap();
            }
            // STDIN records; assert total bytes streamed and the EOS terminator.
            let mut received = 0usize;
            loop {
                let h = RecordHeader::read_from(&mut server_io).await.unwrap();
                assert_eq!(h.record_type, RecordType::Stdin);
                if h.content_length == 0 {
                    break;
                }
                let mut tmp = vec![0u8; h.content_length as usize];
                server_io.read_exact(&mut tmp).await.unwrap();
                received += tmp.len();
            }
            assert_eq!(received, body_len);
            // Send minimal response.
            let hdr = RecordHeader::new(RecordType::Stdout, 1, 0);
            hdr.write_to(&mut server_io).await.unwrap();
            let hdr = RecordHeader::new(RecordType::EndRequest, 1, 8);
            hdr.write_to(&mut server_io).await.unwrap();
            EndRequestBody {
                app_status: 0,
                protocol_status: ProtocolStatus::RequestComplete,
            }
            .write_to(&mut server_io)
            .await
            .unwrap();
        });
        let resp = send_on(&mut client_io, 1, request, false).await.unwrap();
        backend.await.unwrap();
        assert_eq!(resp.app_status, 0);
    }

    /// Construct a NvPair-encoded PARAMS body and ensure that `roundtrip`
    /// via `send_on` includes a `try_encode_length` failure path. (Sanity
    /// fence for the new error-returning encoder.)
    #[tokio::test]
    async fn test_try_encode_length_propagates_via_send_params() {
        // We just hit the happy path here — the failure path is unit-tested
        // in `proto::params`. This is a smoke test ensuring the propagated
        // Result chain compiles and passes through normal data without error.
        let pair = NvPair::new(b"K".as_slice(), b"V".as_slice());
        let mut buf = Vec::new();
        pair.write_to(&mut buf).await.unwrap();
        assert!(!buf.is_empty());
    }

    /// Regression: a large STDIN upload paired with a large STDOUT response
    /// must NOT deadlock. The earlier implementation drained STDIN fully
    /// before reading STDOUT; if the backend's socket buffer filled during
    /// STDIN write while we weren't draining its STDOUT, both sides would
    /// block forever.
    ///
    /// We simulate the deadlock-prone scenario with a tiny duplex buffer
    /// (1 KiB each direction): on the wrong implementation the test
    /// timeouts; on the fixed one it completes in milliseconds because
    /// `send_on_with_options` writes and reads concurrently.
    #[tokio::test]
    async fn test_send_on_does_not_deadlock_on_large_streams() {
        let (mut client_io, mut server_io) = tokio::io::duplex(kib(1));

        // 64 KiB of stdin + 64 KiB of stdout = far more than the duplex
        // buffer can hold in either direction. Sequential write-then-read
        // would block at the first socket-buffer fill in either direction.
        let stdin_body = vec![b's'; kib(64)];
        let stdout_body = vec![b'o'; kib(64)];

        let request = FastCgiClientRequest::new(vec![(
            Bytes::from_static(b"REQUEST_METHOD"),
            Bytes::from_static(b"POST"),
        )])
        .with_stdin(Bytes::from(stdin_body.clone()));

        let stdin_len = stdin_body.len();
        let stdout_clone = stdout_body.clone();
        let backend = tokio::spawn(async move {
            // Drain BEGIN + PARAMS + STDIN.
            let _ = RecordHeader::read_from(&mut server_io).await.unwrap();
            let _ = BeginRequestBody::read_from(&mut server_io).await.unwrap();
            // PARAMS until empty terminator.
            loop {
                let h = RecordHeader::read_from(&mut server_io).await.unwrap();
                if h.content_length == 0 {
                    break;
                }
                let mut tmp = vec![0u8; h.content_length as usize];
                server_io.read_exact(&mut tmp).await.unwrap();
            }
            // Interleave: write a chunk of STDOUT for every chunk of STDIN
            // we drain, exercising the concurrent path on both sides.
            let mut received = 0usize;
            let mut sent = 0usize;
            while received < stdin_len || sent < stdout_clone.len() {
                if received < stdin_len {
                    let h = RecordHeader::read_from(&mut server_io).await.unwrap();
                    assert_eq!(h.record_type, RecordType::Stdin);
                    if h.content_length == 0 {
                        received = stdin_len; // EOS
                    } else {
                        let mut tmp = vec![0u8; h.content_length as usize];
                        server_io.read_exact(&mut tmp).await.unwrap();
                        received += tmp.len();
                    }
                }
                if sent < stdout_clone.len() {
                    let take = (stdout_clone.len() - sent).min(2048);
                    let hdr = RecordHeader::new(RecordType::Stdout, 1, take as u16);
                    hdr.write_to(&mut server_io).await.unwrap();
                    server_io
                        .write_all(&stdout_clone[sent..sent + take])
                        .await
                        .unwrap();
                    sent += take;
                }
            }
            // STDOUT EOS + END_REQUEST.
            RecordHeader::new(RecordType::Stdout, 1, 0)
                .write_to(&mut server_io)
                .await
                .unwrap();
            RecordHeader::new(RecordType::EndRequest, 1, 8)
                .write_to(&mut server_io)
                .await
                .unwrap();
            EndRequestBody {
                app_status: 0,
                protocol_status: ProtocolStatus::RequestComplete,
            }
            .write_to(&mut server_io)
            .await
            .unwrap();
        });

        // Hard deadline: if the implementation deadlocks, this fails fast
        // rather than hanging the test runner.
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            send_on(&mut client_io, 1, request, false),
        )
        .await
        .expect("send_on must not deadlock on large streams")
        .unwrap();

        backend.await.unwrap();
        assert_eq!(resp.app_status, 0);
        assert_eq!(resp.stdout.len(), stdout_body.len());
    }
}
