use std::{env, error::Error, net::SocketAddr};

use rama_core::bytes::{Bytes, BytesMut};
use rama_icap::{
    codec::{Header, HeaderSlot, ResponseLine},
    io::BodyEnd,
    message::{EncapsulatedParts, Response, TrailerBlock},
    proto::{EncapsulatedKind, MethodKind, StatusCode, header},
    server::{ServerConnection, ServerTransaction},
};
use tokio::net::{TcpListener, TcpStream};

type BoxError = Box<dyn Error + Send + Sync>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Normal,
    Always204,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let mut args = env::args().skip(1);
    let mode = match args.next().as_deref() {
        Some("normal") => Mode::Normal,
        Some("204") => Mode::Always204,
        _ => return Err("usage: c_icap_oracle_server normal|204 ADDRESS".into()),
    };
    let address: SocketAddr = args.next().ok_or("missing listen address")?.parse()?;
    if args.next().is_some() {
        return Err("too many arguments".into());
    }

    let listener = TcpListener::bind(address).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, mode).await {
                eprintln!("Rama ICAP oracle connection failed: {error}");
            }
        });
    }
}

async fn serve_connection(stream: TcpStream, mode: Mode) -> Result<(), BoxError> {
    let mut connection = ServerConnection::new(stream);
    while let Some(transaction) = connection.accept().await? {
        let close = transaction.request().should_close();
        serve_request(transaction, mode).await?;
        if close {
            return Ok(());
        }
    }
    Ok(())
}

async fn serve_request<IO>(
    mut transaction: ServerTransaction<'_, IO>,
    mode: Mode,
) -> Result<(), BoxError>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (method, path) = {
        let mut slots = [HeaderSlot::EMPTY; 32];
        let head = transaction.request().parse_head(&mut slots)?;
        (
            head.line().method().kind(),
            head.line().uri().path_str().to_owned(),
        )
    };
    let allow_206 = transaction.request().allows_206();

    if method == MethodKind::Options {
        return transaction
            .respond(options_response()?)
            .await?
            .finish()
            .await
            .map_err(Into::into);
    }

    let incoming = transaction.request().encapsulated().cloned();
    let mut body = BytesMut::new();
    loop {
        while let Some(data) = transaction.next_data().await? {
            body.extend_from_slice(&data);
        }
        if transaction.body_end() != Some(BodyEnd::Preview) {
            break;
        }
        if mode == Mode::Always204 {
            return transaction
                .respond(status_response(
                    method,
                    StatusCode::NO_MODIFICATION_NEEDED,
                    b"No Content",
                    None,
                )?)
                .await?
                .finish()
                .await
                .map_err(Into::into);
        }
        transaction.continue_preview().await?;
    }

    if mode == Mode::Always204 {
        return transaction
            .respond(status_response(
                method,
                StatusCode::NO_MODIFICATION_NEEDED,
                b"No Content",
                None,
            )?)
            .await?
            .finish()
            .await
            .map_err(Into::into);
    }

    if matches!(path.as_str(), "/ex206" | "/full206") {
        if !allow_206 {
            return transaction
                .respond(status_response(
                    method,
                    StatusCode::NO_MODIFICATION_NEEDED,
                    b"No Content",
                    None,
                )?)
                .await?
                .finish()
                .await
                .map_err(Into::into);
        }
        if path == "/full206" {
            return respond_full_206(transaction, method).await;
        }
        return respond_206(transaction, &body).await;
    }

    let trailers = transaction
        .trailers()
        .cloned()
        .unwrap_or_else(TrailerBlock::empty);
    let parts = echo_parts(method, incoming.as_ref())?;
    let response = status_response(method, StatusCode::OK, b"OK", Some(parts.clone()))?;
    let mut response = transaction.respond(response).await?;
    if parts.has_body() {
        response.write_data(&body).await?;
        response.finish_with_trailers(&trailers).await?;
    } else {
        response.finish().await?;
    }
    Ok(())
}

fn options_response() -> Result<Response, BoxError> {
    let fields = [
        Header::new(header::METHODS, b"REQMOD, RESPMOD")?,
        Header::new("Service", b"Rama ICAP oracle")?,
        Header::new(header::ISTAG, b"\"rama-oracle\"")?,
        Header::new(header::PREVIEW, b"1024")?,
        Header::new("Allow", b"204, 206")?,
        Header::new(header::TRANSFER_PREVIEW, b"*")?,
    ];
    Ok(Response::new(
        MethodKind::Options,
        ResponseLine::new(StatusCode::OK, b"OK")?,
        &fields,
        Some(EncapsulatedParts::null()),
    )?)
}

fn status_response(
    method: MethodKind,
    status: StatusCode,
    reason: &'static [u8],
    parts: Option<EncapsulatedParts>,
) -> Result<Response, BoxError> {
    let istag = Header::new(header::ISTAG, b"\"rama-oracle\"")?;
    let fields = matches!(status, StatusCode::OK | StatusCode::PARTIAL_CONTENT).then_some(istag);
    Ok(Response::new(
        method,
        ResponseLine::new(status, reason)?,
        fields.as_slice(),
        parts,
    )?)
}

fn echo_parts(
    method: MethodKind,
    incoming: Option<&EncapsulatedParts>,
) -> Result<EncapsulatedParts, BoxError> {
    let incoming = incoming.ok_or("adaptation request lacks Encapsulated")?;
    let has_body = incoming.has_body();
    match method {
        MethodKind::Reqmod => Ok(EncapsulatedParts::new(
            incoming.request_header().cloned(),
            None,
            if has_body {
                EncapsulatedKind::RequestBody
            } else {
                EncapsulatedKind::NullBody
            },
        )?),
        MethodKind::Respmod => Ok(EncapsulatedParts::new(
            None,
            incoming.response_header().cloned(),
            if has_body {
                EncapsulatedKind::ResponseBody
            } else {
                EncapsulatedKind::NullBody
            },
        )?),
        MethodKind::Options | MethodKind::Extension => Err("unsupported oracle method".into()),
    }
}

async fn respond_206<IO>(
    transaction: ServerTransaction<'_, IO>,
    original: &[u8],
) -> Result<(), BoxError>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    const HTML: &[u8] = b"<html><body>rama ICAP oracle</body></html>\n";
    const PREFIX: &[u8] = b"<html>\n<!--A simple comment added by the  ex206 C-ICAP service-->\n\n";

    let (content_length, prefix, offset) = if original == HTML {
        (104, PREFIX, 6)
    } else {
        (original.len(), &[][..], 0)
    };
    let response_header = Bytes::from(format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {content_length}\r\n\r\n"
    ));
    let parts =
        EncapsulatedParts::new(None, Some(response_header), EncapsulatedKind::ResponseBody)?;
    let response = status_response(
        MethodKind::Respmod,
        StatusCode::PARTIAL_CONTENT,
        b"Partial Content",
        Some(parts),
    )?;
    let mut response = transaction.respond(response).await?;
    response.write_data(prefix).await?;
    response.finish_partial(offset).await?;
    Ok(())
}

async fn respond_full_206<IO>(
    transaction: ServerTransaction<'_, IO>,
    method: MethodKind,
) -> Result<(), BoxError>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    const ADAPTED: &[u8] = b"fully adapted by rama\n";
    if method != MethodKind::Respmod {
        return Err("full206 is a RESPMOD-only oracle service".into());
    }
    let response_header = Bytes::from(format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        ADAPTED.len()
    ));
    let parts =
        EncapsulatedParts::new(None, Some(response_header), EncapsulatedKind::ResponseBody)?;
    let response = status_response(
        method,
        StatusCode::PARTIAL_CONTENT,
        b"Partial Content",
        Some(parts),
    )?;
    let mut response = transaction.respond(response).await?;
    response.write_data(ADAPTED).await?;
    response.finish().await?;
    Ok(())
}
