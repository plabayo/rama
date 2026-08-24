use core::convert::Infallible;
use std::{env, error::Error, net::SocketAddr};

use rama_core::{
    Service, ServiceInput,
    bytes::{Bytes, BytesMut},
    futures::stream,
};
use rama_icap::{
    codec::{Header, HeaderSlot, ResponseLine},
    io::BodyEnd,
    message::{EncapsulatedParts, Response, TrailerBlock},
    proto::{EncapsulatedKind, MethodKind, StatusCode, header},
    server::{BodyFrame, IncomingRequest, OutgoingBody, OutgoingResponse, Server},
};
use tokio::net::TcpListener;
use tokio::task::JoinSet;

type BoxError = Box<dyn Error + Send + Sync>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Normal,
    Always204,
}

#[derive(Clone, Copy, Debug)]
struct Oracle {
    mode: Mode,
}

impl Service<IncomingRequest> for Oracle {
    type Output = OutgoingResponse;
    type Error = BoxError;

    async fn serve(&self, request: IncomingRequest) -> Result<Self::Output, Self::Error> {
        serve_request(request, self.mode).await
    }
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
    let server = Server::new(Oracle { mode }, b"\"rama-oracle\"")?;
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let server = server.clone();
                connections.spawn(async move {
                    server.serve_connection(ServiceInput::new(stream)).await
                });
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                match completed {
                    Some(Ok(Ok(()))) | None => {}
                    Some(Ok(Err(error))) => return Err(Box::new(error) as BoxError),
                    Some(Err(error)) => return Err(Box::new(error) as BoxError),
                }
            }
        }
    }
}

async fn serve_request(
    mut request: IncomingRequest,
    mode: Mode,
) -> Result<OutgoingResponse, BoxError> {
    let (method, path) = {
        let mut slots = [HeaderSlot::EMPTY; 32];
        let head = request.request().parse_head(&mut slots)?;
        (
            head.line().method().kind(),
            head.line().uri().path_str().to_owned(),
        )
    };
    let allow_206 = request.request().allows_206();

    if method == MethodKind::Options {
        return Ok(OutgoingResponse::without_body(options_response()?));
    }

    let incoming = request.request().encapsulated().cloned();
    let mut body = BytesMut::new();
    loop {
        while let Some(data) = request.body_mut().next_data().await? {
            body.extend_from_slice(&data);
        }
        if request.body().body_end() != Some(BodyEnd::Preview) {
            break;
        }
        if mode == Mode::Always204 {
            return Ok(OutgoingResponse::without_body(status_response(
                method,
                StatusCode::NO_MODIFICATION_NEEDED,
                b"No Content",
                None,
            )?));
        }
        request.body_mut().continue_preview().await?;
    }

    if mode == Mode::Always204 {
        return Ok(OutgoingResponse::without_body(status_response(
            method,
            StatusCode::NO_MODIFICATION_NEEDED,
            b"No Content",
            None,
        )?));
    }

    if matches!(path.as_str(), "/ex206" | "/full206") {
        if !allow_206 {
            return Ok(OutgoingResponse::without_body(status_response(
                method,
                StatusCode::NO_MODIFICATION_NEEDED,
                b"No Content",
                None,
            )?));
        }
        if path == "/full206" {
            return respond_full_206(method);
        }
        return respond_206(&body);
    }

    let trailers = request
        .body()
        .trailers()
        .cloned()
        .unwrap_or_else(TrailerBlock::empty);
    let parts = echo_parts(method, incoming.as_ref())?;
    let response = status_response(method, StatusCode::OK, b"OK", Some(parts.clone()))?;
    if parts.has_body() {
        Ok(streaming_response(response, body.freeze(), trailers))
    } else {
        Ok(OutgoingResponse::without_body(response))
    }
}

fn streaming_response(response: Response, body: Bytes, trailers: TrailerBlock) -> OutgoingResponse {
    let frames = [
        (!body.is_empty()).then_some(BodyFrame::Data(body)),
        (!trailers.is_empty()).then_some(BodyFrame::Trailers(trailers)),
    ]
    .into_iter()
    .flatten()
    .map(Ok::<_, Infallible>);
    OutgoingResponse::new(response, OutgoingBody::from_frames(stream::iter(frames)))
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
    Ok(Response::new(
        method,
        ResponseLine::new(status, reason)?,
        &[istag],
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

fn respond_206(original: &[u8]) -> Result<OutgoingResponse, BoxError> {
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
    Ok(OutgoingResponse::new(response, prefix).with_use_original_body(offset))
}

fn respond_full_206(method: MethodKind) -> Result<OutgoingResponse, BoxError> {
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
    Ok(OutgoingResponse::new(response, ADAPTED))
}
