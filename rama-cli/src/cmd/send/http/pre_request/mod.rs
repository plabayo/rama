//! Explicit caller-owned preliminary HTTP requests on the command's existing client.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rama::{
    Service,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    extensions::ExtensionsRef as _,
    http::{
        Body, HeaderName, HeaderValue, Method, Request, Response,
        header::CONTENT_LENGTH,
        headers::{ContentLength, HeaderMapExt as _, TransferEncoding},
    },
    net::{Protocol, uri::Uri},
    ua::profile::{
        format::canonical::ValueId, model::runtime_hints::RequestInitiator,
        selection::variants::VariantPins,
    },
    utils::octets::mib,
};
use serde::Deserialize;
use tokio::io::AsyncReadExt as _;

use super::{SendCommand, WarmupRequest};
use crate::{
    cmd::send::{EmulationProfiles, arg::EmulationHex},
    utils::error::ErrorWithExitCode,
};

const MAX_REQUESTS: usize = 16;
const MAX_INPUT_BYTES: usize = mib(1);
const MAX_BODY_BYTES: usize = 65536;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    method: String,
    uri: String,
    #[serde(default)]
    headers: Vec<(String, String)>,
    body_base64: Option<String>,
    emulate_initiator: Option<RequestInitiator>,
    emulate_connection_variant: Option<String>,
    emulate_request_variant: Option<String>,
}

pub(super) async fn load(cfg: &SendCommand) -> Result<Vec<Request>, BoxError> {
    if cfg.pre_requests.len() > MAX_REQUESTS
        || (!cfg.pre_requests.is_empty() && !cfg.emulate_warmup_connection_variants.is_empty())
    {
        return Err(BoxError::from_static_str(
            "preliminary request count or mixed ordering",
        ));
    }
    let mut requests = Vec::with_capacity(cfg.pre_requests.len());
    let mut total = 0;
    for path in &cfg.pre_requests {
        let file = tokio::fs::File::open(path)
            .await
            .context("open preliminary request")?;
        let mut bytes = Vec::new();
        file.take((MAX_INPUT_BYTES - total + 1) as u64)
            .read_to_end(&mut bytes)
            .await
            .context("read preliminary request")?;
        total += bytes.len();
        if total > MAX_INPUT_BYTES {
            return Err(BoxError::from_static_str(
                "preliminary request input byte limit",
            ));
        }
        let input: Input = serde_json::from_slice(&bytes).context("parse preliminary request")?;
        requests.push(build(cfg, input)?);
    }
    Ok(requests)
}

fn build(cfg: &SendCommand, input: Input) -> Result<Request, BoxError> {
    if input.headers.len() > 256 {
        return Err(BoxError::from_static_str("preliminary header count limit"));
    }
    let method: Method = input.method.parse().context("preliminary request method")?;
    let uri = Uri::parse_reference(input.uri).context("preliminary request URI")?;
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || uri.authority().is_none()
        || uri.fragment().is_some()
        || uri.userinfo().is_some()
        || cfg.http_3 && !uri.scheme().is_some_and(Protocol::is_secure)
        || input.emulate_initiator == Some(RequestInitiator::Ws)
    {
        return Err(BoxError::from_static_str(
            "preliminary request needs an ordinary HTTP(S) URI",
        ));
    }
    let connection = input
        .emulate_connection_variant
        .as_deref()
        .map(str::parse::<EmulationHex>)
        .transpose()
        .context("preliminary connection pin")?;
    let request = input
        .emulate_request_variant
        .as_deref()
        .map(str::parse::<EmulationHex>)
        .transpose()
        .context("preliminary request pin")?;
    if (connection.is_some() || request.is_some())
        && (!matches!(&cfg.emulate, Some(EmulationProfiles::File(_)))
            || cfg.emulate_seed.is_none()
            || cfg.emulate_connection_key.is_none()
            || cfg.emulate_request_key.is_none())
    {
        return Err(BoxError::from_static_str(
            "preliminary pins require explicit captured emulation coordinates",
        ));
    }
    let mut preliminary = Request::new(Body::empty());
    *preliminary.method_mut() = method;
    *preliminary.uri_mut() = uri;
    super::request::apply_preferences(cfg, &mut preliminary)?;
    preliminary.extensions().insert(VariantPins {
        connection: connection.map(|value| ValueId(value.0)),
        request: request.map(|value| ValueId(value.0)),
    });
    if let Some(initiator) = input.emulate_initiator {
        preliminary.extensions().insert(initiator);
    }
    for (name, value) in input.headers {
        let name: HeaderName = name.parse().context("preliminary header name")?;
        let value: HeaderValue = value.parse().context("preliminary header value")?;
        preliminary.headers_mut().append(name, value);
    }
    let has_body = input.body_base64.is_some();
    let body = if let Some(encoded) = input.body_base64 {
        if encoded.len() > MAX_BODY_BYTES.div_ceil(3) * 4 {
            return Err(BoxError::from_static_str(
                "preliminary request body byte limit",
            ));
        }
        let body = STANDARD
            .decode(encoded)
            .context("preliminary base64 body")?;
        if body.len() > MAX_BODY_BYTES {
            return Err(BoxError::from_static_str(
                "preliminary request body byte limit",
            ));
        }
        body
    } else {
        Vec::new()
    };
    let length = preliminary
        .headers()
        .typed_try_get::<ContentLength>()
        .context("preliminary Content-Length")?;
    let transfer = preliminary
        .headers()
        .typed_try_get::<TransferEncoding>()
        .context("preliminary Transfer-Encoding")?;
    if length.is_some_and(|length| length.0 != body.len() as u64)
        || length.is_some() && transfer.is_some()
        || transfer
            .as_ref()
            .is_some_and(|transfer| !cfg.http_11 || transfer.0.len() != 1 || !transfer.is_chunked())
    {
        return Err(BoxError::from_static_str(
            "inconsistent or unsupported preliminary body framing",
        ));
    }
    if has_body && length.is_none() && transfer.is_none() {
        preliminary
            .headers_mut()
            .append(CONTENT_LENGTH, HeaderValue::from(body.len()));
    }
    *preliminary.body_mut() = Body::from(body);
    preliminary.extensions().insert(WarmupRequest);
    Ok(preliminary)
}

pub(super) async fn run<C>(
    cfg: &SendCommand,
    client: &C,
    requests: Vec<Request>,
) -> Result<(), BoxError>
where
    C: Service<Request, Output = Response>,
    C::Error: Into<BoxError>,
{
    for request in requests {
        let response = client
            .serve(request)
            .await
            .map_err(Into::into)
            .context("explicit preliminary request")?;
        if cfg.fail && (response.status().is_client_error() || response.status().is_server_error())
        {
            return Err(Box::new(ErrorWithExitCode {
                error: BoxError::from_static_str("preliminary HTTP failure status code")
                    .context_field("code", response.status()),
                code: 22,
            }));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
