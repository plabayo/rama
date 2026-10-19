//! Further requests on the command's client, given with `--next`.

use clap::{Args, Command, FromArgMatches as _};
use rama::{
    error::{BoxError, BoxErrorExt as _, ErrorExt as _},
    http::service::client::multipart::{FieldSpec, FieldSpecSource},
};

use std::{iter, mem};

use super::{RequestArgs, SendCommand};
use crate::cmd::uri::parse_user_uri;

/// The requests after the first one, parsed from each `--next` in order.
///
/// Client options (proxy, TLS, HTTP version, emulation profile and keys, output)
/// come from before the first `--next` and apply to every request.
pub(super) fn following_requests(cfg: &SendCommand) -> Result<Vec<RequestArgs>, BoxError> {
    validate(cfg, &cfg.req)?;
    let mut requests = Vec::new();
    let mut rest = parse(&cfg.req.next)?;
    while let Some(mut request) = rest {
        validate(cfg, &request)?;
        // Each request owns only its own options; the tail moves on, uncopied.
        let tail = mem::take(&mut request.next);
        requests.push(request);
        rest = parse(&tail)?;
    }
    // Stdin can be consumed only once for the whole command.
    let stdin_reads: usize = iter::once(&cfg.req).chain(&requests).map(stdin_reads).sum();
    if stdin_reads > 1 {
        return Err(BoxError::from_static_str(
            "stdin (@- or <-) can be used as a request body only once",
        ));
    }
    // A WebSocket takes over the connection, so it can only end the sequence.
    if let Some(ws) = iter::once(&cfg.req)
        .chain(&requests)
        .take(requests.len())
        .find(|request| is_ws_uri(&request.uri))
    {
        return Err(
            BoxError::from_static_str("only the last --next request may use a ws/wss URI")
                .context_str_field("uri", ws.uri.as_str()),
        );
    }
    Ok(requests)
}

fn stdin_reads(request: &RequestArgs) -> usize {
    let data = request
        .data
        .iter()
        .flatten()
        .filter(|data| {
            data.strip_prefix('@')
                .is_some_and(|path| path.trim_end() == "-")
        })
        .count();
    let form = request
        .form_data
        .iter()
        .flatten()
        .filter(|spec| {
            FieldSpec::parse(spec).is_ok_and(|spec| {
                matches!(
                    spec.source,
                    FieldSpecSource::File("-") | FieldSpecSource::FileText("-")
                )
            })
        })
        .count();
    data + form
}

fn is_ws_uri(uri: &str) -> bool {
    parse_user_uri(uri).is_ok_and(|uri| uri.scheme().is_some_and(|scheme| scheme.is_ws()))
}

fn parse(arguments: &[String]) -> Result<Option<RequestArgs>, BoxError> {
    if arguments.is_empty() {
        return Ok(None);
    }
    let matches = RequestArgs::augment_args(Command::new("next").no_binary_name(true))
        .try_get_matches_from(arguments)?;
    Ok(Some(RequestArgs::from_arg_matches(&matches)?))
}

/// Emulation request options need the command's emulation profile, and pins its keys.
fn validate(cfg: &SendCommand, request: &RequestArgs) -> Result<(), BoxError> {
    let pinned =
        request.emulate_connection_variant.is_some() || request.emulate_request_variant.is_some();
    let emulated =
        pinned || request.emulate_initiator.is_some() || request.emulate_connection_bootstrap;
    if emulated && cfg.emulate.is_none() {
        return Err(BoxError::from_static_str(
            "request emulation options require --emulate",
        ));
    }
    if pinned
        && (cfg.emulate_seed.is_none()
            || cfg.emulate_connection_key.is_none()
            || cfg.emulate_request_key.is_none())
    {
        return Err(BoxError::from_static_str(
            "variant pins require --emulate-seed and both draw keys",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
