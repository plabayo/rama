//! Further requests on the command's client, given with `--next`.

use clap::{Args, Command, FromArgMatches as _};
use rama::error::{BoxError, BoxErrorExt as _};

use super::{RequestArgs, SendCommand};

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
        let tail = std::mem::take(&mut request.next);
        requests.push(request);
        rest = parse(&tail)?;
    }
    Ok(requests)
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
