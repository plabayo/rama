use super::{
    ConnectIpRole, ConnectIpSession, ConnectIpSessionConfig, validate_connect_ip_response,
};
use rama_core::{
    Service,
    error::{BoxError, ErrorContext as _},
};
use rama_http::{Request, Response, io::upgrade::handle_upgrade};

/// Open a CONNECT-IP session using an existing Rama HTTP client.
///
/// Build `request` with [`super::ConnectIpTemplate`], then apply authentication
/// headers/layers as needed. The HTTP client must honor its HTTPS URI and requested
/// version. H1 sends no optimistic tunnel bytes. Configuration is validated before
/// network I/O and the response before packet I/O is exposed.
pub async fn connect_ip<S>(
    client: &S,
    request: Request,
    mut config: ConnectIpSessionConfig,
) -> Result<ConnectIpSession, BoxError>
where
    S: Service<Request, Output = Response, Error: Into<BoxError>>,
{
    config.http_config()?;
    config.policy.role = ConnectIpRole::Client;
    let version = request.version();
    if request.uri().scheme_str() != Some("https") {
        return Err(super::ConnectIpRequestError::Template.into());
    }
    let protocol = rama_http::datagram::handshake::validate_capsule_request(
        &request,
        rama_http::datagram::ViolationPolicy::Reject,
    )?;
    if protocol != rama_http::proto::ext::Protocol::CONNECT_IP {
        return Err(super::ConnectIpRequestError::Handshake.into());
    }
    let deadline = tokio::time::Instant::now() + config.write_timeout;
    let response = tokio::time::timeout_at(deadline, client.serve(request))
        .await
        .map_err(|_error| super::ConnectIpError::Timeout)?
        .map_err(Into::into)
        .context("CONNECT-IP request")?;
    validate_connect_ip_response(version, &response)?;
    let upgraded = tokio::time::timeout_at(deadline, handle_upgrade(&response))
        .await
        .map_err(|_error| super::ConnectIpError::Timeout)?
        .context("CONNECT-IP upgrade")?;
    Ok(ConnectIpSession::new(upgraded, config)?)
}
