use rama_core::matcher::Matcher;
use rama_net::{
    Protocol,
    address::{AuthorityRef, HostWithPort},
};

use super::ValidateRequest;
use crate::{Body, Request, Response, StatusCode, header::HOST};

/// Validate every request against a trusted intercepted origin and its current
/// policy. Use with [`super::ValidateRequestHeaderLayer::custom`].
///
/// The authority comes from the interception decision, never from the first
/// request on a connection. URI authority and Host must both agree with it when
/// present. A mismatch, missing authority, or policy denial returns 421 before
/// the next service runs. This validator works with H1, H2, and H3 requests.
#[derive(Debug, Clone)]
pub struct BoundAuthority<P> {
    authority: HostWithPort,
    secure: bool,
    policy: P,
}

impl<P> BoundAuthority<P> {
    /// Bind an HTTPS origin, including its destination port.
    #[must_use]
    pub fn https(authority: HostWithPort, policy: P) -> Self {
        Self {
            authority: authority.canonicalize(),
            secure: true,
            policy,
        }
    }

    /// Bind an HTTP origin, including its destination port.
    #[must_use]
    pub fn http(authority: HostWithPort, policy: P) -> Self {
        Self {
            authority: authority.canonicalize(),
            secure: false,
            policy,
        }
    }

    fn matches_authority(&self, authority: AuthorityRef<'_>) -> bool {
        // User information is never part of an HTTP routing authority.
        authority.userinfo().is_none()
            && authority
                .into_owned()
                .address
                .canonicalize()
                .into_host_with_port_or(if self.secure { 443 } else { 80 })
                == self.authority
    }

    fn matches_request<B>(&self, request: &Request<B>) -> bool {
        if let Some(scheme) = request.uri().scheme()
            && scheme
                != if self.secure {
                    &Protocol::HTTPS
                } else {
                    &Protocol::HTTP
                }
        {
            return false;
        }

        let uri = request.uri().authority();
        let mut hosts = request.headers().get_all(HOST).iter();
        let host = hosts.next();
        // Even equal duplicate Host fields are ambiguous routing input.
        if hosts.next().is_some() || (uri.is_none() && host.is_none()) {
            return false;
        }
        if uri.is_some_and(|authority| !self.matches_authority(authority)) {
            return false;
        }
        if let Some(host) = host {
            let Ok(authority) = AuthorityRef::parse_strict(host.as_bytes()) else {
                return false;
            };
            if !self.matches_authority(authority) {
                return false;
            }
        }
        true
    }
}

impl<B, P> ValidateRequest<B> for BoundAuthority<P>
where
    B: Send + 'static,
    P: Matcher<Request<B>>,
{
    type ResponseBody = Body;

    async fn validate(&self, request: Request<B>) -> Result<Request<B>, Response> {
        if self.matches_request(&request) && self.policy.matches(None, &request) {
            return Ok(request);
        }
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::MISDIRECTED_REQUEST;
        *response.version_mut() = request.version();
        Err(response)
    }
}

#[cfg(test)]
mod tests;
