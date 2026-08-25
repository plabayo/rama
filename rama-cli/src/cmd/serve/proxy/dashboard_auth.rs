use rama::{
    Service,
    http::{
        Body, Method, Request, Response, StatusCode, header,
        service::web::response::IntoResponse as _,
    },
};
use std::sync::Arc;

const AUTH_COOKIE: &str = "rama-inspector";

/// Capability boundary for the inspector control plane.
///
/// UI sessions only isolate filters and selections. This independent, random
/// startup capability prevents arbitrary proxy clients and rebound browser
/// origins from reading captures or invoking inspector controls.
#[derive(Debug, Clone)]
pub(super) struct DashboardAuthService<S> {
    inner: S,
    token: Arc<str>,
}

impl<S> DashboardAuthService<S> {
    pub(super) fn new(inner: S, token: Arc<str>) -> Self {
        Self { inner, token }
    }
}

pub(super) fn generate_token() -> Result<Arc<str>, rama::error::BoxError> {
    let mut token = [0_u8; 32];
    rama::tls::boring::core::rand::rand_bytes(&mut token)?;
    Ok(Arc::from(hex::encode(token)))
}

impl<S> Service<Request> for DashboardAuthService<S>
where
    S: Service<Request, Output = Response>,
{
    type Output = Response;
    type Error = S::Error;

    async fn serve(&self, request: Request) -> Result<Self::Output, Self::Error> {
        if has_enrollment_token(&request, self.token.as_bytes()) {
            return Ok(enrollment_response(&self.token));
        }
        if !same_origin_when_present(&request) {
            return Ok(StatusCode::FORBIDDEN.into_response());
        }
        if !request_capability(&request)
            .is_some_and(|token| capability_eq(token, self.token.as_bytes()))
        {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(
                    "Rama Proxy Inspector authorization required. Open the inspector URL printed by rama.",
                ))
                .unwrap_or_else(|_| StatusCode::UNAUTHORIZED.into_response()));
        }
        self.inner.serve(request).await
    }
}

fn has_enrollment_token(request: &Request, expected: &[u8]) -> bool {
    if request.method() != Method::GET
        || request
            .uri()
            .path()
            .is_none_or(|path| path.as_encoded_str() != "/")
    {
        return false;
    }
    request.uri().query().is_some_and(|query| {
        query.as_encoded_str().split('&').any(|pair| {
            pair.split_once('=').is_some_and(|(name, value)| {
                name == "token" && capability_eq(value.as_bytes(), expected)
            })
        })
    })
}

fn capability_eq(candidate: &[u8], expected: &[u8]) -> bool {
    candidate.len() == expected.len() && rama::tls::boring::core::memcmp::eq(candidate, expected)
}

fn request_capability(request: &Request) -> Option<&[u8]> {
    request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.as_bytes().strip_prefix(b"Bearer "))
        .or_else(|| {
            request
                .headers()
                .get(header::COOKIE)?
                .as_bytes()
                .split(|byte| *byte == b';')
                .find_map(|cookie| {
                    let cookie = cookie.trim_ascii();
                    let separator = cookie.iter().position(|byte| *byte == b'=')?;
                    let (name, value) = cookie.split_at(separator);
                    let value = value.get(1..)?;
                    (name == AUTH_COOKIE.as_bytes()).then_some(value)
                })
        })
}

fn same_origin_when_present(request: &Request) -> bool {
    let Some(origin) = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    let Ok(origin) = origin.parse::<rama::net::uri::Uri>() else {
        return false;
    };
    let Some(origin_authority) = origin.authority() else {
        return false;
    };
    request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|host| host.eq_ignore_ascii_case(&origin_authority.to_string()))
}

fn enrollment_response(token: &str) -> Response {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/")
        .header(
            header::SET_COOKIE,
            format!("{AUTH_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict"),
        )
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from("Inspector authorization accepted"))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::{http::Body, service::service_fn};
    use std::convert::Infallible;

    fn service()
    -> DashboardAuthService<impl Service<Request, Output = Response, Error = Infallible>> {
        DashboardAuthService::new(
            service_fn(|_| async { Ok::<_, Infallible>(Response::new(Body::from("inspector"))) }),
            Arc::from("0123456789abcdef"),
        )
    }

    #[tokio::test]
    async fn enrollment_sets_host_only_cookie_and_cookie_authorizes() {
        let response = service()
            .serve(
                Request::builder()
                    .uri("/?token=0123456789abcdef")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
        assert_eq!(
            cookie,
            "rama-inspector=0123456789abcdef; Path=/; HttpOnly; SameSite=Strict"
        );

        let response = service()
            .serve(
                Request::builder()
                    .uri("/api/capture/1.json")
                    .header(header::COOKIE, "rama-inspector=0123456789abcdef")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rejects_missing_capability_and_cross_origin_requests() {
        let response = service().serve(Request::new(Body::empty())).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = service()
            .serve(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/captures/clear")
                    .header(header::HOST, "127.0.0.1:8080")
                    .header(header::ORIGIN, "http://evil.test:8080")
                    .header(header::COOKIE, "rama-inspector=0123456789abcdef")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn token_query_is_accepted_only_for_root_get() {
        for request in [
            Request::builder()
                .uri("/?wrong=0123456789abcdef")
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .uri("/?token=wrong")
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .method(Method::POST)
                .uri("/?token=0123456789abcdef")
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .uri("/api/capture/1.json?token=0123456789abcdef")
                .body(Body::empty())
                .unwrap(),
        ] {
            let response = service().serve(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }
}
