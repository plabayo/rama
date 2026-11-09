use std::convert::Infallible;

use rama::{
    http::headers::{HeaderMapExt as _, SecFetchMode},
    service::service_fn,
};

use super::super::{StorageAuthLayer, StorageAuthorized};
use super::*;

const SECRET: &str = "storage-secret";
const PAGE: &str = "https://h2.fp.example.org";

fn grant(authorized: bool) -> SiteGrant {
    SiteGrant {
        authorized,
        origin: PAGE.into(),
    }
}

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000)
}

fn domain(host: &'static str) -> Domain {
    Domain::from_static(host)
}

fn sites() -> Sites {
    Sites::try_new(
        Some(domain("h2.fp.ss.example.org")),
        Some(domain("h2.fp.xss.example.com")),
        Some(SECRET),
    )
    .unwrap()
    .unwrap()
}

#[test]
fn no_probe_host_configures_no_sites() {
    assert!(Sites::try_new(None, None, Some(SECRET)).unwrap().is_none());
}

#[test]
fn tokens_carry_the_page_authorization_until_they_expire() {
    let tokens = SiteTokens::new(Some(SECRET)).unwrap();
    for authorized in [true, false] {
        let token = tokens.mint(authorized, PAGE, now()).unwrap();
        assert_eq!(
            tokens.verify(&token, now() + Duration::from_mins(14)),
            Some(grant(authorized))
        );
        assert_eq!(tokens.verify(&token, now() + TOKEN_LIFETIME), None);
    }
}

#[test]
fn every_instance_sharing_the_secret_accepts_a_token() {
    let token = SiteTokens::new(Some(SECRET))
        .unwrap()
        .mint(true, PAGE, now())
        .unwrap();
    assert_eq!(
        SiteTokens::new(Some(SECRET)).unwrap().verify(&token, now()),
        Some(grant(true))
    );
    assert_eq!(
        SiteTokens::new(Some("other-secret"))
            .unwrap()
            .verify(&token, now()),
        None
    );
}

#[test]
fn tokens_without_a_storage_secret_never_authorize() {
    let tokens = SiteTokens::new(None).unwrap();
    let token = tokens.mint(true, PAGE, now()).unwrap();
    assert_eq!(tokens.verify(&token, now()), Some(grant(false)));
}

#[test]
fn altered_or_malformed_tokens_are_rejected() {
    let tokens = SiteTokens::new(Some(SECRET)).unwrap();
    let original = URL_SAFE_NO_PAD
        .decode(tokens.mint(false, PAGE, now()).unwrap().as_bytes())
        .unwrap();
    let altered = |index: usize, value: u8| {
        let mut token = original.clone();
        token[index] = value;
        URL_SAFE_NO_PAD.encode(token)
    };
    // Authorization, a later expiry, and another page origin under the original signature.
    for (index, value) in [(8, 1), (7, original[7] ^ 1), (HEADER_BYTES + 8, b'X')] {
        assert_eq!(
            tokens.verify(&altered(index, value), now()),
            None,
            "{index}"
        );
    }
    assert_eq!(tokens.mint(true, "", now()), None);
    assert_eq!(
        tokens.mint(true, &"a".repeat(MAX_ORIGIN_BYTES + 1), now()),
        None
    );
    for malformed in ["", "not base64!", "AAAA"] {
        assert_eq!(tokens.verify(malformed, now()), None, "{malformed}");
    }
}

#[test]
fn the_token_is_read_from_its_query_parameter() {
    let tokens = SiteTokens::new(Some(SECRET)).unwrap();
    let token = tokens.mint(true, PAGE, now()).unwrap();
    let request = |query: String| {
        Request::builder()
            .uri(format!(
                "https://h2.fp.xss.example.com/api/fetch/number/1?{query}"
            ))
            .body(())
            .unwrap()
    };
    assert_eq!(
        tokens.grant(
            &request(format!("a=1&{SITE_TOKEN_PARAM}={token}&b=2")),
            now()
        ),
        Some(grant(true))
    );
    assert_eq!(
        tokens.grant(&request(format!("other={token}")), now()),
        None
    );
}

#[test]
fn probes_target_every_site_with_their_own_token() {
    let sites = sites();
    let probes = sites.probes(true, PAGE, now()).unwrap();
    assert_eq!(probes.len(), 2);
    assert_eq!(probes[0].site, SiteKind::SameSite);
    assert_eq!(probes[0].origin.as_ref(), "https://h2.fp.ss.example.org");
    assert_eq!(probes[1].site, SiteKind::CrossSite);
    assert_eq!(probes[1].origin.as_ref(), "https://h2.fp.xss.example.com");
    for probe in &probes {
        assert_eq!(
            sites.tokens().verify(&probe.token, now()),
            Some(grant(true))
        );
    }
    assert!(sites.is_site_host(&domain("h2.fp.xss.example.com")));
    assert!(!sites.is_site_host(&domain("h2.fp.example.org")));
}

#[test]
fn the_page_policy_admits_the_probe_hosts() {
    let csp = sites().extend_csp(ContentSecurityPolicy::strict_self());
    let directives = csp
        .directives()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    for name in [
        "script-src",
        "style-src",
        "img-src",
        "connect-src",
        "frame-src",
        "form-action",
    ] {
        let directive = directives
            .iter()
            .find(|directive| directive.starts_with(name))
            .unwrap_or_else(|| panic!("{name} in {directives:?}"));
        for host in [
            "https://h2.fp.ss.example.org",
            "https://h2.fp.xss.example.com",
        ] {
            assert!(directive.contains(host), "{directive}");
        }
    }
}

fn cors_service() -> impl Service<Request<()>, Output = Response, Error = Infallible> {
    SiteCorsLayer.into_layer(service_fn(|_request: Request<()>| async {
        Ok::<_, Infallible>(Response::new(Body::from("probe")))
    }))
}

fn granted(request: Request<()>) -> Request<()> {
    request.extensions().insert(grant(true));
    request
}

#[tokio::test]
async fn granted_preflights_are_answered_for_the_requesting_origin() {
    let request = granted(
        Request::builder()
            .method(Method::OPTIONS)
            .uri("/api/fetch/number/1")
            .header(ORIGIN, PAGE)
            .header(ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(
                ACCESS_CONTROL_REQUEST_HEADERS,
                "x-rama-custom-header-marker",
            )
            .body(())
            .unwrap(),
    );
    let response = cors_service().serve(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let headers = response.headers();
    assert_eq!(headers[ACCESS_CONTROL_ALLOW_ORIGIN], PAGE);
    assert_eq!(headers[ACCESS_CONTROL_ALLOW_METHODS], "POST");
    assert_eq!(
        headers[ACCESS_CONTROL_ALLOW_HEADERS],
        "x-rama-custom-header-marker"
    );
    assert_eq!(headers[&TIMING_ALLOW_ORIGIN], PAGE);
}

#[tokio::test]
async fn granted_responses_are_readable_and_timed_by_the_page() {
    let request = granted(
        Request::builder()
            .method(Method::POST)
            .uri("/api/fetch/number/1")
            .header(ORIGIN, PAGE)
            .body(())
            .unwrap(),
    );
    let response = cors_service().serve(request).await.unwrap();
    assert_eq!(response.headers()[ACCESS_CONTROL_ALLOW_ORIGIN], PAGE);
    assert_eq!(response.headers()[VARY], "Origin");

    let image = granted(
        Request::builder()
            .uri("/assets/banner.jpeg")
            .body(())
            .unwrap(),
    );
    let response = cors_service().serve(image).await.unwrap();
    assert_eq!(response.headers()[&TIMING_ALLOW_ORIGIN], PAGE);
    assert!(!response.headers().contains_key(ACCESS_CONTROL_ALLOW_ORIGIN));
}

#[tokio::test]
async fn a_token_used_from_another_origin_shares_nothing() {
    for method in [Method::OPTIONS, Method::POST] {
        let request = granted(
            Request::builder()
                .method(method.clone())
                .uri("/api/fetch/number/1")
                .header(ORIGIN, "https://attacker.example")
                .header(ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .body(())
                .unwrap(),
        );
        let response = cors_service().serve(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{method}");
        for name in [ACCESS_CONTROL_ALLOW_ORIGIN, TIMING_ALLOW_ORIGIN.clone()] {
            assert!(!response.headers().contains_key(&name), "{method} {name}");
        }
    }
}

#[tokio::test]
async fn requests_without_a_grant_are_not_shared_across_origins() {
    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri("/api/fetch/number/1")
        .header(ORIGIN, "https://attacker.example")
        .header(ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .body(())
        .unwrap();
    let response = cors_service().serve(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    for name in [ACCESS_CONTROL_ALLOW_ORIGIN, TIMING_ALLOW_ORIGIN.clone()] {
        assert!(!response.headers().contains_key(&name), "{name}");
    }
}

#[tokio::test]
async fn storage_auth_accepts_the_site_token_in_place_of_the_cookie() {
    let sites = sites();
    let service = StorageAuthLayer {
        storage_auth: Some(SECRET.to_owned()),
        site_tokens: Some(sites.tokens().clone()),
    }
    .into_layer(service_fn(|request: Request<()>| async {
        Ok::<_, Infallible>(request)
    }));
    for authorized in [true, false] {
        let token = sites
            .tokens()
            .mint(authorized, PAGE, SystemTime::now())
            .unwrap();
        let mut request = Request::builder()
            .uri(format!("/landing?{SITE_TOKEN_PARAM}={token}"))
            .body(())
            .unwrap();
        request.headers_mut().typed_insert(SecFetchMode::Navigate);
        let output = service.serve(request).await.unwrap();
        assert_eq!(
            output.extensions().contains::<StorageAuthorized>(),
            authorized
        );
        assert_eq!(
            output.extensions().get_ref::<SiteGrant>().cloned(),
            Some(grant(authorized))
        );
    }
    let output = service
        .serve(
            Request::builder()
                .uri(format!("/landing?{SITE_TOKEN_PARAM}=forged"))
                .body(())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(!output.extensions().contains::<StorageAuthorized>());
    assert!(!output.extensions().contains::<SiteGrant>());
}
