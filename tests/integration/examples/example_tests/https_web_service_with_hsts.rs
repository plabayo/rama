use super::utils;
use rama::http::headers::StrictTransportSecurity;
use rama::http::headers::{HeaderMapExt, Location};
use rama::http::service::client::HttpClientExt as _;
use rama::http::{BodyExtractExt, StatusCode, client::EasyHttpWebClient};
use rama::net::address::Authority;
use std::time::Duration;

const ADDRESS_HTTP: Authority = Authority::local_ipv4(62043);
const ADDRESS_HTTPS: Authority = Authority::local_ipv4(62044);

#[tokio::test]
#[ignore]
async fn test_https_web_service_with_hsts() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("https_web_service_with_hsts", Some("rustls"));

    // Get Redirected correctly from http to https (including port overwrite)

    let req_uri = format!("http://{ADDRESS_HTTP}");
    let response = runner.get(req_uri).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let hsts_header = response
        .headers()
        .typed_get::<StrictTransportSecurity>()
        .unwrap();
    assert!(!hsts_header.include_subdomains());
    assert_eq!(hsts_header.max_age(), Duration::from_secs(31536000));
    let homepage = response.try_into_string().await.unwrap();
    assert!(homepage.contains("<h1>Hello HSTS</h1>"));

    // Go directly to the HTTPS service

    let req_uri = format!("https://{ADDRESS_HTTPS}");
    let response = runner.get(req_uri).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let hsts_header = response
        .headers()
        .typed_get::<StrictTransportSecurity>()
        .unwrap();
    assert!(!hsts_header.include_subdomains());
    assert_eq!(hsts_header.max_age(), Duration::from_secs(31536000));
    let homepage = response.try_into_string().await.unwrap();
    assert!(homepage.contains("<h1>Hello HSTS</h1>"));

    // test redirect

    let response = EasyHttpWebClient::default()
        .get(format!("http://{ADDRESS_HTTP}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
    assert!(
        response
            .headers()
            .typed_get::<StrictTransportSecurity>()
            .is_none()
    ); // not given on http-connection
    let loc: Location = response.headers().typed_get::<Location>().unwrap();
    assert_eq!(loc.to_str().unwrap(), format!("https://{ADDRESS_HTTPS}/"));
}
