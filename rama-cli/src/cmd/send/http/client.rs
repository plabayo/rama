use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext, OpaqueError},
    http::{
        Request, Response, StatusCode, StreamingBody,
        body::util::BodyExt,
        client::{
            EasyHttpWebClient, ProxyConnectorLayer,
            proxy::layer::{
                HttpProxyAddressLayer, HttpProxyConnectorLayer, SetProxyAuthHttpHeaderLayer,
            },
        },
        convert::curl,
        layer::{
            auth::AddAuthorizationLayer,
            decompression::DecompressionLayer,
            follow_redirect::{FollowRedirectLayer, policy::Limited},
            required_header::AddRequiredRequestHeadersLayer,
        },
        service::web::response::IntoResponse,
    },
    layer::{HijackLayer, MapResultLayer, TimeoutLayer},
    net::{
        address::ProxyAddress,
        tls::{KeyLogIntent, client::ServerVerifyMode},
        user::{Basic, ProxyCredential},
    },
    proxy::socks5::Socks5ProxyConnectorLayer,
    service::service_fn,
    tls::boring::client::{EmulateTlsProfileLayer, TlsConnectorDataBuilder},
    ua::{
        layer::emulate::{
            UserAgentEmulateHttpConnectModifierLayer, UserAgentEmulateHttpRequestModifier,
            UserAgentEmulateLayer, UserAgentSelectFallback,
        },
        profile::UserAgentDatabase,
    },
};

use std::{str::FromStr as _, sync::Arc, time::Duration};
use terminal_prompt::Terminal;

use super::{SendCommand, arg::HttpHeader};

pub(super) async fn new(
    cfg: &SendCommand,
) -> Result<impl Service<Request, Response = Response, Error = BoxError>, BoxError> {
    // todo: pass writer

    let mut tls_config = if cfg.emulate {
        TlsConnectorDataBuilder::new()
    } else {
        TlsConnectorDataBuilder::new_http_auto()
    };
    tls_config.set_keylog_intent(KeyLogIntent::Environment);

    let mut proxy_tls_config = TlsConnectorDataBuilder::new();

    if cfg.insecure {
        tls_config.set_server_verify_mode(ServerVerifyMode::Disable);
    }
    if cfg.proxy_insecure {
        proxy_tls_config.set_server_verify_mode(ServerVerifyMode::Disable);
    }

    let mut http_proxy_connector = HttpProxyConnectorLayer::required();
    for HttpHeader { name, value } in &cfg.proxy_header {
        http_proxy_connector.set_custom_header(name.clone(), value.clone());
    }

    let proxy_connector =
        ProxyConnectorLayer::optional(Socks5ProxyConnectorLayer::required(), http_proxy_connector);

    let inner_client = EasyHttpWebClient::builder()
        .with_default_transport_connector()
        .with_tls_proxy_support_using_boringssl_config(proxy_tls_config.into_shared_builder())
        .with_custom_proxy_connector(proxy_connector)
        .with_tls_support_using_boringssl(Some(tls_config.into_shared_builder()))
        .with_custom_connector(UserAgentEmulateHttpConnectModifierLayer::default())
        .with_default_http_connector()
        .with_svc_req_inspector((
            UserAgentEmulateHttpRequestModifier::default(),
            // request_writer,
        ))
        .with_custom_connector(
            if let Some(timeout) = cfg.connect_timeout
                && timeout > 0.
            {
                TimeoutLayer::new(Duration::from_secs_f64(timeout))
            } else {
                TimeoutLayer::never()
            },
        )
        .build();

    let client_builder = (
        MapResultLayer::new(map_internal_client_error),
        cfg.emulate.then(|| {
            (
                UserAgentEmulateLayer::new(Arc::new(UserAgentDatabase::embedded()))
                    .try_auto_detect_user_agent(true)
                    .select_fallback(UserAgentSelectFallback::Random),
                EmulateTlsProfileLayer::new(),
            )
        }),
        FollowRedirectLayer::with_policy(Limited::new(if cfg.location && cfg.max_redirs > 0 {
            cfg.max_redirs as usize
        } else {
            0
        })),
        DecompressionLayer::new(),
        cfg.user
            .as_deref()
            .map(|auth| {
                let mut basic = Basic::from_str(auth).context("parse basic str")?;
                if auth.ends_with(':') && basic.password().is_empty() {
                    let mut terminal =
                        Terminal::open().context("open terminal for password prompting")?;
                    let password = terminal
                        .prompt_sensitive("password: ")
                        .context("prompt password from terminal")?;
                    basic.set_password(password);
                }
                Ok::<_, OpaqueError>(AddAuthorizationLayer::new(basic).as_sensitive(true))
            })
            .transpose()?
            .unwrap_or_else(AddAuthorizationLayer::none),
        AddRequiredRequestHeadersLayer::default(),
        match cfg.proxy.as_ref() {
            None => HttpProxyAddressLayer::try_from_env_default()?,
            Some(proxy) => {
                let mut proxy_address: ProxyAddress =
                    proxy.parse().context("parse proxy address")?;
                if let Some(proxy_user) = cfg.proxy_user.as_ref() {
                    let credential = ProxyCredential::Basic(
                        proxy_user
                            .parse()
                            .context("parse basic proxy credentials")?,
                    );
                    proxy_address.credential = Some(credential);
                }
                HttpProxyAddressLayer::maybe(Some(proxy_address))
            }
        },
        SetProxyAuthHttpHeaderLayer::default(),
        HijackLayer::new(
            cfg.curl,
            service_fn(async |req: Request| {
                let Ok(req) = UserAgentEmulateHttpRequestModifier::new().serve(req).await else {
                    return Ok(
                        (StatusCode::INTERNAL_SERVER_ERROR, "failed to emulate UA").into_response()
                    );
                };

                let (parts, body) = req.into_parts();
                let payload = body.collect().await.unwrap().to_bytes();
                let curl_cmd = curl::cmd_string_for_request_parts_and_payload(&parts, &payload);

                // TODO: use same writer as other traffic...
                #[allow(clippy::print_stdout)]
                {
                    println!("{curl_cmd}");
                }

                Ok::<_, OpaqueError>(StatusCode::OK.into_response())
            }),
        ),
    );

    Ok(client_builder.into_layer(inner_client))
}

fn map_internal_client_error<E, Body>(
    result: Result<Response<Body>, E>,
) -> Result<Response, BoxError>
where
    E: Into<BoxError>,
    Body: StreamingBody<Data = rama::bytes::Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    match result {
        Ok(response) => Ok(response.map(rama::http::Body::new)),
        Err(err) => Err(err.into()),
    }
}
