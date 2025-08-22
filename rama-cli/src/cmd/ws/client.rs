use rama::{
    Context, Layer, Service,
    error::{BoxError, ErrorContext, OpaqueError},
    http::{
        Request, Response,
        client::{
            EasyHttpWebClient,
            proxy::layer::{HttpProxyAddressLayer, SetProxyAuthHttpHeaderLayer},
        },
        headers::SecWebSocketProtocol,
        layer::{
            auth::AddAuthorizationLayer,
            decompression::DecompressionLayer,
            follow_redirect::{FollowRedirectLayer, policy::Limited},
            required_header::AddRequiredRequestHeadersLayer,
            timeout::TimeoutLayer,
        },
        ws::handshake::client::{ClientWebSocket, HttpClientWebSocketExt},
    },
    layer::MapResultLayer,
    net::{
        address::ProxyAddress,
        tls::{KeyLogIntent, client::ServerVerifyMode},
        user::{Basic, Bearer, ProxyCredential},
    },
    tls::boring::client::{EmulateTlsProfileLayer, TlsConnectorDataBuilder},
    ua::{
        emulate::{
            UserAgentEmulateHttpConnectModifier, UserAgentEmulateHttpRequestModifier,
            UserAgentEmulateLayer, UserAgentSelectFallback,
        },
        profile::UserAgentDatabase,
    },
};
use std::{str::FromStr, sync::Arc, time::Duration};
use terminal_prompt::Terminal;

use crate::utils::http::HttpVersion;

pub(super) async fn connect(cfg: super::CliCommandWs) -> Result<ClientWebSocket, OpaqueError> {
    let client = create_client(cfg.clone()).await?;

    let mut builder = match cfg.http_version {
        HttpVersion::Auto | HttpVersion::H1 => client.websocket(cfg.uri),
        HttpVersion::H2 => client.websocket_h2(cfg.uri),
    };

    if let Some(mut protocols) = cfg.protocols.map(|p| p.into_iter())
        && let Some(first_protocol) = protocols.next()
    {
        builder.set_protocols(
            SecWebSocketProtocol::new(first_protocol).with_additional_protocols(protocols),
        );
    }

    builder
        .with_per_message_deflate_overwrite_extensions()
        .handshake(Context::default())
        .await
        .context("establish WS(S) connection")
}

async fn create_client<S>(
    cfg: super::CliCommandWs,
) -> Result<impl Service<S, Request, Response = Response, Error = BoxError>, BoxError>
where
    S: Clone + Send + Sync + 'static,
{
    let mut tls_config = if cfg.emulate {
        TlsConnectorDataBuilder::new()
    } else {
        match cfg.http_version {
            // NOTE: flow might be broken when in-mem upgrade http version between h1 and h2,
            // use at your own risk for now
            HttpVersion::Auto => TlsConnectorDataBuilder::new_http_auto(),
            HttpVersion::H1 => TlsConnectorDataBuilder::new_http_1(),
            HttpVersion::H2 => TlsConnectorDataBuilder::new_http_2(),
        }
    };
    tls_config.set_keylog_intent(KeyLogIntent::Environment);

    let mut proxy_tls_config = TlsConnectorDataBuilder::new();

    if cfg.insecure {
        tls_config.set_server_verify_mode(ServerVerifyMode::Disable);
        proxy_tls_config.set_server_verify_mode(ServerVerifyMode::Disable);
    }

    let inner_client = EasyHttpWebClient::builder()
        .with_default_transport_connector()
        .with_tls_proxy_support_using_boringssl_config(proxy_tls_config.into_shared_builder())
        .with_proxy_support()
        .with_tls_support_using_boringssl(Some(tls_config.into_shared_builder()))
        .with_jit_req_inspector(UserAgentEmulateHttpConnectModifier::default())
        .with_svc_req_inspector(UserAgentEmulateHttpRequestModifier::default())
        .build();

    // TODO: need to insert TLS separate from http:
    // - first tls is needed
    // - but http only is to be selected after handshake is done...

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
        (TimeoutLayer::new(if cfg.timeout > 0 {
            Duration::from_secs(cfg.timeout)
        } else {
            Duration::from_secs(180)
        })),
        FollowRedirectLayer::with_policy(Limited::new(if cfg.follow {
            cfg.max_redirects
        } else {
            0
        })),
        DecompressionLayer::new(),
        cfg.auth
            .as_deref()
            .map(|auth| match cfg.auth_type.trim().to_lowercase().as_str() {
                "basic" => {
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
                }
                "bearer" => Ok(AddAuthorizationLayer::new(
                    Bearer::try_from(auth).context("parse bearer str")?,
                )),
                unknown => panic!("unknown auth type: {unknown} (known: basic, bearer)"),
            })
            .transpose()?
            .unwrap_or_else(AddAuthorizationLayer::none),
        AddRequiredRequestHeadersLayer::default(),
        match cfg.proxy {
            None => HttpProxyAddressLayer::try_from_env_default()?,
            Some(proxy) => {
                let mut proxy_address: ProxyAddress =
                    proxy.parse().context("parse proxy address")?;
                if let Some(proxy_user) = cfg.proxy_user {
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
    );

    Ok(client_builder.into_layer(inner_client))
}

fn map_internal_client_error<E, Body>(
    result: Result<Response<Body>, E>,
) -> Result<Response, BoxError>
where
    E: Into<BoxError>,
    Body: rama::http::dep::http_body::Body<Data = rama::bytes::Bytes, Error: Into<BoxError>>
        + Send
        + Sync
        + 'static,
{
    match result {
        Ok(response) => Ok(response.map(rama::http::Body::new)),
        Err(err) => Err(err.into()),
    }
}
