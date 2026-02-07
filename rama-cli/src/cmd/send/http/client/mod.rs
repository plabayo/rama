use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    http::{
        Request, Response, StreamingBody,
        client::{
            EasyHttpWebClient, ProxyConnectorLayer,
            proxy::layer::{
                HttpProxyAddressLayer, HttpProxyConnectorLayer, SetProxyAuthHttpHeaderLayer,
            },
        },
        layer::{
            auth::AddAuthorizationLayer,
            follow_redirect::{FollowRedirectLayer, policy::Limited},
            required_header::AddRequiredRequestHeadersLayer,
        },
    },
    layer::{HijackLayer, MapResultLayer, TimeoutLayer, layer_fn},
    net::{
        tls::client::ServerVerifyMode,
        user::{Basic, ProxyCredential},
    },
    proxy::socks5::Socks5ProxyConnectorLayer,
    rt::Executor,
    tls::boring::{
        client::{EmulateTlsProfileLayer, TlsConnectorDataBuilder},
        core::ssl::SslVersion,
    },
    ua::{
        layer::emulate::{
            UserAgentEmulateHttpConnectModifierLayer, UserAgentEmulateHttpRequestModifierLayer,
            UserAgentEmulateLayer, UserAgentSelectFallback,
        },
        profile::UserAgentDatabase,
    },
};

use std::{str::FromStr as _, sync::Arc, time::Duration};
use terminal_prompt::Terminal;

use crate::cmd::send::layer::resolve::OptDnsOverwriteLayer;

use super::{SendCommand, arg::HttpHeader};

mod logger_body_res;
mod logger_headers_req;
mod logger_headers_res;
mod logger_l4;
mod logger_tls;

mod curl_writer;
mod writer;

pub(super) async fn new(
    cfg: &SendCommand,
) -> Result<impl Service<Request, Output = Response, Error = BoxError>, BoxError> {
    let writer = writer::try_new(cfg).await?;

    let inner_client = new_inner_client(cfg)?;

    let show_headers = cfg.show_headers;
    let client_builder = (
        MapResultLayer::new(map_internal_client_error),
        layer_fn({
            let writer = writer.clone();
            move |inner| logger_body_res::ResponseBodyLogger {
                inner,
                writer: writer.clone(),
            }
        }),
        cfg.emulate
            .then(|| {
                Ok::<_, BoxError>((
                    UserAgentEmulateLayer::new(Arc::new(UserAgentDatabase::try_embedded()?))
                        .with_try_auto_detect_user_agent(true)
                        .with_select_fallback(UserAgentSelectFallback::Random),
                    EmulateTlsProfileLayer::new(),
                ))
            })
            .transpose()?,
        FollowRedirectLayer::with_policy(Limited::new(if cfg.location && cfg.max_redirs > 0 {
            cfg.max_redirs as usize
        } else {
            0
        })),
        OptDnsOverwriteLayer::new(cfg.resolve.clone()),
        cfg.user
            .as_deref()
            .map(|auth| {
                let mut basic = Basic::from_str(auth).context("parse basic str")?;
                if auth.ends_with(':') && basic.password().is_none() {
                    let mut terminal =
                        Terminal::open().context("open terminal for password prompting")?;
                    let password = terminal
                        .prompt_sensitive("password: ")
                        .context("prompt password from terminal")?
                        .parse()
                        .context("parse password as non-empty-str")?;
                    basic.set_password(password);
                }
                Ok::<_, BoxError>(AddAuthorizationLayer::new(basic).with_sensitive(true))
            })
            .transpose()?
            .unwrap_or_else(AddAuthorizationLayer::none),
        AddRequiredRequestHeadersLayer::default(),
        match cfg.proxy.clone() {
            None => HttpProxyAddressLayer::try_from_env_default()?,
            Some(mut proxy_address) => {
                if let Some(credentials) = cfg.proxy_user.clone() {
                    proxy_address.credential = Some(ProxyCredential::Basic(credentials));
                }
                HttpProxyAddressLayer::maybe(Some(proxy_address))
            }
        },
        SetProxyAuthHttpHeaderLayer::default(),
        HijackLayer::new(cfg.curl, curl_writer::CurlWriter { writer }),
        layer_fn(move |svc| logger_headers_res::ResponseHeaderLogger {
            inner: svc,
            show_headers,
        }),
    );

    Ok(client_builder.into_layer(inner_client))
}

fn new_inner_client(
    cfg: &SendCommand,
) -> Result<impl Service<Request, Output = Response, Error = BoxError> + Clone, BoxError> {
    let mut tls_config = if cfg.emulate {
        TlsConnectorDataBuilder::new()
    } else {
        TlsConnectorDataBuilder::new_http_auto()
    };

    if cfg.verbose {
        tls_config.set_store_server_certificate_chain(true);
    }

    if let Some(min_ssl_version) = match (cfg.tls_v10, cfg.tls_v11, cfg.tls_v12, cfg.tls_v13) {
        (true, false, false, false) => Some(SslVersion::TLS1),
        (false, true, false, false) => Some(SslVersion::TLS1_1),
        (false, false, true, false) => Some(SslVersion::TLS1_2),
        (false, false, false, true) => Some(SslVersion::TLS1_3),
        (false, false, false, false) => None,
        _ => Err(BoxError::from(
            "--tlsv1.0, --tlsv1.1, --tlsv1.2, --tlsv1.3 are mutually exclusive",
        ))?,
    } {
        tls_config.set_min_ssl_version(min_ssl_version);
    }

    if let Some(max_ssl_version) = cfg.tls_max.as_ref() {
        let max_ssl_version = match max_ssl_version {
            crate::cmd::send::arg::TlsVersion::V10 => SslVersion::TLS1,
            crate::cmd::send::arg::TlsVersion::V11 => SslVersion::TLS1_1,
            crate::cmd::send::arg::TlsVersion::V12 => SslVersion::TLS1_2,
            crate::cmd::send::arg::TlsVersion::V13 => SslVersion::TLS1_3,
        };

        tls_config.set_max_ssl_version(max_ssl_version);
    }

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

    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_custom_connector(layer_fn(logger_l4::TransportConnInfoLogger))
        .with_tls_proxy_support_using_boringssl_config(proxy_tls_config.into_shared_builder())
        .with_custom_proxy_connector(proxy_connector)
        .with_tls_support_using_boringssl(Some(tls_config.into_shared_builder()))
        .with_custom_connector(layer_fn(logger_tls::TlsInfoLogger))
        .with_custom_connector(UserAgentEmulateHttpConnectModifierLayer::default())
        .with_default_http_connector(Executor::default())
        .with_custom_connector(
            if let Some(timeout) = cfg.connect_timeout
                && timeout > 0.
            {
                TimeoutLayer::new(Duration::from_secs_f64(timeout))
            } else {
                TimeoutLayer::never()
            },
        )
        .build_client()
        .with_jit_layer((
            UserAgentEmulateHttpRequestModifierLayer::default(),
            logger_headers_req::RequestHeaderLoggerLayer::default(),
        ));

    Ok(client)
}

#[derive(Debug, Clone, Copy)]
pub(super) struct VerboseLogs;

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
