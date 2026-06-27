use rama::{
    Layer, Service,
    error::{BoxError, BoxErrorExt, ErrorContext, ErrorExt, extra::OpaqueError},
    extensions::Extension,
    http::{
        Body, Request, Response, StreamingBody,
        client::{
            EasyHttpWebClient, ProxyConnectorLayer,
            proxy::layer::{
                HttpProxyAddressLayer, HttpProxyConnectorLayer, SetProxyAuthHttpHeaderLayer,
            },
        },
        layer::{
            auth::AddAuthorizationLayer,
            follow_redirect::{
                FollowRedirectLayer,
                policy::{FilterCredentials, Limited, PolicyExt},
            },
            required_header::AddRequiredRequestHeadersLayer,
        },
    },
    layer::{HijackLayer, MapErrLayer, MapResultLayer, TimeoutLayer, layer_fn},
    net::user::{Basic, ProxyCredential},
    proxy::socks5::Socks5ProxyConnectorLayer,
    rt::Executor,
    tls::boring::client::{BoringClientConfigExt, EmulateTlsProfileLayer},
    tls::{
        ProtocolVersion,
        client::{ServerVerifyMode, TlsClientConfig},
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
    feed_tui: bool,
) -> Result<impl Service<Request, Output = Response, Error = OpaqueError>, BoxError> {
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
                feed_tui,
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
        OptDnsOverwriteLayer::new(cfg.resolve.clone()),
        match cfg.proxy.clone() {
            None => HttpProxyAddressLayer::try_from_env_default()?,
            Some(mut proxy_address) => {
                if let Some(credentials) = cfg.proxy_user.clone() {
                    proxy_address.credential = Some(ProxyCredential::Basic(credentials));
                }
                HttpProxyAddressLayer::maybe(Some(proxy_address))
            }
        },
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
        FollowRedirectLayer::with_policy(
            Limited::new(redirect_limit(cfg)).and::<_, Body, OpaqueError>(
                FilterCredentials::new()
                    .with_block_cross_origin(!cfg.location_trusted)
                    .with_remove_blocklisted(!cfg.location_trusted),
            ),
        ),
        // Inner to FollowRedirect: proxy credentials are per-hop and authenticate
        // to the (same) proxy, so they must be re-applied on every redirect rather
        // than stripped by FilterCredentials' cross-origin rule like origin creds.
        SetProxyAuthHttpHeaderLayer::default(),
        AddRequiredRequestHeadersLayer::default(),
        HijackLayer::new(cfg.curl, curl_writer::CurlWriter { writer }),
        MapErrLayer::into_box_error(),
        layer_fn(move |svc| logger_headers_res::ResponseHeaderLogger {
            inner: svc,
            show_headers,
        }),
    );

    Ok(client_builder.into_layer(inner_client))
}

fn redirect_limit(cfg: &SendCommand) -> usize {
    compute_redirect_limit(cfg.location, cfg.location_trusted, cfg.max_redirs)
}

fn compute_redirect_limit(location: bool, location_trusted: bool, max_redirs: isize) -> usize {
    // Redirects only follow when --location or --location-trusted is set.
    if !(location || location_trusted) {
        return 0;
    }

    // curl semantics: --max-redirs -1 means unlimited.
    if max_redirs < 0 {
        usize::MAX
    } else {
        max_redirs as usize
    }
}

fn new_inner_client(
    cfg: &SendCommand,
) -> Result<impl Service<Request, Output = Response, Error = OpaqueError> + Clone, BoxError> {
    let mut tls_config = if cfg.emulate {
        TlsClientConfig::new()
    } else {
        TlsClientConfig::new().with_alpn_http_auto()
    };

    if cfg.verbose {
        tls_config.set_store_server_cert_chain(true);
    }

    if let Some(min_ssl_version) = match (cfg.tls_v10, cfg.tls_v11, cfg.tls_v12, cfg.tls_v13) {
        (true, false, false, false) => Some(ProtocolVersion::TLSv1_0),
        (false, true, false, false) => Some(ProtocolVersion::TLSv1_1),
        (false, false, true, false) => Some(ProtocolVersion::TLSv1_2),
        (false, false, false, true) => Some(ProtocolVersion::TLSv1_3),
        (false, false, false, false) => None,
        _ => Err(BoxError::from_static_str(
            "--tlsv1.0, --tlsv1.1, --tlsv1.2, --tlsv1.3 are mutually exclusive",
        ))?,
    } {
        tls_config.set_min_version(min_ssl_version);
    }

    if let Some(max_ssl_version) = cfg.tls_max.as_ref() {
        let max_ssl_version = match max_ssl_version {
            crate::cmd::send::arg::TlsVersion::V10 => ProtocolVersion::TLSv1_0,
            crate::cmd::send::arg::TlsVersion::V11 => ProtocolVersion::TLSv1_1,
            crate::cmd::send::arg::TlsVersion::V12 => ProtocolVersion::TLSv1_2,
            crate::cmd::send::arg::TlsVersion::V13 => ProtocolVersion::TLSv1_3,
        };
        tls_config.set_max_version(max_ssl_version);
    }

    let mut proxy_tls_config = TlsClientConfig::new();

    if cfg.insecure {
        tls_config.set_server_verify(ServerVerifyMode::Disable);
    }
    if cfg.proxy_insecure {
        proxy_tls_config.set_server_verify(ServerVerifyMode::Disable);
    }

    let mut http_proxy_connector = HttpProxyConnectorLayer::required();
    for HttpHeader { name, value } in &cfg.proxy_header {
        http_proxy_connector.set_custom_header(name.clone(), value.clone());
    }

    let proxy_connector =
        ProxyConnectorLayer::optional(Socks5ProxyConnectorLayer::required(), http_proxy_connector);

    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_custom_connector(layer_fn(logger_l4::TransportConnInfoLogger))
        .with_tls_proxy_support_using_boringssl_config(proxy_tls_config)
        .with_custom_proxy_connector(proxy_connector)
        .with_tls_support_using_boringssl(tls_config)
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

#[derive(Debug, Clone, Copy, Extension)]
pub(super) struct VerboseLogs;

fn map_internal_client_error<E, Body>(
    result: Result<Response<Body>, E>,
) -> Result<Response, OpaqueError>
where
    E: Into<BoxError>,
    Body: StreamingBody<Data = rama::bytes::Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    match result {
        Ok(response) => Ok(response.map(rama::http::Body::new)),
        Err(err) => Err(err.into_opaque_error()),
    }
}

#[cfg(test)]
mod tests {
    use super::compute_redirect_limit;

    #[test]
    fn redirect_limit_disabled_without_location() {
        // No redirects unless --location or --location-trusted is set.
        assert_eq!(compute_redirect_limit(false, false, 50), 0);
        assert_eq!(compute_redirect_limit(false, false, -1), 0);
    }

    #[test]
    fn redirect_limit_location_trusted_alone_enables_redirects() {
        assert_eq!(compute_redirect_limit(false, true, 50), 50);
    }

    #[test]
    fn redirect_limit_respects_max_redirs() {
        assert_eq!(compute_redirect_limit(true, false, 0), 0);
        assert_eq!(compute_redirect_limit(true, false, 7), 7);
    }

    #[test]
    fn redirect_limit_negative_is_unlimited() {
        assert_eq!(compute_redirect_limit(true, false, -1), usize::MAX);
        assert_eq!(compute_redirect_limit(false, true, -1), usize::MAX);
    }
}
