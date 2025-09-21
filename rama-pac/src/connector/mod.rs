use crate::pac_parser::ProxyDirective;
use crate::{pac_fetcher::fetch_pac, pac_parser::parse_pac_file};
use rama_core::{Context, Service, error::BoxError};
use rama_http::{Uri, service::client::HttpClientExt};
use rama_http_types::Request;

pub struct PACConnector<S, W> {
    pub service: S,
    pub web_client: W,
    pub pac_uri: Uri,
}

impl<S, W> PACConnector<S, W>
where
    W: HttpClientExt + Send + Sync + 'static,
{
    pub fn new(service: S, web_client: W, pac_uri: Uri) -> Self {
        Self {
            service,
            web_client,
            pac_uri,
        }
    }
}

impl<S, W, Body> Service<Request<Body>> for PACConnector<S, W>
where
    S: Service<Request<Body>, Error: Into<BoxError> + Send + Sync + 'static>,
    W: HttpClientExt + Send + Sync + 'static,
    Body: Clone + Send + Sync + 'static,
    W::ExecuteError: std::error::Error + Send + Sync + 'static,
    W::ExecuteResponse: Into<String>,
{
    type Response = S::Response;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let pac_file = fetch_pac(&self.web_client, &self.pac_uri)
            .await
            .unwrap();

        let request_url = req.uri();
        let proxy_options = parse_pac_file(request_url, &pac_file).unwrap();

        let req_template = req;
        let mut last_err: Option<BoxError> = None;

        for opt in proxy_options {
            let mut attempt = req_template.clone();
            match opt {
                ProxyDirective::Direct => {}
                ProxyDirective::Proxy(hp) | ProxyDirective::Http(hp) => {
                    let proxy_uri: Uri = format!("http://{hp}")
                        .parse()
                        .map_err(|e| format!("bad PROXY uri {hp}: {e}"))?;
                    *attempt.uri_mut() = proxy_uri;
                }
                ProxyDirective::Https(hp) => {
                    let proxy_uri: Uri = format!("https://{hp}")
                        .parse()
                        .map_err(|e| format!("bad HTTPS proxy uri {hp}: {e}"))?;
                    *attempt.uri_mut() = proxy_uri;
                }
                ProxyDirective::Socks(hp) => {
                    let proxy_uri: Uri = format!("socks://{hp}")
                        .parse()
                        .map_err(|e| format!("bad socks uri {hp}: {e}"))?;
                    *attempt.uri_mut() = proxy_uri;
                }
                ProxyDirective::Socks4(hp) => {
                    let proxy_uri: Uri = format!("socks4://{hp}")
                        .parse()
                        .map_err(|e| format!("bad socks4 uri {hp}: {e}"))?;
                    *attempt.uri_mut() = proxy_uri;
                }
                ProxyDirective::Socks5(hp) => {
                    let proxy_uri: Uri = format!("socks5://{hp}")
                        .parse()
                        .map_err(|e| format!("bad socks5 uri {hp}: {e}"))?;
                    *attempt.uri_mut() = proxy_uri;
                }
            }
            match self.service.serve(ctx.clone(), attempt).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    last_err = Some(e.into());
                }
            }
        }

        Err(last_err.unwrap_or_else(|| "no PAC options succeeded".into()))
    }
}
