//! tls features provided from the http layer.

use crate::error::{ErrorContext as _, OpaqueError};
use crate::http::{
    BodyExtractExt as _, Request, Response, StatusCode, Uri, client::EasyHttpWebClient,
    service::client::HttpClientExt as _,
};
use crate::net::address::{Domain, DomainParentMatch, DomainTrie};
use crate::net::tls::{
    DataEncoding,
    client::ClientHello,
    server::{DynamicCertIssuer, ServerAuthData},
};
use crate::telemetry::tracing;
use crate::utils::str::NonEmptyString;
use crate::{Context, Service, combinators::Either, service::BoxService};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as ENGINE;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Json input used as http (POST) request payload sent by the [`CertIssuerHttpClient`].
pub struct CertOrderInput {
    pub domain: Domain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Json payload expected in
/// the http (POST) response payload as received by the [`CertIssuerHttpClient`].
pub struct CertOrderOutput {
    pub crt_pem_base64: String,
    pub key_pem_base64: String,
}

#[derive(Debug)]
/// An http client used to fetch certs dynamically ([`DynamicCertIssuer`]).
///
/// There is no server implementation in Rama.
/// It is up to the user of this client to provide their own server.
pub struct CertIssuerHttpClient {
    endpoint: Uri,
    allow_list: Option<DomainTrie<DomainAllowMode>>,
    http_client: BoxService<Request, Response, OpaqueError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DomainAllowMode {
    Exact,
    Parent,
}

impl CertIssuerHttpClient {
    /// Create a new [`CertIssuerHttpClient`] using the default [`EasyHttpWebClient`].
    pub fn new(endpoint: Uri) -> Self {
        Self::new_with_client(endpoint, EasyHttpWebClient::default().boxed())
    }

    #[cfg(feature = "boring")]
    pub fn try_from_env() -> Result<Self, OpaqueError> {
        use crate::{
            Layer as _,
            http::{headers::Authorization, layer::set_header::SetRequestHeaderLayer},
            net::user::Bearer,
            tls::boring::{
                client::TlsConnectorDataBuilder,
                core::x509::{X509, store::X509StoreBuilder},
            },
        };
        use std::sync::Arc;

        let uri_raw = std::env::var("RAMA_TLS_REMOTE").context("RAMA_TLS_REMOTE is undefined")?;

        let mut tls_config = TlsConnectorDataBuilder::new_http_auto();

        if let Ok(remote_ca_raw) = std::env::var("RAMA_TLS_REMOTE_CA") {
            let mut store_builder = X509StoreBuilder::new().expect("build x509 store builder");
            store_builder
                .add_cert(
                    X509::from_pem(
                        &ENGINE
                            .decode(remote_ca_raw)
                            .expect("base64 decode RAMA_TLS_REMOTE_CA")[..],
                    )
                    .expect("load CA cert"),
                )
                .expect("add CA cert to store builder");
            let store = store_builder.build();
            tls_config.set_server_verify_cert_store(store);
        }

        let client = EasyHttpWebClient::builder()
            .with_default_transport_connector()
            .without_tls_proxy_support()
            .without_proxy_support()
            .with_tls_support_using_boringssl(Some(Arc::new(tls_config)))
            .build();

        let uri: Uri = uri_raw.parse().expect("RAMA_TLS_REMOTE to be a valid URI");
        let mut client = if let Ok(auth_raw) = std::env::var("RAMA_TLS_REMOTE_AUTH") {
            Self::new_with_client(
                uri,
                SetRequestHeaderLayer::overriding_typed(Authorization::new(
                    Bearer::new(auth_raw).expect("RAMA_TLS_REMOTE_AUTH to be a valid Bearer token"),
                ))
                .into_layer(client)
                .boxed(),
            )
        } else {
            Self::new_with_client(uri, client.boxed())
        };

        if let Ok(allow_cn_csv_raw) = std::env::var("RAMA_TLS_REMOTE_CN_CSV") {
            for raw_cn_str in allow_cn_csv_raw.split(',') {
                match raw_cn_str.strip_prefix("*.") {
                    Some(raw_cn_str) => client.set_allow_parent_domain(raw_cn_str),
                    None => client.set_allow_exact_domain(raw_cn_str),
                };
            }
        }

        Ok(client)
    }

    /// Create a new [`CertIssuerHttpClient`] using a custom http client.
    ///
    /// The custom http client allows you to add whatever layers and client implementation
    /// you wish, to allow for custom headers, behaviour and security measures
    /// such as authorization.
    pub fn new_with_client(
        endpoint: Uri,
        client: BoxService<Request, Response, OpaqueError>,
    ) -> Self {
        Self {
            endpoint,
            allow_list: None,
            http_client: client,
        }
    }

    crate::utils::macros::generate_set_and_with! {
        /// Only allow fetching certs for the given domain.
        ///
        /// By default, if none of the `allow_*` setters are called
        /// the client will fetch for any client.
        pub fn allow_exact_domain(mut self, domain: impl AsRef<str>) -> Self {
            self.allow_list.get_or_insert_default().insert_domain(domain, DomainAllowMode::Exact);
            self
        }
    }

    crate::utils::macros::generate_set_and_with! {
        /// Only allow fetching certs for the given domains.
        ///
        /// By default, if none of the `allow_*` setters are called
        /// the client will fetch for any client.
        pub fn allow_exact_domains(mut self, domains: impl Iterator<Item: AsRef<str>>) -> Self {
            self.allow_list.get_or_insert_default().insert_domain_iter(domains, DomainAllowMode::Exact);
            self
        }
    }

    crate::utils::macros::generate_set_and_with! {
        /// Only allow fetching certs for the given domain.
        ///
        /// By default, if none of the `allow_*` setters are called
        /// the client will fetch for any client.
        pub fn allow_parent_domain(mut self, domain: impl AsRef<str>) -> Self {
            self.allow_list.get_or_insert_default().insert_domain(domain, DomainAllowMode::Parent);
            self
        }
    }

    crate::utils::macros::generate_set_and_with! {
        /// Only allow fetching certs for the given domains.
        ///
        /// By default, if none of the `allow_*` setters are called
        /// the client will fetch for any client.
        pub fn allow_parent_domains(mut self, domains: impl Iterator<Item: AsRef<str>>) -> Self {
            self.allow_list.get_or_insert_default().insert_domain_iter(domains, DomainAllowMode::Parent);
            self
        }
    }
}

impl DynamicCertIssuer for CertIssuerHttpClient {
    fn issue_cert(
        &self,
        client_hello: ClientHello,
        _server_name: Option<Domain>,
    ) -> impl Future<Output = Result<ServerAuthData, OpaqueError>> + Send + Sync + '_ {
        let domain = match client_hello.ext_server_name() {
            Some(domain) => {
                if let Some(ref allow_list) = self.allow_list {
                    match allow_list.match_parent(domain.as_str()) {
                        None => {
                            return Either::A(std::future::ready(Err(OpaqueError::from_display(
                                "sni found: unexpected unknown domain",
                            ))));
                        }
                        Some(DomainParentMatch {
                            value: &DomainAllowMode::Exact,
                            is_exact,
                            ..
                        }) => {
                            if is_exact {
                                domain
                            } else {
                                return Either::A(std::future::ready(Err(
                                    OpaqueError::from_display("sni found: unexpected child domain"),
                                )));
                            }
                        }
                        Some(DomainParentMatch {
                            value: &DomainAllowMode::Parent,
                            ..
                        }) => domain,
                    }
                } else {
                    domain
                }
            }
            None => {
                return Either::A(std::future::ready(Err(OpaqueError::from_display(
                    "no SNI found: failure",
                ))));
            }
        };

        let (tx, rx) = tokio::sync::oneshot::channel();
        let http_client = self.http_client.clone();
        let uri = self.endpoint.clone();
        let domain = domain.clone();

        tokio::spawn(async move {
            if let Err(err) = tx.send(fetch_certs(http_client, domain, uri).await) {
                tracing::debug!("failed to send result back to callee: {err:?}");
            }
        });

        Either::B(async move { rx.await.context("await crt order result")? })
    }
}

async fn fetch_certs(
    client: BoxService<Request, Response, OpaqueError>,
    domain: Domain,
    uri: Uri,
) -> Result<ServerAuthData, OpaqueError> {
    let response = client
        .post(uri)
        .json(&CertOrderInput { domain })
        .send(Context::default())
        .await
        .context("send order request")?;

    let status = response.status();
    if status != StatusCode::OK {
        return Err(OpaqueError::from_display(format!(
            "unexpected dinocert order response status code: {status}"
        )));
    }

    let CertOrderOutput {
        crt_pem_base64,
        key_pem_base64,
    } = response
        .into_body()
        .try_into_json()
        .await
        .context("fetch json crt order response")?;

    let crt = ENGINE.decode(crt_pem_base64).context("base64 decode crt")?;
    let key = ENGINE.decode(key_pem_base64).context("base64 decode crt")?;

    Ok(ServerAuthData {
        cert_chain: DataEncoding::Pem(
            NonEmptyString::try_from(
                String::from_utf8(crt).context("concert crt pem to utf8 string")?,
            )
            .context("convert crt utf8 string to non-empty")?,
        ),
        private_key: DataEncoding::Pem(
            NonEmptyString::try_from(
                String::from_utf8(key).context("concert private key pem to utf8 string")?,
            )
            .context("convert privatek key pem utf8 string to non-empty")?,
        ),
        ocsp: None,
    })
}
