//! ACME orders for IP identifiers (RFC 8738) against an in-process ACME server
//! that validates challenges the way the RFC describes.

use std::{
    convert::Infallible,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use parking_lot::Mutex;
use rama::{
    Layer as _, Service, ServiceInput,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
    http::{Body, Request, Response, StatusCode, body::util::BodyExt as _},
    io::Io,
    net::{address::Domain, tls::ApplicationProtocol},
    tls::{
        acme::{
            AcmeClient,
            proto::{
                client::{CreateAccountOptions, NewOrderPayload},
                common::Identifier,
                server::{ChallengeType, OrderStatus},
            },
        },
        server::{
            InputWithClientHello, PeekTlsClientHelloService, ServerAuthData, TlsServerConfig,
        },
    },
};
use rama_crypto::{
    dep::{
        aws_lc_rs::digest::{SHA256, digest},
        x509_parser::{
            certificate::X509Certificate,
            certification_request::X509CertificationRequest,
            extensions::{GeneralName, ParsedExtension},
            oid_registry::Oid,
            prelude::FromDer as _,
        },
    },
    jose::JWK,
    pki_types::CertificateDer,
};
use rama_tls_boring::{
    core::{
        ssl::{SslConnector, SslMethod, SslVerifyMode},
        tokio::SslStreamBuilder,
    },
    server::TlsAcceptorLayer as BoringAcceptorLayer,
};
use rama_tls_rustls::server::TlsAcceptorLayer as RustlsAcceptorLayer;
use rama_utils::octets::kib;
use serde_json::{Value, json};
use tokio::{
    io::{DuplexStream, duplex},
    time::timeout,
};

const BASE: &str = "https://acme.test";

/// How the server reaches a client's challenge responders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Responder {
    Boring,
    Rustls,
}

/// Completes a challenge connection; validation needs only the handshake.
#[derive(Clone, Copy)]
struct Accept;

impl<S: Send + 'static> Service<S> for Accept {
    type Output = ();

    type Error = Infallible;

    async fn serve(&self, _stream: S) -> Result<Self::Output, Self::Error> {
        Ok(())
    }
}

/// Challenge material the client publishes, by destination and challenge name.
#[derive(Default)]
struct Published {
    http: Vec<(Identifier, Box<str>, Box<str>)>,
    tls: Vec<(Domain, ServerAuthData)>,
}

struct SelectChallenge {
    published: Arc<Mutex<Published>>,
    responder: Responder,
}

impl<IO> Service<InputWithClientHello<IO>> for SelectChallenge
where
    IO: Io + Unpin + ExtensionsRef + 'static,
{
    type Output = ();

    type Error = BoxError;

    async fn serve(&self, hello: InputWithClientHello<IO>) -> Result<(), BoxError> {
        let name = hello
            .client_hello
            .ext_server_domain()
            .ok_or_else(|| BoxError::from_static_str("challenge SNI missing"))?;
        let auth = self
            .published
            .lock()
            .tls
            .iter()
            .find(|(published, _)| published == name)
            .map(|(_, auth)| auth.clone())
            .ok_or_else(|| BoxError::from_static_str("challenge SNI has no credential"))?;
        let config = TlsServerConfig::new()
            .with_server_auth(auth)
            .with_alpn([ApplicationProtocol::ACME_TLS].into_iter().collect());
        match self.responder {
            Responder::Boring => {
                BoringAcceptorLayer::new(config)
                    .into_layer(Accept)
                    .serve(hello.input)
                    .await
            }
            Responder::Rustls => {
                RustlsAcceptorLayer::new(config)
                    .into_layer(Accept)
                    .serve(hello.input)
                    .await
            }
        }
    }
}

#[derive(Default)]
struct State {
    thumbprint: Option<Box<str>>,
    identifiers: Vec<Identifier>,
    wire_identifiers: Vec<Value>,
    valid: Vec<bool>,
    finalized: bool,
    csr_names: Vec<Box<str>>,
}

/// An in-process ACME server.
#[derive(Clone)]
struct MockAcme {
    state: Arc<Mutex<State>>,
    published: Arc<Mutex<Published>>,
    responder: Responder,
}

fn url(path: &str) -> Box<str> {
    format!("{BASE}{path}").into()
}

fn response(status: StatusCode, location: Option<Box<str>>, body: &Value) -> Response {
    let mut builder = Response::builder()
        .status(status)
        .header("replay-nonce", "nonce")
        .header("content-type", "application/json");
    if let Some(location) = location {
        builder = builder.header("location", location.as_ref());
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

fn decode(segment: &str) -> Vec<u8> {
    BASE64_URL_SAFE_NO_PAD.decode(segment).unwrap()
}

impl MockAcme {
    /// Create the challenge service state.
    fn new(responder: Responder) -> Self {
        Self {
            state: Arc::default(),
            published: Arc::default(),
            responder,
        }
    }

    /// Return the challenge token.
    fn token(index: usize, kind: &str) -> Box<str> {
        format!("token-{index}-{kind}").into()
    }

    /// Build the test order representation.
    fn order(&self) -> Value {
        let state = self.state.lock();
        let status = if state.finalized {
            "valid"
        } else if !state.valid.is_empty() && state.valid.iter().all(|valid| *valid) {
            "ready"
        } else {
            "pending"
        };
        json!({
            "status": status,
            "identifiers": state.identifiers,
            "authorizations": (0..state.identifiers.len())
                .map(|index| url(&format!("/authz/{index}")))
                .collect::<Vec<_>>(),
            "finalize": url("/order/finalize"),
            "certificate": url("/cert"),
        })
    }

    /// Build the test challenge representation.
    fn challenge(&self, index: usize, kind: &str) -> Value {
        let status = if self.state.lock().valid[index] {
            "valid"
        } else {
            "pending"
        };
        json!({
            "type": kind,
            "url": url(&format!("/chall/{index}/{kind}")),
            "token": Self::token(index, kind),
            "status": status,
        })
    }

    /// Build the test authorization representation.
    fn authorization(&self, index: usize) -> Value {
        let identifier = self.state.lock().identifiers[index].clone();
        let mut challenges = vec![
            self.challenge(index, "http-01"),
            self.challenge(index, "tls-alpn-01"),
        ];
        // RFC 8738 section 7: dns-01 must not validate an ip identifier.
        if identifier.as_ip().is_none() {
            challenges.push(self.challenge(index, "dns-01"));
        }
        json!({"identifier": identifier, "status": "pending", "challenges": challenges})
    }

    /// Return the expected key authorization.
    fn key_authorization(&self, token: &str) -> Box<str> {
        let thumbprint = self.state.lock().thumbprint.clone().unwrap();
        format!("{token}.{thumbprint}").into()
    }

    /// Validate `http-01`: the published response at the token path is the key authorization.
    fn validate_http(&self, identifier: &Identifier, token: &str) -> bool {
        let path = format!("/.well-known/acme-challenge/{token}").into_boxed_str();
        let served = self
            .published
            .lock()
            .http
            .iter()
            .find(|(destination, published, _)| destination == identifier && **published == *path)
            .map(|(_, _, body)| body.clone());
        served.as_deref() == Some(self.key_authorization(token).as_ref())
    }

    /// Validate `tls-alpn-01` as RFC 8737 section 3 and RFC 8738 section 6 describe.
    async fn validate_tls(&self, identifier: &Identifier, token: &str) -> bool {
        let published = self.published.clone();
        let responder = self.responder;
        let (client, server) = duplex(kib(64));
        let serve = tokio::spawn(async move {
            PeekTlsClientHelloService::new(SelectChallenge {
                published,
                responder,
            })
            .serve(ServiceInput::new(server))
            .await
        });
        let leaf = present(client, identifier).await;
        serve.abort();
        let Some(leaf) = leaf else {
            return false;
        };
        certificate_proves(&leaf, identifier, &self.key_authorization(token))
    }

    /// Handle one request to the test service.
    async fn handle(&self, request: Request) -> Response {
        let path = request
            .uri()
            .path()
            .map(|path| path.to_string().into_boxed_str())
            .unwrap_or_default();
        let method = request.method().clone();
        if method == "GET" && path.as_ref() == "/dir" {
            return response(
                StatusCode::OK,
                None,
                &json!({
                    "newNonce": url("/nonce"),
                    "newAccount": url("/account"),
                    "newOrder": url("/order"),
                    "revokeCert": url("/revoke"),
                    "keyChange": url("/key-change"),
                }),
            );
        }
        if method == "HEAD" {
            return response(StatusCode::OK, None, &Value::Null);
        }
        let body = request.into_body().collect().await.unwrap().to_bytes();
        let jws: Value = serde_json::from_slice(&body).unwrap();
        let protected: Value =
            serde_json::from_slice(&decode(jws["protected"].as_str().unwrap())).unwrap();
        let payload_text = jws["payload"].as_str().unwrap_or_default();
        let payload: Value = if payload_text.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&decode(payload_text)).unwrap()
        };
        let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        match segments.as_slice() {
            ["account"] => {
                let jwk: JWK = serde_json::from_value(protected["jwk"].clone()).unwrap();
                let thumbprint = BASE64_URL_SAFE_NO_PAD.encode(jwk.thumb_sha256().unwrap());
                self.state.lock().thumbprint = Some(thumbprint.into());
                response(
                    StatusCode::CREATED,
                    Some(url("/account/1")),
                    &json!({"status": "valid"}),
                )
            }
            ["order"] => {
                let wire_identifiers = payload["identifiers"].as_array().unwrap().clone();
                let request: NewOrderPayload = serde_json::from_value(payload).unwrap();
                {
                    let mut state = self.state.lock();
                    state.valid = vec![false; request.identifiers.len()];
                    state.identifiers = request.identifiers;
                    state.wire_identifiers = wire_identifiers;
                }
                response(StatusCode::CREATED, Some(url("/order/1")), &self.order())
            }
            ["order", "1"] => response(StatusCode::OK, None, &self.order()),
            ["order", "finalize"] => {
                let csr = decode(payload["csr"].as_str().unwrap());
                let (_, request) = X509CertificationRequest::from_der(&csr).unwrap();
                assert!(
                    request
                        .certification_request_info
                        .subject
                        .iter()
                        .next()
                        .is_none()
                );
                let names = request
                    .requested_extensions()
                    .into_iter()
                    .flatten()
                    .filter_map(|extension| match extension {
                        ParsedExtension::SubjectAlternativeName(san) => Some(san),
                        _ => None,
                    })
                    .flat_map(|san| san.general_names.iter().map(general_name))
                    .collect();
                {
                    let mut state = self.state.lock();
                    state.csr_names = names;
                    state.finalized = true;
                }
                response(StatusCode::OK, None, &self.order())
            }
            ["authz", index] => response(
                StatusCode::OK,
                None,
                &self.authorization(index.parse().unwrap()),
            ),
            ["chall", index, kind] => {
                let index: usize = index.parse().unwrap();
                if !payload.is_null() {
                    // The challenge must be validated against the configured destination.
                    let identifier = self.state.lock().identifiers[index].clone();
                    let token = Self::token(index, kind);
                    let valid = match *kind {
                        "http-01" => self.validate_http(&identifier, &token),
                        "tls-alpn-01" => self.validate_tls(&identifier, &token).await,
                        _ => false,
                    };
                    assert!(
                        valid,
                        "challenge validation failed: {identifier:?} {kind} {:?}",
                        self.responder
                    );
                    self.state.lock().valid[index] = valid;
                }
                response(StatusCode::OK, None, &self.challenge(index, kind))
            }
            _ => response(StatusCode::NOT_FOUND, None, &Value::Null),
        }
    }
}

impl Service<Request> for MockAcme {
    type Output = Response;

    type Error = Infallible;

    async fn serve(&self, request: Request) -> Result<Self::Output, Self::Error> {
        Ok(self.handle(request).await)
    }
}

fn general_name(name: &GeneralName<'_>) -> Box<str> {
    match name {
        GeneralName::DNSName(name) => format!("dns:{name}").into(),
        GeneralName::IPAddress(bytes) => match bytes.len() {
            4 => format!("ip:{}", IpAddr::from(<[u8; 4]>::try_from(*bytes).unwrap())).into(),
            16 => format!("ip:{}", IpAddr::from(<[u8; 16]>::try_from(*bytes).unwrap())).into(),
            _ => "ip:invalid".into(),
        },
        other => format!("other:{other:?}").into(),
    }
}

fn expected_name(identifier: &Identifier) -> Box<str> {
    if let Some(ip) = identifier.as_ip() {
        format!("ip:{ip}").into()
    } else {
        format!("dns:{identifier}").into()
    }
}

/// The identifier as an ACME client sends it in a new order.
fn wire_identifier(identifier: &Identifier) -> Value {
    match (identifier.as_ip(), identifier.as_domain()) {
        (Some(ip), _) => json!({"type": "ip", "value": ip.to_string()}),
        (None, domain) => json!({"type": "dns", "value": domain.map(Domain::as_str)}),
    }
}

/// Handshake as a `tls-alpn-01` validator: SNI is the identifier's TLS-ALPN server name.
async fn present(client: DuplexStream, identifier: &Identifier) -> Option<CertificateDer<'static>> {
    let mut builder = SslConnector::builder(SslMethod::tls()).ok()?;
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_alpn_protos(b"\x0aacme-tls/1").ok()?;
    let mut ssl = builder.build().configure().ok()?.into_ssl(None).ok()?;
    let server_name = identifier.tls_alpn_server_name().ok()?;
    ssl.set_hostname(server_name.as_str()).ok()?;
    let stream = timeout(
        Duration::from_secs(5),
        SslStreamBuilder::new(ssl, client).connect(),
    )
    .await
    .ok()?
    .ok()?;
    if stream.ssl().selected_alpn_protocol() != Some(b"acme-tls/1".as_slice()) {
        return None;
    }
    let leaf = stream.ssl().peer_certificate()?.to_der().ok()?;
    Some(CertificateDer::from(leaf))
}

/// The certificate names only `identifier` and carries the key authorization digest.
fn certificate_proves(
    leaf: &CertificateDer<'_>,
    identifier: &Identifier,
    key_authorization: &str,
) -> bool {
    let Ok((_, certificate)) = X509Certificate::from_der(leaf.as_ref()) else {
        return false;
    };
    let Ok(Some(san)) = certificate.subject_alternative_name() else {
        return false;
    };
    let names: Vec<_> = san.value.general_names.iter().map(general_name).collect();
    if names != [expected_name(identifier)] {
        return false;
    }
    let acme_identifier = Oid::from(&[1, 3, 6, 1, 5, 5, 7, 1, 31]).unwrap();
    let Ok(Some(extension)) = certificate.get_extension_unique(&acme_identifier) else {
        return false;
    };
    // The extension value is a DER OCTET STRING of the SHA-256 digest.
    let expected = digest(&SHA256, key_authorization.as_bytes());
    let mut encoded = vec![0x04, 0x20];
    encoded.extend_from_slice(expected.as_ref());
    extension.critical && extension.value == encoded.as_slice()
}

/// Run one order for `identifiers`, completing every authorization with `kind`.
async fn run_order(
    responder: Responder,
    identifiers: Vec<Identifier>,
    kind: &ChallengeType,
) -> (bool, MockAcme) {
    let mock = MockAcme::new(responder);
    let client = AcmeClient::try_new(&url("/dir"), mock.clone())
        .await
        .unwrap()
        .with_default_retry_duration(Duration::from_millis(1));
    let account = client
        .create_account(CreateAccountOptions {
            terms_of_service_agreed: Some(true),
            ..Default::default()
        })
        .await
        .unwrap_or_else(|_| panic!("create account"));
    let mut order = account
        .try_new_order(NewOrderPayload {
            identifiers,
            ..Default::default()
        })
        .await
        .unwrap_or_else(|_| panic!("create order"));
    let authorizations = order
        .get_authorizations()
        .await
        .unwrap_or_else(|_| panic!("get authorizations"));
    for mut authorization in authorizations {
        let identifier = authorization.identifier.clone();
        let Some(challenge) = authorization
            .challenges
            .iter_mut()
            .find(|challenge| &challenge.r#type == kind)
        else {
            return (false, mock);
        };
        match kind {
            ChallengeType::Http01 => {
                let key_authorization = order.create_key_authorization(challenge).unwrap();
                mock.published.lock().http.push((
                    identifier.clone(),
                    format!("/.well-known/acme-challenge/{}", challenge.token).into(),
                    key_authorization.as_str().into(),
                ));
            }
            ChallengeType::TlsAlpn01 => {
                let (key, certificate) = order
                    .create_tls_challenge_data(challenge, &identifier)
                    .unwrap();
                mock.published.lock().tls.push((
                    identifier.tls_alpn_server_name().unwrap(),
                    ServerAuthData {
                        cert_chain: vec![certificate.der().clone()],
                        private_key: key.into(),
                        ocsp: None,
                    },
                ));
            }
            _ => return (false, mock),
        }
        if order.finish_challenge(challenge).await.is_err() {
            return (false, mock);
        }
    }
    if order
        .wait_until_all_authorizations_finished()
        .await
        .is_err()
    {
        return (false, mock);
    }
    let (_key, csr) = order.create_csr().unwrap();
    let finalized = order
        .finalize(csr.der())
        .await
        .is_ok_and(|order| order.status == OrderStatus::Valid);
    (finalized, mock)
}

fn identifier_sets() -> [Vec<Identifier>; 3] {
    let v4 = Identifier::ip(Ipv4Addr::new(192, 0, 2, 1).into());
    let v6 = Identifier::ip("2001:db8::1".parse::<Ipv6Addr>().unwrap().into());
    let dns = Identifier::dns(Domain::example());
    [vec![v4.clone()], vec![v6.clone()], vec![dns, v4, v6]]
}

#[tokio::test]
async fn ip_orders_validate_with_http_and_tls_alpn_challenges() {
    for responder in [Responder::Boring, Responder::Rustls] {
        for kind in [ChallengeType::Http01, ChallengeType::TlsAlpn01] {
            for identifiers in identifier_sets() {
                let (finalized, mock) = run_order(responder, identifiers.clone(), &kind).await;
                assert!(finalized, "{responder:?} {kind:?} {identifiers:?}");
                let state = mock.state.lock();
                // The server saw the identifiers with their own types, and the CSR names them.
                assert_eq!(state.identifiers, identifiers);
                let expected_wire: Vec<_> = identifiers.iter().map(wire_identifier).collect();
                assert_eq!(state.wire_identifiers, expected_wire);
                let expected: Vec<_> = identifiers.iter().map(expected_name).collect();
                assert_eq!(state.csr_names, expected, "{responder:?} {kind:?}");
            }
        }
    }
}

#[tokio::test]
async fn ip_orders_offer_no_dns_challenge_and_names_spelling_addresses_are_sent_as_ip() {
    let spelled = Identifier::dns("192.0.2.1");
    let (finalized, mock) =
        run_order(Responder::Rustls, vec![spelled], &ChallengeType::Dns01).await;
    assert!(!finalized, "dns-01 is not offered for an ip identifier");
    assert_eq!(
        mock.state.lock().wire_identifiers,
        [json!({"type": "ip", "value": "192.0.2.1"})]
    );
    assert_eq!(
        mock.state.lock().identifiers,
        [Identifier::ip(Ipv4Addr::new(192, 0, 2, 1).into())]
    );
}

#[tokio::test]
async fn challenge_validation_requires_the_destination_and_received_reverse_name() {
    let identifier = Identifier::ip(IpAddr::from([192, 0, 2, 1]));
    for responder in [Responder::Boring, Responder::Rustls] {
        let (_, http) =
            run_order(responder, vec![identifier.clone()], &ChallengeType::Http01).await;
        http.published.lock().http[0].0 = Identifier::ip(IpAddr::from([192, 0, 2, 2]));
        assert!(!http.validate_http(&identifier, &MockAcme::token(0, "http-01")));
        let (_, tls) = run_order(
            responder,
            vec![identifier.clone()],
            &ChallengeType::TlsAlpn01,
        )
        .await;
        tls.published.lock().tls[0].0 = Domain::from_static("other.test");
        assert!(
            !tls.validate_tls(&identifier, &MockAcme::token(0, "tls-alpn-01"))
                .await
        );
    }
}
