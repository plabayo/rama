use crate::tls::acme::proto::{
    client::{FinalizePayload, KeyAuthorization, NewOrderPayload},
    common::Identifier,
    server::{
        AccountStatus, Authorization, AuthorizationStatus, Challenge, Order, OrderStatus, Problem,
        ProtectedHeader, ProtectedHeaderKey,
    },
};

use super::proto::{
    client::CreateAccountOptions,
    server::{Account, Directory, DirectoryMeta, LOCATION_HEADER, REPLAY_NONCE_HEADER},
};
use crate::crypto::dep::aws_lc_rs::signature;
use crate::crypto::jose::{Empty, JWK, JWSFlattened, Verifier};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use parking_lot::Mutex;
use rama_core::{
    Context, Layer, Service,
    error::{BoxError, ErrorContext, OpaqueError},
    layer::ConsumeErrLayer,
    service::{BoxService, service_fn},
};
use rama_crypto::dep::{
    aws_lc_rs::signature::UnparsedPublicKey,
    rcgen::Issuer,
    x509_parser::{asn1_rs::oid, parse_x509_certificate},
};
use rama_http::{
    Body, Request, Response,
    dep::http_body_util::BodyExt,
    layer::auth,
    matcher::UriParams,
    service::{
        client::HttpClientExt,
        web::{Router, extract::Json, response::Html},
    },
};
use rama_net::{
    client::EstablishedClientConnection,
    tls::{DataEncoding, client::NegotiatedTlsParameters},
};
use rama_tls_rustls::dep::rcgen::{
    self, Certificate, CertificateParams, CertificateSigningRequestParams, DistinguishedName, IsCa,
    KeyPair,
};
use serde::de::DeserializeOwned;
/// Very very basic acme server implementation, currently only useful
/// for testing but can extended to a full one
use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, atomic::AtomicU64},
    vec,
};

/// A very very basic acme serve
///
/// Warning: never use this for anything production related!
/// It can be used for internal rama tests or if you want to deploy
/// a very basic acme test server somewhere
pub struct AcmeServer<T = Config> {
    config: T,
    router: Router<Arc<Config>>,
}

/// Config for the [`AcmeServer`]
///
/// Note that how we generate ids is insecure and how we store/fetch
/// them is highly inefficient under load
pub struct Config {
    http_challenge_client: Option<HttpChallengeClient>,
    tls_challenge_client: Option<TlsChallengeClient>,
    host: String,
    current_nonce: AtomicU64,
    nonces: Arc<Mutex<Vec<u64>>>,
    current_kid: AtomicU64,
    accounts: Arc<Mutex<HashMap<String, Account>>>,
    key_ids: KeyIds,
    jwks: Arc<Mutex<HashMap<String, JWK>>>,
    current_order: AtomicU64,
    orders: Arc<Mutex<HashMap<String, CompleteOrder>>>,
    // certificate: Certificate,
    // keypair: KeyPair,
    issuer: Issuer<'static, KeyPair>,
}

struct CompleteOrder {
    order: Order,
    authorizations: Vec<Authorization>,
    certificate: Option<Certificate>,
}

struct TlsCertResponse<S> {
    inner: S,
}

impl<S> TlsCertResponse<S> {
    fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, T> Service<(), Request> for TlsCertResponse<S>
where
    S: Service<
            (),
            Request,
            Response = EstablishedClientConnection<T, (), Request>,
            Error: Into<BoxError>,
        >,
    T: Send + 'static,
{
    type Response = DataEncoding;

    type Error = OpaqueError;

    async fn serve(&self, ctx: Context<()>, req: Request) -> Result<Self::Response, Self::Error> {
        let conn = self
            .inner
            .serve(ctx, req)
            .await
            .map_err(|err| OpaqueError::from_boxed(err.into()))?;
        let peer_cert = conn
            .ctx
            .get::<NegotiatedTlsParameters>()
            .context("negotiated tls params")?
            .peer_certificate_chain
            .clone()
            .context("peer certificate chain")?;
        Ok(peer_cert)
    }
}

type HttpChallengeClient = BoxService<(), Request, Response, Infallible>;
type TlsChallengeClient = BoxService<(), Request<Body>, DataEncoding, OpaqueError>;

pub struct DirectoryPaths<'a> {
    pub directory: &'a str,
    pub new_nonce: &'a str,
    pub new_account: &'a str,
    pub new_order: &'a str,
    pub new_authz: Option<&'a str>,
    pub revoke_cert: &'a str,
    pub key_change: &'a str,
}

#[derive(Default, Debug)]
struct KeyIds(Arc<Mutex<HashMap<String, signature::UnparsedPublicKey<Vec<u8>>>>>);

#[derive(Debug)]
struct MaybeKeyIdsVerifier<'a> {
    key_ids: &'a KeyIds,
    nonces: &'a Arc<Mutex<Vec<u64>>>,
}

impl<'a> Verifier for MaybeKeyIdsVerifier<'a> {
    type Error = OpaqueError;
    type Output = ProtectedHeader;

    fn verify(
        &self,
        payload: &[u8],
        signatures: &[rama_crypto::jose::ToVerifySignature],
    ) -> Result<Self::Output, Self::Error> {
        println!("verify");
        if signatures.len() != 1 {
            return Err(OpaqueError::from_display(
                "received unexpected amount of signatures",
            ));
        }
        println!("verify2");

        let signature = &signatures[0];
        let decoded = signature.decoded_signature();
        let info = decoded.decode_protected_headers::<ProtectedHeader>()?;

        let received_nonce: u64 = info.nonce.parse().context("parse nonce to u64")?;
        println!("verify3");
        let mut nonces = self.nonces.lock();
        let nonce_idx = nonces.iter().position(|nonce| nonce == &received_nonce);

        if let Some(idx) = nonce_idx {
            nonces.remove(idx);
        } else {
            return Err(OpaqueError::from_display("invalid nonce provided"));
        };

        println!("verify4");
        match info.key {
            ProtectedHeaderKey::JWK(ref jwk) => {
                println!("verify5");
                let key = jwk.unparsed_public_key()?;
                println!("verify5: {:?}", decoded.signature());

                let result = key
                    .verify(signature.signed_data().as_bytes(), decoded.signature())
                    .context("verify correct signature");
                println!("key: {result:?}");
                println!("verify5");
            }
            ProtectedHeaderKey::KeyID(ref id) => {
                let keys = self.key_ids.0.lock();
                let key = keys.get(id).context("fetch key for given key_id")?;
                key.verify(signature.signed_data().as_bytes(), decoded.signature())
                    .context("verify correct signature")?;
            }
        }
        println!("verify6");
        Ok(info)
    }
}

type State = Arc<Config>;

impl AcmeServer {
    pub fn new(
        host: &str,
        directory_paths: &DirectoryPaths,
        directory_meta: Option<DirectoryMeta>,
    ) -> Self {
        let directory = Directory {
            new_nonce: format!("{}{}", host, directory_paths.new_nonce),
            new_account: format!("{}{}", host, directory_paths.new_account),
            new_order: format!("{}{}", host, directory_paths.new_order),
            new_authz: directory_paths
                .new_authz
                .map(|path| format!("{}{}", host, path)),
            revoke_cert: format!("{}{}", host, directory_paths.revoke_cert),
            key_change: format!("{}{}", host, directory_paths.key_change),
            meta: directory_meta,
        };

        let ca_key_pair = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        let mut ca_distinguished_name = DistinguishedName::new();
        ca_distinguished_name.push(rcgen::DnType::CommonName, "My Test CA");
        ca_params.distinguished_name = ca_distinguished_name;
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        // let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();

        let issuer = Issuer::new(ca_params, ca_key_pair);

        let config = Config {
            host: host.into(),
            // certificate: ca_cert,
            // keypair: ca_key_pair,
            accounts: Default::default(),
            current_kid: Default::default(),
            current_nonce: Default::default(),
            current_order: Default::default(),
            http_challenge_client: Default::default(),
            jwks: Default::default(),
            key_ids: Default::default(),
            nonces: Default::default(),
            orders: Default::default(),
            tls_challenge_client: Default::default(),
            issuer,
        };

        let layers = (WithNonceHeaderLayer, ConsumeErrLayer::default());

        let router = Router::new()
            .get("/", Html("Very basic acme server".to_owned()))
            .get(directory_paths.directory, Json(directory))
            .head(
                directory_paths.new_nonce,
                layers.layer(service_fn(Self::new_nonce)),
            )
            .post(
                directory_paths.new_account,
                layers.layer(service_fn(Self::new_account)),
            )
            .post(
                directory_paths.new_order,
                layers.layer(service_fn(Self::new_order)),
            )
            .post("/order/{order_idx}", layers.layer(service_fn(Self::order)))
            .post(
                "/finalize/{order_idx}",
                layers.layer(service_fn(Self::finalize)),
            )
            .post(
                "/certificate/{order_idx}",
                layers.layer(service_fn(Self::certificate)),
            )
            .post(
                "/authorization/{order_idx}/{auth_idx}",
                layers.layer(service_fn(Self::authorization)),
            )
            .post(
                "/challenge/{order_idx}/{auth_idx}/{challenge_idx}",
                layers.layer(service_fn(Self::challenge)),
            );

        Self { config, router }
    }

    pub fn with_http_challenge_client(mut self, client: HttpChallengeClient) -> Self {
        self.config.http_challenge_client = Some(client);
        self
    }

    pub fn with_tls_challenge_client<C, T>(mut self, tls_connector: C) -> Self
    where
        C: Service<
                (),
                Request,
                Response = EstablishedClientConnection<T, (), Request>,
                Error: Into<BoxError>,
            >,
        T: Send + 'static,
    {
        let tls_client = TlsCertResponse::new(tls_connector).boxed();
        self.config.tls_challenge_client = Some(tls_client);
        self
    }

    pub fn build(self) -> AcmeServer<Arc<Config>> {
        AcmeServer {
            router: self.router,
            config: Arc::new(self.config),
        }
    }

    async fn new_nonce(_ctx: Context<State>, _req: Request) -> Result<Response, OpaqueError> {
        // Nonce header is always set by our WithNonceHeaderLayer, we just need to endpoint to return
        // and emtpy 200 response
        let resp = Response::builder().body(rama_http::Body::empty()).unwrap();
        Ok(resp)
    }

    async fn new_account(ctx: Context<State>, req: Request) -> Result<Response, OpaqueError> {
        println!("server account");
        let (create_opts, protected_header) =
            Self::parse_request::<CreateAccountOptions>(&ctx, req).await?;

        // println!("protected header: {:?}", result.protected());

        println!("create_opts: {:?}", create_opts);

        let kid = ctx
            .state()
            .current_kid
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        let host = ctx.state().host.as_str();
        let location = format!("{host}/account/{kid}");

        let (jwk, pub_key) = match protected_header.key {
            ProtectedHeaderKey::JWK(jwk) => {
                let pub_key = jwk.unparsed_public_key()?;
                (jwk, pub_key)
            }
            ProtectedHeaderKey::KeyID(_) => {
                return Err(OpaqueError::from_display("JWK needed to create account"));
            }
        };

        let account = Account {
            contact: None,
            external_account_binding: None,
            status: AccountStatus::Valid,
            orders: String::new(),
            terms_of_service_agreed: None,
        };

        ctx.state()
            .key_ids
            .0
            .lock()
            .insert(location.clone(), pub_key);

        ctx.state().jwks.lock().insert(location.clone(), jwk);

        let mut accounts = ctx.state().accounts.lock();
        let inserted = accounts.entry(kid.to_string()).insert_entry(account);
        let account = inserted.get();

        let resp = Response::builder()
            .header(LOCATION_HEADER, location)
            .body(Body::from(serde_json::to_vec(account).unwrap()))
            .unwrap();

        println!("creating account server");
        Ok(resp)
    }

    async fn new_order(ctx: Context<State>, req: Request) -> Result<Response, OpaqueError> {
        let (payload, _header) = Self::parse_request::<NewOrderPayload>(&ctx, req).await?;

        let order_id = ctx
            .state()
            .current_order
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        let mut authorizations = Vec::with_capacity(payload.identifiers.len());
        let mut authorizations_locations = Vec::with_capacity(payload.identifiers.len());
        for (idx, identifier) in payload.identifiers.iter().enumerate() {
            let auth = Self::create_authorization(&ctx, identifier, order_id, idx as u64)?;
            authorizations_locations.push(auth.0);
            authorizations.push(auth.1);
        }

        let host = ctx.state().host.as_str();
        let location = format!("{host}/order/{order_id}");
        let finalize_location = format!("{host}/finalize/{order_id}");

        let order = Order {
            authorizations: authorizations_locations,
            certificate: None,
            error: None,
            expires: None,
            finalize: finalize_location,
            identifiers: payload.identifiers,
            not_after: payload.not_after,
            not_before: payload.not_before,
            status: OrderStatus::Pending,
        };

        let resp = Response::builder()
            .header(LOCATION_HEADER, location)
            .status(201)
            .body(Body::from(serde_json::to_vec(&order).unwrap()))
            .unwrap();

        let order = CompleteOrder {
            order,
            authorizations,
            certificate: None,
        };

        ctx.state()
            .orders
            .lock()
            .insert(order_id.to_string(), order);

        Ok(resp)
    }

    fn create_authorization(
        ctx: &Context<State>,
        identifier: &Identifier,
        order_idx: u64,
        auth_idx: u64,
    ) -> Result<(String, Authorization), OpaqueError> {
        let authz = Authorization {
            challenges: Self::create_challenges(ctx, identifier, order_idx, auth_idx)?,
            expires: None,
            identifier: identifier.clone(),
            status: super::proto::server::AuthorizationStatus::Pending,
            wildcard: None,
        };

        let host = ctx.state().host.as_str();
        let location = format!("{host}/authorization/{order_idx}/{auth_idx}");

        Ok((location, authz))
    }

    fn create_challenges(
        ctx: &Context<State>,
        identifier: &Identifier,
        order_idx: u64,
        auth_idx: u64,
    ) -> Result<Vec<Challenge>, OpaqueError> {
        let mut challenges = vec![];
        if ctx.state().http_challenge_client.is_some() {
            challenges.push(Self::create_http_challenge(
                &ctx,
                identifier,
                order_idx,
                auth_idx,
                challenges.len() as u64,
            )?);
        }

        if ctx.state().tls_challenge_client.is_some() {
            challenges.push(Self::create_tls_challenge(
                &ctx,
                identifier,
                order_idx,
                auth_idx,
                challenges.len() as u64,
            )?);
        }

        Ok(challenges)
    }

    fn create_http_challenge(
        ctx: &Context<State>,
        _identifier: &Identifier,
        order_idx: u64,
        auth_idx: u64,
        challenge_idx: u64,
    ) -> Result<Challenge, OpaqueError> {
        if ctx.state().http_challenge_client.is_none() {
            return Err(OpaqueError::from_display(
                "http challenge only possible if a http client is configured",
            ));
        }

        let host = ctx.state().host.as_str();
        let challenge = Challenge {
            r#type: super::proto::server::ChallengeType::Http01,
            error: None,
            status: super::proto::server::ChallengeStatus::Pending,
            token: "random-uuid".into(),
            url: format!("{host}/challenge/{order_idx}/{auth_idx}/{challenge_idx}"),
        };

        Ok(challenge)
    }

    fn create_tls_challenge(
        ctx: &Context<State>,
        _identifier: &Identifier,
        order_idx: u64,
        auth_idx: u64,
        challenge_idx: u64,
    ) -> Result<Challenge, OpaqueError> {
        if ctx.state().tls_challenge_client.is_none() {
            return Err(OpaqueError::from_display(
                "tls challenge only possible if a tls client is configured",
            ));
        }

        let host = ctx.state().host.as_str();
        let challenge = Challenge {
            r#type: super::proto::server::ChallengeType::TlsAlpn01,
            error: None,
            status: super::proto::server::ChallengeStatus::Pending,
            token: "random-uuid".into(),
            url: format!("{host}/challenge/{order_idx}/{auth_idx}/{challenge_idx}"),
        };

        Ok(challenge)
    }

    async fn order(ctx: Context<State>, _req: Request) -> Result<Response, OpaqueError> {
        let params = ctx.get::<UriParams>().unwrap();
        let id = params.get("order_idx").unwrap();

        let orders = ctx.state().orders.lock();
        let order = orders.get(id).unwrap();

        let resp = Response::builder()
            .body(Body::from(serde_json::to_vec(&order.order).unwrap()))
            .unwrap();

        Ok(resp)
    }

    async fn finalize(ctx: Context<State>, req: Request) -> Result<Response, OpaqueError> {
        let params = ctx.get::<UriParams>().unwrap();
        let id = params.get("order_idx").unwrap();

        let (payload, _) = Self::parse_request::<FinalizePayload>(&ctx, req).await?;

        let mut orders = ctx.state().orders.lock();
        let order = orders.get_mut(id).unwrap();

        if order.order.status != OrderStatus::Ready {
            return Err(OpaqueError::from_display("order not in ready state"));
        }

        // TODO checks to verify that csr is valid for this order

        order.order.status = OrderStatus::Processing;
        println!("csr: {:?}", &payload);

        let csr = CertificateSigningRequestParams::from_pem(&payload.csr).unwrap();
        let signed_cert = csr.signed_by(&ctx.state().issuer).unwrap();
        order.certificate = Some(signed_cert);
        let host = ctx.state().host.as_str();
        order.order.certificate = Some(format!("{host}/certificate/{id}"));
        order.order.status = OrderStatus::Valid;

        let resp = Response::builder()
            .body(Body::from(serde_json::to_vec(&order.order).unwrap()))
            .unwrap();

        Ok(resp)
    }

    async fn certificate(ctx: Context<State>, _req: Request) -> Result<Response, OpaqueError> {
        let params = ctx.get::<UriParams>().unwrap();
        let id = params.get("order_idx").unwrap();

        let orders = ctx.state().orders.lock();
        let order = orders.get(id).unwrap();

        let certificate = order.certificate.as_ref().unwrap().pem();

        let resp = Response::builder()
            .body(Body::from(serde_json::to_vec(&certificate).unwrap()))
            .unwrap();

        Ok(resp)
    }

    async fn authorization(ctx: Context<State>, _req: Request) -> Result<Response, OpaqueError> {
        let params = ctx.get::<UriParams>().unwrap();
        let order_idx = params.get("order_idx").unwrap();
        let auth_idx = params.get("auth_idx").unwrap().parse::<usize>().unwrap();

        let orders = ctx.state().orders.lock();

        let order = orders.get(order_idx).unwrap();
        let authorization = &order.authorizations[auth_idx];

        let resp = Response::builder()
            .body(Body::from(serde_json::to_vec(authorization).unwrap()))
            .unwrap();

        Ok(resp)
    }

    async fn challenge(ctx: Context<State>, req: Request) -> Result<Response, OpaqueError> {
        let params = ctx.get::<UriParams>().unwrap();
        let order_idx = params.get("order_idx").unwrap();
        let auth_idx = params.get("auth_idx").unwrap().parse::<usize>().unwrap();
        let challenge_idx = params
            .get("challenge_idx")
            .unwrap()
            .parse::<usize>()
            .unwrap();

        let (payload, headers) = Self::parse_request::<Option<Empty>>(&ctx, req).await?;

        println!("challenge payload: {:?}", payload);

        // No payload = client wants to refresh data
        if payload.is_none() {
            let orders = ctx.state().orders.lock();
            let order = orders.get(order_idx).unwrap();
            let challenge = &order.authorizations[auth_idx].challenges[challenge_idx];

            let resp = Response::builder()
                .body(Body::from(serde_json::to_vec(challenge).unwrap()))
                .unwrap();
            return Ok(resp);
        }

        enum ChallengeType {
            Http(String),
            Tls,
        }

        let (challenge_type, key_authz) = {
            let mut orders = ctx.state().orders.lock();
            let order = orders.get_mut(order_idx).unwrap();
            let challenge = &mut order.authorizations[auth_idx].challenges[challenge_idx];
            println!("checking challenge: {:?}", challenge);

            challenge.status = super::proto::server::ChallengeStatus::Processing;

            let challenge_type = match challenge.r#type {
                crate::tls::acme::proto::server::ChallengeType::Http01 => {
                    ChallengeType::Http(format!(
                        "https://todo.com/.well-known/acme-challenge/{}",
                        challenge.token
                    ))
                }
                crate::tls::acme::proto::server::ChallengeType::Dns01 => todo!(),
                crate::tls::acme::proto::server::ChallengeType::TlsAlpn01 => ChallengeType::Tls,
                crate::tls::acme::proto::server::ChallengeType::Unknown(_) => todo!(),
            };

            let jwks = ctx.state().jwks.lock();

            let jwk = match &headers.key {
                ProtectedHeaderKey::JWK(jwk) => todo!("jkfd"),
                ProtectedHeaderKey::KeyID(id) => jwks.get(id).unwrap(),
            };

            let key_authz = KeyAuthorization::new(challenge.token.as_str(), jwk)?;
            println!("key_authz: {key_authz:?}");
            (challenge_type, key_authz)
        };

        match challenge_type {
            ChallengeType::Http(url) => {
                Self::verify_http_challenge(&ctx, &url, (order_idx, auth_idx, challenge_idx))
                    .await?
            }
            ChallengeType::Tls => {
                Self::verify_tls_challenge(&ctx, (order_idx, auth_idx, challenge_idx), &key_authz)
                    .await?
            }
        }

        let resp = Response::builder()
            .body(Body::from(serde_json::to_vec(&Empty {}).unwrap()))
            .unwrap();
        Ok(resp)
    }

    async fn verify_tls_challenge(
        ctx: &Context<State>,
        id: (&str, usize, usize),
        key_authz: &KeyAuthorization,
    ) -> Result<(), OpaqueError> {
        let client = ctx
            .state()
            .tls_challenge_client
            .as_ref()
            .context("client needed")?;

        let data = client
            .serve(
                Context::default(),
                Request::builder()
                    .uri("https://todo.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        println!("keyauthz received: {:?}", &data);

        {
            let mut orders = ctx.state().orders.lock();
            let order = orders.get_mut(id.0).unwrap();
            let auth = &mut order.authorizations[id.1];
            let challenge = &mut auth.challenges[id.2];
            println!("checking challenge: {:?}", challenge);

            let cert = match data {
                DataEncoding::Der(_) => Err(OpaqueError::from_display("todo")),
                DataEncoding::DerStack(items) => Ok(items[0].clone()),
                DataEncoding::Pem(_) => Err(OpaqueError::from_display("todo")),
            }?;

            let digest = key_authz.digest();
            let expected = digest.as_ref();
            println!("expected extension content: {:?}", expected);

            println!("received cert: {:?}", cert);

            let (_, cert) = parse_x509_certificate(&cert).context("parse certificate")?;

            let oid = oid!(1.3.6.1.5.5.7.1.31);
            let acme = cert
                .get_extension_unique(&oid)
                .context("get acme extension")?
                .unwrap();

            if expected == &acme.value[2..] {
                auth.status = AuthorizationStatus::Valid;
                challenge.status = super::proto::server::ChallengeStatus::Valid;
            } else {
                return Err(OpaqueError::from_display("wrong key provided"));
            }

            let all_valid = order
                .authorizations
                .iter()
                .all(|auth| auth.status == AuthorizationStatus::Valid);

            if all_valid {
                println!("tls ready");
                order.order.status = OrderStatus::Ready;
            }
        }

        let "rhs" = Self::testtt("e") else {
            return Err(OpaqueError::from_display("msg"));
        };

        let x = rhs;

        println!("tls ok");
        Ok(())
    }

    fn testtt<'a>(a: &'a str) -> &'a str {
        a
    }

    async fn verify_http_challenge(
        ctx: &Context<State>,
        url: &str,
        id: (&str, usize, usize),
    ) -> Result<(), OpaqueError> {
        let client = ctx
            .state()
            .http_challenge_client
            .as_ref()
            .context("client needed")?;

        let bytes = client
            .get(url)
            .send(Context::default())
            .await
            .unwrap()
            .into_body()
            .collect()
            .await?
            .to_bytes();

        let data = String::from_utf8(bytes.to_vec()).unwrap();
        println!("keyauthz received: {}", &data);

        {
            let mut orders = ctx.state().orders.lock();
            let order = orders.get_mut(id.0).unwrap();
            let auth = &mut order.authorizations[id.1];
            let challenge = &mut auth.challenges[id.2];
            println!("checking challenge: {:?}", challenge);

            if data.contains(challenge.token.as_str()) {
                auth.status = AuthorizationStatus::Valid;
                challenge.status = super::proto::server::ChallengeStatus::Valid;
            } else {
                return Err(OpaqueError::from_display("wrong key provided"));
            }

            let all_valid = order
                .authorizations
                .iter()
                .all(|auth| auth.status == AuthorizationStatus::Valid);

            if all_valid {
                order.order.status = OrderStatus::Ready;
            }
        };
        Ok(())
    }

    async fn parse_request<T: DeserializeOwned + std::fmt::Debug>(
        ctx: &Context<State>,
        req: Request,
    ) -> Result<(T, ProtectedHeader), OpaqueError> {
        let bytes = req.into_body().collect().await.unwrap().to_bytes();

        println!("bytes: {:?}", &bytes);
        let result = serde_json::from_slice::<JWSFlattened>(&bytes).context("parse response")?;

        let (decoded, protected_header) = result.decode(&MaybeKeyIdsVerifier {
            key_ids: &ctx.state().key_ids,
            nonces: &ctx.state().nonces,
        })?;

        println!("decodedd input: {:?}", decoded.payload());

        let payload = if decoded.payload().len() > 0 {
            decoded.payload()
        } else {
            "null".as_bytes()
        };

        let result = serde_json::from_slice::<T>(payload).context("decode payload");
        println!("decodedd payload: {:?}", result);
        let result = result?;
        Ok((result, protected_header))
    }
}

impl Service<(), Request> for AcmeServer<Arc<Config>> {
    type Response = Response;

    type Error = OpaqueError;

    async fn serve(&self, ctx: Context<()>, req: Request) -> Result<Self::Response, Self::Error> {
        let ctx = ctx.clone_with_state(self.config.clone());

        self.router
            .serve(ctx, req)
            .await
            .map_err(|_err| OpaqueError::from_display("something went wrong"))
    }
}

struct WithNonceHeader<S>(S);

impl<S> Service<State, Request> for WithNonceHeader<S>
where
    S: Service<State, Request, Response = Response, Error = Infallible>,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let nonce = ctx
            .state()
            .current_nonce
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        ctx.state().nonces.lock().push(nonce);

        let mut resp = self.0.serve(ctx, req).await?;
        resp.headers_mut().insert(REPLAY_NONCE_HEADER, nonce.into());

        Ok(resp)
    }
}

struct WithNonceHeaderLayer;
impl<S> Layer<S> for WithNonceHeaderLayer {
    type Service = WithNonceHeader<S>;

    fn layer(&self, inner: S) -> Self::Service {
        WithNonceHeader(inner)
    }
}
