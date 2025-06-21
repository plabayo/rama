use crate::tls::acme::proto::{
    client::{Jwk, KeyAuthorization, KeyIdToUnparsedPublicKey, NewOrderPayload},
    common::{Empty, Identifier},
    server::{AccountStatus, Authorization, Challenge, Order, OrderStatus},
};

use super::proto::{
    client::{CreateAccountOptions, DecodedJws, Jws},
    server::{Account, Directory, DirectoryMeta, LOCATION_HEADER, REPLAY_NONCE_HEADER},
};
use aws_lc_rs::signature;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use parking_lot::Mutex;
use rama_core::{
    Context, Layer, Service,
    error::{BoxError, ErrorContext, OpaqueError},
    layer::ConsumeErrLayer,
    service::{BoxService, service_fn},
};
use rama_http::{
    Body, Request, Response,
    dep::http_body_util::BodyExt,
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
use rama_tls_rustls::dep::pki_types::CertificateDer;
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

#[derive(Default)]
/// Config for the [`AcmeServer`]
///
/// Note that how we generate ids is unsecure and how we store/fetch
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
    jwks: Arc<Mutex<HashMap<String, Jwk>>>,
    current_order: AtomicU64,
    orders: Arc<Mutex<HashMap<String, Order>>>,
    current_authorization: AtomicU64,
    authorizations: Arc<Mutex<HashMap<String, Authorization>>>,
    current_challenge: AtomicU64,
    challenges: Arc<Mutex<HashMap<String, Challenge>>>,
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

#[derive(Default)]
struct KeyIds(Arc<Mutex<HashMap<String, signature::UnparsedPublicKey<Vec<u8>>>>>);

impl KeyIdToUnparsedPublicKey for KeyIds {
    fn verify<F>(&self, key_id: &str, verify: F) -> Result<(), OpaqueError>
    where
        F: FnOnce(Option<&signature::UnparsedPublicKey<Vec<u8>>>) -> Result<(), OpaqueError>,
    {
        (verify)(self.0.lock().get(key_id))
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

        let config = Config {
            host: host.into(),
            ..Default::default()
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
            .post("/order/{id}", layers.layer(service_fn(Self::order)))
            .post(
                "/authorization/{id}",
                layers.layer(service_fn(Self::authorization)),
            )
            .post("/challenge/{id}", layers.layer(service_fn(Self::challenge)));

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
        let result = Self::parse_request::<CreateAccountOptions>(&ctx, req).await?;

        println!("protected header: {:?}", result.protected());

        println!("payload: {:?}", result.payload());

        let kid = ctx
            .state()
            .current_kid
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        let host = ctx.state().host.as_str();
        let location = format!("{host}/account/{kid}");

        let (jwk, pub_key) = match result.protected().unwrap().key {
            crate::tls::acme::proto::client::ProtectedHeaderKey::JWK(jwk) => {
                let pub_key = jwk.unparsed_public_key();
                (jwk, pub_key)
            }
            crate::tls::acme::proto::client::ProtectedHeaderKey::KeyID(_) => {
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

        Ok(resp)
    }

    async fn new_order(ctx: Context<State>, req: Request) -> Result<Response, OpaqueError> {
        let result = Self::parse_request::<NewOrderPayload>(&ctx, req).await?;
        let payload = result.into_payload().unwrap();

        let order_id = ctx
            .state()
            .current_order
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        let mut authorizations = Vec::with_capacity(payload.identifiers.len());
        for identifier in payload.identifiers.iter() {
            authorizations.push(Self::create_authorization(&ctx, identifier)?)
        }

        let order = Order {
            authorizations: authorizations,
            certificate: None,
            error: None,
            expires: None,
            finalize: "finalize".into(),
            identifiers: payload.identifiers,
            not_after: payload.not_after,
            not_before: payload.not_before,
            status: OrderStatus::Pending,
        };

        let mut orders = ctx.state().orders.lock();
        let inserted = orders.entry(order_id.to_string()).insert_entry(order);
        let order = inserted.get();

        let host = ctx.state().host.as_str();
        let location = format!("{host}/order/{order_id}");

        let resp = Response::builder()
            .header(LOCATION_HEADER, location)
            .body(Body::from(serde_json::to_vec(order).unwrap()))
            .unwrap();

        Ok(resp)
    }

    fn create_authorization(
        ctx: &Context<State>,
        identifier: &Identifier,
    ) -> Result<String, OpaqueError> {
        let authz_id = ctx
            .state()
            .current_authorization
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        let authz = Authorization {
            challenges: Self::create_challenges(ctx, identifier)?,
            expires: None,
            identifier: identifier.clone(),
            status: super::proto::server::AuthorizationStatus::Pending,
            wildcard: None,
        };

        ctx.state()
            .authorizations
            .lock()
            .insert(authz_id.to_string(), authz);

        let host = ctx.state().host.as_str();
        let location = format!("{host}/authorization/{authz_id}");
        Ok(location)
    }

    fn create_challenges(
        ctx: &Context<State>,
        identifier: &Identifier,
    ) -> Result<Vec<Challenge>, OpaqueError> {
        let mut challenges = vec![];
        if ctx.state().http_challenge_client.is_some() {
            challenges.push(Self::create_http_challenge(&ctx, identifier)?);
        }

        if ctx.state().tls_challenge_client.is_some() {
            challenges.push(Self::create_tls_challenge(&ctx, identifier)?);
        }

        Ok(challenges)
    }

    fn create_http_challenge(
        ctx: &Context<State>,
        _identifier: &Identifier,
    ) -> Result<Challenge, OpaqueError> {
        if ctx.state().http_challenge_client.is_none() {
            return Err(OpaqueError::from_display(
                "http challenge only possible if a http client is configured",
            ));
        }
        let challenge_id = ctx
            .state()
            .current_challenge
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        let host = ctx.state().host.as_str();
        let challenge = Challenge {
            r#type: super::proto::server::ChallengeType::Http01,
            error: None,
            status: super::proto::server::ChallengeStatus::Pending,
            token: "random-uuid".into(),
            url: format!("{host}/challenge/{challenge_id}"),
        };

        ctx.state()
            .challenges
            .lock()
            .insert(challenge_id.to_string(), challenge.clone());

        Ok(challenge)
    }

    fn create_tls_challenge(
        ctx: &Context<State>,
        _identifier: &Identifier,
    ) -> Result<Challenge, OpaqueError> {
        if ctx.state().tls_challenge_client.is_none() {
            return Err(OpaqueError::from_display(
                "tls challenge only possible if a tls client is configured",
            ));
        }
        let challenge_id = ctx
            .state()
            .current_challenge
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        let host = ctx.state().host.as_str();
        let challenge = Challenge {
            r#type: super::proto::server::ChallengeType::TlsAlpn01,
            error: None,
            status: super::proto::server::ChallengeStatus::Pending,
            token: "random-uuid".into(),
            url: format!("{host}/challenge/{challenge_id}"),
        };

        ctx.state()
            .challenges
            .lock()
            .insert(challenge_id.to_string(), challenge.clone());

        Ok(challenge)
    }

    async fn order(ctx: Context<State>, _req: Request) -> Result<Response, OpaqueError> {
        let params = ctx.get::<UriParams>().unwrap();
        let id = params.get("id").unwrap();

        let orders = ctx.state().orders.lock();
        let order = orders.get(id).unwrap();

        let resp = Response::builder()
            .body(Body::from(serde_json::to_vec(order).unwrap()))
            .unwrap();

        Ok(resp)
    }

    async fn authorization(ctx: Context<State>, _req: Request) -> Result<Response, OpaqueError> {
        let params = ctx.get::<UriParams>().unwrap();
        let id = params.get("id").unwrap();

        let authorizations = ctx.state().authorizations.lock();
        let authorization = authorizations.get(id).unwrap();

        let resp = Response::builder()
            .body(Body::from(serde_json::to_vec(authorization).unwrap()))
            .unwrap();

        Ok(resp)
    }

    async fn challenge(ctx: Context<State>, req: Request) -> Result<Response, OpaqueError> {
        let params = ctx.get::<UriParams>().unwrap();
        let id = params.get("id").unwrap();

        let result = Self::parse_request::<Empty>(&ctx, req).await?;

        // No payload = client wants to refresh data
        if result.payload().is_none() {
            let challenges = ctx.state().challenges.lock();
            let challenge = challenges.get(id).unwrap();
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
            let mut challenges = ctx.state().challenges.lock();
            let challenge = challenges.get_mut(id).unwrap();
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

            let jwk = match &result.protected().unwrap().key {
                crate::tls::acme::proto::client::ProtectedHeaderKey::JWK(jwk) => todo!("jkfd"),
                crate::tls::acme::proto::client::ProtectedHeaderKey::KeyID(id) => {
                    jwks.get(*id).unwrap()
                }
            };

            let thumb_sha256 = jwk.thumb_sha256().unwrap();
            println!("thumb_sha256: {thumb_sha256:?}");
            let thumb = BASE64_URL_SAFE_NO_PAD.encode(thumb_sha256);

            let key_authz = KeyAuthorization::new(challenge.token.as_str(), thumb.as_str());
            println!("key_authz: {key_authz:?}");
            (challenge_type, key_authz)
        };

        match challenge_type {
            ChallengeType::Http(url) => Self::verify_http_challenge(&ctx, &url, id).await?,
            ChallengeType::Tls => Self::verify_tls_challenge(&ctx, id, &key_authz).await?,
        }

        let resp = Response::builder()
            .body(Body::from(serde_json::to_vec(&Empty).unwrap()))
            .unwrap();
        Ok(resp)
    }

    async fn verify_tls_challenge(
        ctx: &Context<State>,
        id: &str,
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
            let mut challenges = ctx.state().challenges.lock();
            let challenge = challenges.get_mut(id).unwrap();
            println!("checking challenge: {:?}", challenge);

            let cert = match data {
                DataEncoding::Der(items) => Err(OpaqueError::from_display("todo")),
                DataEncoding::DerStack(items) => Ok(items[0].clone()),
                DataEncoding::Pem(non_empty_string) => Err(OpaqueError::from_display("todo")),
            }?;

            println!(
                "expected extension content: {:?}",
                key_authz.digest().as_ref()
            );

            // let cert = CertificateDer::from(cert);

            if true {
                // challenge.status = super::proto::server::ChallengeStatus::Valid;
                return Err(OpaqueError::from_display("wrong key provided"));
            } else {
                return Err(OpaqueError::from_display("wrong key provided"));
            }
        };
        Ok(())
    }

    async fn verify_http_challenge(
        ctx: &Context<State>,
        url: &str,
        id: &str,
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
            let mut challenges = ctx.state().challenges.lock();
            let challenge = challenges.get_mut(id).unwrap();
            println!("checking challenge: {:?}", challenge);

            if data.contains(challenge.token.as_str()) {
                challenge.status = super::proto::server::ChallengeStatus::Valid;
            } else {
                return Err(OpaqueError::from_display("wrong key provided"));
            }
        };
        Ok(())
    }

    async fn parse_request<T: DeserializeOwned>(
        ctx: &Context<State>,
        req: Request,
    ) -> Result<DecodedJws<T>, OpaqueError> {
        let bytes = req.into_body().collect().await.unwrap().to_bytes();

        println!("bytes: {:?}", &bytes);
        let result = serde_json::from_slice::<Jws<T>>(&bytes).unwrap();
        // println!("resulting jws: {:?}", result);
        let key_id_store = &ctx.state().key_ids;
        let result = result.decode(key_id_store).unwrap();

        // Check if this is a valid request
        let received_nonce: u64 = result.protected().unwrap().nonce.unwrap().parse().unwrap();

        let mut nonces = ctx.state().nonces.lock();
        let nonce_idx = nonces.iter().position(|nonce| nonce == &received_nonce);

        if let Some(idx) = nonce_idx {
            nonces.remove(idx);
        } else {
            return Err(OpaqueError::from_display("invalid nonce provided"));
        };

        Ok(result)
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
