use super::proto::{
    client::{
        CreateAccountOptions, Jws, Key, KeyAuthorization, NewOrderPayload, ProtectedHeader,
        ProtectedHeaderKey, Signer,
    },
    common::{EMPTY_PAYLOAD, NO_PAYLOAD},
    server::{self, Problem},
};
use crate::{
    Context, Service,
    error::{BoxError, ErrorContext, ErrorExt, OpaqueError},
    http::{
        Body, BodyExtractExt, Request, Response, client::EasyHttpWebClient,
        dep::http_body_util::BodyExt, service::client::HttpClientExt, utils::HeaderValueGetter,
    },
    service::BoxService,
    tls::{
        acme::proto::{
            common::Empty,
            server::{LOCATION_HEADER, REPLAY_NONCE_HEADER},
        },
        rustls::dep::{
            pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
            rcgen::{self},
            rustls::{crypto::aws_lc_rs::sign::any_ecdsa_type, sign::CertifiedKey},
        },
    },
};

use parking_lot::Mutex;
use serde::Serialize;
use std::time::Duration;
use tokio::time::{sleep, timeout};

// TODO user_agent: rame version
// TODO accept_language: en
// TODO binary base64url (trailing = stripped)
// TODO body inside jws acc private key, flattened serialisation
//      protected header: alg, nonce, url, jwk|kid
// signature es256 or EdDsa (Ed25519 variant)
// TODO content_type: application/jose+json

// POST as get = get -> post ''

// GET possible for directory and newNonce

/*
Happy path
- get directory
- get nonce head
- create acc
- submit order
- fetch challenges post as get
- respond to challenges
- poll status
- finalize order
- poll status
- download cert
*/

/// Acme client that will used for all acme operations
pub struct AcmeClient {
    https_client: AcmeHttpsClient,
    directory: server::Directory,
    nonce: Mutex<Option<String>>,
}

/// Alias for http client used by acme client
type AcmeHttpsClient = BoxService<(), Request, Response, OpaqueError>;

impl AcmeClient {
    /// Create a new acme [`Client`] for the given directory url and using the default https client
    pub async fn new(directory_url: &str) -> Result<AcmeClient, OpaqueError> {
        let https_client = EasyHttpWebClient::default().boxed();
        Self::new_with_https_client(directory_url, https_client).await
    }

    /// Create a new acme [`Client`] for the given acme provider and using the default https client
    pub async fn new_for_provider(provider: &AcmeProvider) -> Result<AcmeClient, OpaqueError> {
        let https_client = EasyHttpWebClient::default().boxed();
        Self::new_with_https_client(provider.as_str(), https_client).await
    }

    /// Create a new acme [`Client`] for the given directory url and using the provided https client
    pub async fn new_with_https_client(
        directory_url: &str,
        https_client: AcmeHttpsClient,
    ) -> Result<AcmeClient, OpaqueError> {
        let directory = https_client
            .get(directory_url)
            .send(Context::default())
            .await?
            .try_into_json::<server::Directory>()
            .await?;

        Ok(Self {
            https_client,
            directory,
            nonce: Mutex::new(None),
        })
    }

    /// Create a new acme [`Client`] for the given acme provider and using the provided https client
    pub async fn new_for_provider_with_https_client(
        provider: &AcmeProvider,
    ) -> Result<AcmeClient, OpaqueError> {
        let https_client = EasyHttpWebClient::default().boxed();
        Self::new_with_https_client(provider.as_str(), https_client).await
    }

    /// Get a nonce for making requests, if no nonce from a previous request is
    /// available this function will try to fetch a new one
    pub async fn nonce(&self) -> Result<String, OpaqueError> {
        if let Some(nonce) = self.nonce.lock().take() {
            return Ok(nonce);
        }

        let response = self
            .https_client
            .head(&self.directory.new_nonce)
            .send(Context::default())
            .await
            .context("fetch new nonce")?;

        println!("response: {:?}", response);

        let nonce = Self::get_nonce_from_response(&response)?;
        Ok(nonce)
    }

    fn get_nonce_from_response(response: &Response<Body>) -> Result<String, OpaqueError> {
        Ok(response
            .header_str(REPLAY_NONCE_HEADER)
            .context("get nonce from headers")?
            .to_owned())
    }

    pub async fn create_account(
        &self,
        options: CreateAccountOptions,
    ) -> Result<Account, OpaqueError> {
        let (key, _) = Key::generate().context("generate key for account")?;

        let response = self
            .post::<server::Account>(&self.directory.new_account, Some(&options), &key)
            .await
            .context("create account request")?;

        let location: String = response.header_str(LOCATION_HEADER).unwrap().into();
        println!("Status code: {}", response.status());
        let account = response.into_body().context("accound info")?;

        Ok(Account {
            client: self,
            inner: account,
            credentials: AccountCredentials {
                key: key,
                kid: location,
            },
        })
    }

    async fn post<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        url: &str,
        payload: Option<&impl Serialize>,
        signer: &impl Signer,
    ) -> Result<Response<Result<T, Problem>>, OpaqueError> {
        loop {
            let nonce = self.nonce().await?;
            let protected_header = signer.protected_header(Some(&nonce), url);

            let jws = Jws::new(payload, &protected_header, signer).context("create jws payload")?;
            // println!("jose_json: {:?}", jose_json);
            let request = self
                .https_client
                .post(url)
                .header("content-type", "application/jose+json")
                // TODO use const
                .header("user-agent", "rama")
                .json(&jws);

            // println!("Request: {:?}", request);
            let response = request.send(Context::default()).await?;

            *self.nonce.lock() = Some(Self::get_nonce_from_response(&response)?);

            let response = Self::parse_response::<T>(response).await.unwrap();
            match response.body() {
                Ok(_) => return Ok(response),
                Err(problem) => {
                    if let server::Problem::BadNonce(_) = problem {
                        continue;
                    }
                    return Ok(response);
                }
            }
        }
    }

    async fn parse_response<T: serde::de::DeserializeOwned + Send + 'static>(
        response: Response,
    ) -> Result<Response<Result<T, Problem>>, OpaqueError> {
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();

        let result = serde_json::from_slice::<T>(&bytes);
        match result {
            Ok(result) => Ok(Response::from_parts(parts, Ok(result))),
            Err(err) => {
                let problem = serde_json::from_slice::<server::Problem>(&bytes);
                match problem {
                    Ok(problem) => Ok(Response::from_parts(parts, Err(problem))),
                    Err(_err) => Err(err.context("parse problem response")),
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
/// Enum of popular acme providers and their directory url
pub enum AcmeProvider {
    LetsEncrypt(&'static str),
    ZeroSsl(&'static str),
    GoogleTrustServices(&'static str),
}

impl AcmeProvider {
    pub const LETSENCRYPT_PRODUCTION: Self =
        Self::LetsEncrypt("https://acme-v01.api.letsencrypt.org/directory");

    pub const LETSENCRYPT_STAGING: Self =
        Self::LetsEncrypt("https://acme-staging-v02.api.letsencrypt.org/directory");

    pub const ZERO_SSL_PRODUCTION: Self = Self::ZeroSsl("https://acme.zerossl.com/v2/DV90");

    pub const GOOGLE_TRUST_SERVICES_PRODUCTION: Self =
        Self::GoogleTrustServices("https://dv.acme-v02.api.pki.goog/directory");

    pub const GOOGLE_TRUST_SERVICES_STAGING: Self =
        Self::GoogleTrustServices("https://dv.acme-v02.test-api.pki.goog/directory");

    pub fn as_str(&self) -> &str {
        match self {
            AcmeProvider::LetsEncrypt(url) => url,
            AcmeProvider::ZeroSsl(url) => url,
            AcmeProvider::GoogleTrustServices(url) => url,
        }
    }
}

pub struct Account<'a> {
    client: &'a AcmeClient,
    credentials: AccountCredentials,
    inner: server::Account,
}

struct AccountCredentials {
    key: Key,
    kid: String,
}

impl<'a> Account<'a> {
    pub fn state(&self) -> &server::Account {
        &self.inner
    }

    pub async fn new_order(&self, new_order: NewOrderPayload) -> Result<Order, OpaqueError> {
        let response = self
            .post::<server::Order>(&self.client.directory.new_order, Some(&new_order))
            .await?;

        let location: String = response.header_str(LOCATION_HEADER).unwrap().into();
        let order = response.into_body().context("create order info")?;
        Ok(Order {
            account: self,
            url: location,
            inner: order,
        })
    }

    pub async fn orders(&self) -> Result<server::OrdersList, OpaqueError> {
        let response = self
            .post::<server::OrdersList>(&self.inner.orders, NO_PAYLOAD)
            .await?;

        let orders = response.into_body().context("open order list")?;
        Ok(orders)
    }

    pub async fn get_order(&self, order_url: &str) -> Result<Order, OpaqueError> {
        let response = self.post::<server::Order>(&order_url, NO_PAYLOAD).await?;

        let location: String = response.header_str(LOCATION_HEADER).unwrap().into();

        let order = response.into_body().context("order info")?;
        Ok(Order {
            account: self,
            url: location,
            inner: order,
        })
    }

    async fn post<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        url: &str,
        payload: Option<&impl Serialize>,
    ) -> Result<Response<Result<T, Problem>>, OpaqueError> {
        self.client.post::<T>(url, payload, &self.credentials).await
    }
}

pub struct Order<'a> {
    account: &'a Account<'a>,
    url: String,
    inner: server::Order,
}

impl Signer for AccountCredentials {
    type Signature = <Key as Signer>::Signature;

    fn protected_header<'n, 'u: 'n, 's: 'u>(
        &'s self,
        nonce: Option<&'n str>,
        url: &'u str,
    ) -> ProtectedHeader<'n> {
        ProtectedHeader {
            alg: self.key.signing_algorithm,
            key: ProtectedHeaderKey::KeyID(&self.kid),
            nonce,
            url,
        }
    }

    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, BoxError> {
        self.key.sign(payload)
    }
}

impl<'a> Order<'a> {
    pub fn state(&self) -> &server::Order {
        &self.inner
    }

    pub fn account(&self) -> &'a Account<'a> {
        self.account
    }

    pub async fn refresh(&mut self) -> Result<&server::Order, OpaqueError> {
        let response = self
            .account
            .post::<server::Order>(&self.url, NO_PAYLOAD)
            .await?;
        self.inner = response.into_body().context("order info")?;
        Ok(&self.inner)
    }

    pub async fn get_authorizations(&self) -> Result<Vec<server::Authorization>, OpaqueError> {
        let mut authz: Vec<server::Authorization> =
            Vec::with_capacity(self.inner.authorizations.len());
        for auth_url in self.inner.authorizations.iter() {
            let auth = self.get_authorization(auth_url.as_str()).await?;
            authz.push(auth);
        }

        Ok(authz)
    }

    pub async fn get_authorization(
        &self,
        authorization_url: &str,
    ) -> Result<server::Authorization, OpaqueError> {
        println!("{}", authorization_url);
        let response = self
            .account
            .post::<server::Authorization>(&authorization_url, NO_PAYLOAD)
            .await?;

        let authorization = response.into_body().context("authorization info")?;
        Ok(authorization)
    }

    pub async fn poll_until_all_authorizations_finished(
        &mut self,
        timeout_duration: Duration,
    ) -> Result<&server::Order, OpaqueError> {
        timeout(timeout_duration, async {
            loop {
                self.refresh().await.unwrap();
                if self.inner.status != server::OrderStatus::Pending {
                    break;
                }
                // TODO use retry header
                sleep(Duration::from_millis(1000)).await;
            }
        })
        .await
        .context("poll until complete")?;

        Ok(&self.inner)
    }

    pub async fn refresh_challenge(
        &self,
        challenge: &mut server::Challenge,
    ) -> Result<(), OpaqueError> {
        let response = self
            .post::<server::Challenge>(&challenge.url, NO_PAYLOAD)
            .await
            .unwrap();

        *challenge = response.into_body().context("challenge info")?;
        Ok(())
    }

    pub async fn notify_challenge_ready(
        &self,
        challenge: &server::Challenge,
    ) -> Result<(), OpaqueError> {
        println!("sending: {:?}", EMPTY_PAYLOAD);
        self.post::<Empty>(&challenge.url, EMPTY_PAYLOAD)
            .await?
            .into_body()
            .context("empty confirmation")?;

        Ok(())
    }

    pub fn create_key_authorization(&self, challenge: &server::Challenge) -> KeyAuthorization {
        KeyAuthorization::new(&challenge.token, &self.account.credentials.key.thumb)
    }

    // TODO boring variants

    pub fn create_rustls_cert_for_acme_authz<'b>(
        &self,
        authorization: &'b server::Authorization,
    ) -> Result<(&'b server::Challenge, CertifiedKey), OpaqueError> {
        let challenge = authorization
            .challenges
            .iter()
            .find(|challenge| challenge.r#type == server::ChallengeType::TlsAlpn01)
            .unwrap();

        let key_authz = self.create_key_authorization(challenge);

        let mut cert_params =
            rcgen::CertificateParams::new(vec![authorization.identifier.clone().into()]).unwrap();
        cert_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        cert_params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(
            key_authz.digest().as_ref(),
        )];

        println!("key_authz: {key_authz:?}");

        println!("cert_params: {:?}", cert_params);

        let key_pair = rcgen::KeyPair::generate().unwrap();
        let key_der = key_pair.serialize_der();

        let cert = cert_params.self_signed(&key_pair).unwrap();
        println!("{:?}", cert.pem());
        // let cert_der = cert.der();

        let pk = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

        let cert_key = CertifiedKey::new(
            vec![cert.der().clone()],
            any_ecdsa_type(&pk).unwrap().into(),
        );

        Ok((challenge, cert_key))
    }

    pub async fn poll_until_challenge_finished(
        &self,
        challenge: &mut server::Challenge,
        timeout_duration: Duration,
    ) -> Result<(), OpaqueError> {
        timeout(timeout_duration, async {
            loop {
                self.refresh_challenge(challenge).await?;
                println!("{challenge:?}");

                if challenge.status == server::ChallengeStatus::Valid
                    || challenge.status == server::ChallengeStatus::Invalid
                {
                    break;
                }

                // TODO use retry after header
                sleep(Duration::from_millis(1000)).await;
            }

            Ok(())
        })
        .await
        .context("poll until challenge ready")?
    }

    async fn post<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        url: &str,
        payload: Option<&impl Serialize>,
    ) -> Result<Response<Result<T, Problem>>, OpaqueError> {
        self.account.post::<T>(url, payload).await
    }
}
