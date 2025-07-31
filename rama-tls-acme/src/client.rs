use crate::proto::common::{ProtectedHeaderAcme, ProtectedHeaderCrypto, ProtectedHeaderKey};

use super::proto::{
    client::FinalizePayload,
    client::{CreateAccountOptions, KeyAuthorization, NewOrderPayload},
    common::{self},
    server::REPLAY_NONCE_HEADER,
    server::{self, Problem},
};

use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use parking_lot::Mutex;
use rama_core::{
    Context,
    error::{ErrorContext, ErrorExt, OpaqueError},
    service::BoxService,
};
use rama_crypto::{
    dep::{
        pki_types::PrivatePkcs8KeyDer,
        rcgen::{self, Certificate},
    },
    jose::{EMPTY_PAYLOAD, EcdsaKey, Empty, Headers, JWSBuilder, NO_PAYLOAD, Signer},
};
use rama_http::{
    BodyExtractExt, Request, Response,
    dep::http_body_util::BodyExt,
    headers::{ContentType, HeaderMapExt, Location, RetryAfter, TypedHeader, UserAgent},
    service::client::HttpClientExt,
    utils::HeaderValueGetter,
};
use serde::Serialize;
use std::{
    borrow::Cow,
    time::{Duration, SystemTime},
};
use tokio::time::{sleep, timeout};

/// Acme client that will used for all acme operations
pub struct AcmeClient {
    https_client: AcmeHttpsClient,
    directory: server::Directory,
    nonce: Mutex<Option<String>>,
}

/// Alias for http client used by acme client
pub type AcmeHttpsClient = BoxService<(), Request, Response, OpaqueError>;

impl AcmeClient {
    /// Create a new acme [`AcmeClient`] for the given directory url and using the provided https client
    pub async fn new(
        directory_url: &str,
        https_client: AcmeHttpsClient,
    ) -> Result<Self, OpaqueError> {
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

    /// Create a new acme [`AcmeClient`] for the given [`AcmeProvider`] and using the provided https client
    pub async fn new_for_provider(
        provider: &AcmeProvider,
        https_client: AcmeHttpsClient,
    ) -> Result<Self, OpaqueError> {
        Self::new(provider.as_str(), https_client).await
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

        let nonce = Self::get_nonce_from_response(&response)?;
        Ok(nonce)
    }

    fn get_nonce_from_response(response: &Response) -> Result<String, OpaqueError> {
        Ok(response
            .header_str(REPLAY_NONCE_HEADER)
            .context("get nonce from headers")?
            .to_owned())
    }

    /// Create a new account with the given [`CreateAccountOptions`] options
    pub async fn create_account(
        &self,
        options: CreateAccountOptions,
    ) -> Result<Account, ClientError> {
        let key = EcdsaKey::generate().context("generate key for account")?;

        let do_request = async || {
            let response = self
                .post(&self.directory.new_account, Some(&options), &key)
                .await
                .context("create account request")?;

            let location: String = response
                .header_str(Location::name())
                .context("get location header")?
                .into();

            let account = parse_response::<server::Account>(response).await?;
            Ok((location, account))
        };

        let (location, account) = retry_bad_nonce(do_request).await?;

        Ok(Account {
            client: self,
            inner: account,
            credentials: AccountCredentials { key, kid: location },
        })
    }

    async fn post(
        &self,
        url: &str,
        payload: Option<&impl Serialize>,
        signer: &impl Signer,
    ) -> Result<Response, OpaqueError> {
        let mut builder = JWSBuilder::new();
        if let Some(payload) = payload {
            let payload = serde_json::to_vec(payload).context("serialize payload")?;
            builder.set_payload(payload);
        }

        let nonce = self.nonce().await?;
        builder.try_set_protected_headers(ProtectedHeaderAcme {
            nonce: Cow::Owned(nonce),
            url: Cow::Borrowed(url),
        })?;

        let jws = builder.build_flattened(signer)?;

        let request = self
            .https_client
            .post(url)
            .typed_header(UserAgent::from_static("rama-tls-acme"))
            .typed_header(ContentType::jose_json())
            .json(&jws);

        let response = request.send(Context::default()).await?;

        *self.nonce.lock() = Some(Self::get_nonce_from_response(&response)?);
        Ok(response)
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

    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::LetsEncrypt(url) | Self::ZeroSsl(url) | Self::GoogleTrustServices(url) => url,
        }
    }
}

/// Wrapped [`AcmeClient`] with account info
pub struct Account<'a> {
    client: &'a AcmeClient,
    credentials: AccountCredentials,
    inner: server::Account,
}

struct AccountCredentials {
    key: EcdsaKey,
    kid: String,
}

impl<'a> Account<'a> {
    #[must_use]
    /// Get (local) account state
    pub fn state(&self) -> &server::Account {
        &self.inner
    }

    /// Place a new [`Order`] using this [`Account`]
    pub async fn new_order(&self, new_order: NewOrderPayload) -> Result<Order, ClientError> {
        let do_request = async || {
            let response = self
                .post(&self.client.directory.new_order, Some(&new_order))
                .await?;

            let location: String = response
                .header_str(Location::name())
                .context("read location header")?
                .into();
            let order = parse_response::<server::Order>(response).await?;
            Ok((location, order))
        };

        let (location, order) = retry_bad_nonce(do_request).await?;

        Ok(Order {
            account: self,
            url: location,
            inner: order,
        })
    }

    /// Get a list of all the order urls, associated to this [`Account`]
    pub async fn orders(&self) -> Result<server::OrdersList, ClientError> {
        let do_request = async || {
            let response = self.post(&self.inner.orders, NO_PAYLOAD).await?;

            let orders = parse_response::<server::OrdersList>(response).await?;
            Ok(orders)
        };
        let orders = retry_bad_nonce(do_request).await?;

        Ok(orders)
    }

    /// Get [`Order`] which is stored on the given url
    pub async fn get_order(&self, order_url: &str) -> Result<Order, ClientError> {
        let do_request = async || {
            let response = self.post(order_url, NO_PAYLOAD).await?;

            let location: String = response
                .header_str(Location::name())
                .context("read location header")?
                .into();

            let order = parse_response::<server::Order>(response).await?;
            Ok((location, order))
        };
        let (location, order) = retry_bad_nonce(do_request).await?;

        Ok(Order {
            account: self,
            url: location,
            inner: order,
        })
    }

    async fn post(
        &self,
        url: &str,
        payload: Option<&impl Serialize>,
    ) -> Result<Response, OpaqueError> {
        self.client.post(url, payload, &self.credentials).await
    }
}

/// Wrapped [`Account`] with order info
pub struct Order<'a> {
    account: &'a Account<'a>,
    url: String,
    inner: server::Order,
}

impl Signer for AccountCredentials {
    type Signature = <EcdsaKey as Signer>::Signature;
    type Error = OpaqueError;

    fn set_headers(
        &self,
        protected_headers: &mut Headers,
        _unprotected_headers: &mut Headers,
    ) -> Result<(), Self::Error> {
        protected_headers.try_set_headers(ProtectedHeaderCrypto {
            alg: self.key.alg(),
            key: ProtectedHeaderKey::KeyID(Cow::Borrowed(&self.kid)),
        })?;
        Ok(())
    }

    fn sign(&self, payload: &str) -> Result<Self::Signature, Self::Error> {
        self.key.sign(payload)
    }
}

impl<'a> Order<'a> {
    #[must_use]
    /// Get (local) order state
    pub fn state(&self) -> &server::Order {
        &self.inner
    }

    #[must_use]
    /// Get reference to [`Account`] linked to this [`Order`]
    pub fn account(&self) -> &'a Account<'a> {
        self.account
    }

    /// Refresh [`Order`] state, and return it (and potential retry-after delay in case we want to refresh again)
    ///
    /// This also returns a duration which the server has requested to wait before calling this again if any
    pub async fn refresh(&mut self) -> Result<(&server::Order, Option<Duration>), ClientError> {
        let do_request = async || {
            let response = self.account.post(&self.url, NO_PAYLOAD).await?;
            let retry_after = get_retry_after_duration(&response);
            let order = parse_response::<server::Order>(response).await?;
            Ok((order, retry_after))
        };
        let result = retry_bad_nonce(do_request).await?;
        self.inner = result.0;

        Ok((&self.inner, result.1))
    }

    /// Get list of [`server::Authorization`]s linked to this [`Order`]
    pub async fn get_authorizations(&self) -> Result<Vec<server::Authorization>, ClientError> {
        let mut authz: Vec<server::Authorization> =
            Vec::with_capacity(self.inner.authorizations.len());

        for auth_url in self.inner.authorizations.iter() {
            let auth = self.get_authorization(auth_url.as_str()).await?;
            authz.push(auth);
        }

        Ok(authz)
    }

    /// Get [`server::Authorization`] which is stored on the given url
    pub async fn get_authorization(
        &self,
        authorization_url: &str,
    ) -> Result<server::Authorization, ClientError> {
        let do_request = async || {
            let response = self.account.post(authorization_url, NO_PAYLOAD).await?;

            let authorization = parse_response::<server::Authorization>(response).await?;
            Ok(authorization)
        };

        let authorization = retry_bad_nonce(do_request).await?;

        Ok(authorization)
    }

    /// Notify ACME server that the given challenge is ready
    ///
    /// Server will now try to verify this and we should keep polling the server
    /// with [`Self::poll_until_challenge_finished()`] to wait for the result.
    pub async fn notify_challenge_ready(
        &self,
        challenge: &server::Challenge,
    ) -> Result<(), ClientError> {
        let do_request = async || {
            let response = self.post(&challenge.url, EMPTY_PAYLOAD).await?;

            parse_response::<Empty>(response).await?;
            Ok(())
        };

        retry_bad_nonce(do_request).await?;

        Ok(())
    }

    /// Referesh the given challenge
    ///
    /// This returns a duration which the server has requested to wait before calling this again if any
    pub async fn refresh_challenge(
        &self,
        challenge: &mut server::Challenge,
    ) -> Result<Option<Duration>, ClientError> {
        let do_request = async || {
            let response = self
                .post(&challenge.url, NO_PAYLOAD)
                .await
                .context("refresh challenge request")?;

            let retry = get_retry_after_duration(&response);
            let challenge = parse_response::<server::Challenge>(response).await?;
            Ok((retry, challenge))
        };

        let (retry, new) = retry_bad_nonce(do_request).await?;
        *challenge = new;
        Ok(retry)
    }

    /// Poll until the challenge is finished (challenge.status == server::ChallengeStatus::Valid | server::ChallengeStatus::Invalid)
    pub async fn poll_until_challenge_finished(
        &self,
        challenge: &mut server::Challenge,
        timeout_duration: Duration,
    ) -> Result<(), ClientError> {
        timeout(timeout_duration, async {
            loop {
                let retry_wait = self.refresh_challenge(challenge).await?;

                if challenge.status == server::ChallengeStatus::Valid
                    || challenge.status == server::ChallengeStatus::Invalid
                {
                    break;
                }

                sleep(retry_wait.unwrap_or(Duration::from_millis(1000))).await;
            }

            Ok(())
        })
        .await
        .context("poll until challenge ready")?
    }

    /// Keep polling until all [`server::Authorization`]s have finished
    ///
    /// Note for this to work each [`server::Authorization`] needs to have one valid challenge
    pub async fn poll_until_all_authorizations_finished(
        &mut self,
        timeout_duration: Duration,
    ) -> Result<&server::Order, ClientError> {
        self.poll_until_status(timeout_duration, server::OrderStatus::Ready)
            .await
    }

    /// Finalize the order and request ACME server to generate a certifcate from the provided certificate params
    ///
    /// Note: for this to work all [`server::Authorization`]s need to have finished (order.status == server::OrderStatus::Ready)
    pub async fn finalize<T: AsRef<[u8]>>(
        &mut self,
        csr_der: T,
    ) -> Result<&server::Order, ClientError> {
        let csr = BASE64_URL_SAFE_NO_PAD.encode(csr_der.as_ref());
        let payload = FinalizePayload { csr };

        let do_request = async || {
            let response = self
                .account
                .post(&self.inner.finalize, Some(&payload))
                .await?;

            let order = parse_response::<server::Order>(response).await?;
            Ok(order)
        };

        self.inner = retry_bad_nonce(do_request).await?;

        Ok(&self.inner)
    }

    /// Keep polling until the certificate is ready (order.status == server::OrderStatus::Valid)
    pub async fn poll_until_certificate_ready(
        &mut self,
        timeout_duration: Duration,
    ) -> Result<&server::Order, ClientError> {
        self.poll_until_status(timeout_duration, server::OrderStatus::Valid)
            .await
    }

    /// Download the certificate generated by the server
    ///
    /// Note: for this to work the certificate needs to be ready (order.status == server::OrderStatus::Valid)
    pub async fn download_certificate(&self) -> Result<String, OpaqueError> {
        let certificate_url = self
            .inner
            .certificate
            .as_ref()
            .context("read stored certificate url")?;
        let response = self.account.post(certificate_url, NO_PAYLOAD).await?;

        let body = response.into_body();
        let bytes = body.collect().await.context("collect body")?.to_bytes();
        let certificate = str::from_utf8(bytes.as_ref())
            .context("parse response to pem")?
            .to_owned();

        Ok(certificate)
    }

    /// Keep polling until the order has reached the given status
    pub async fn poll_until_status(
        &mut self,
        timeout_duration: Duration,
        status: server::OrderStatus,
    ) -> Result<&server::Order, ClientError> {
        timeout(timeout_duration, async {
            loop {
                let (_, retry_wait) = self.refresh().await?;
                if self.inner.status == status {
                    break Ok::<_, ClientError>(());
                }
                if self.inner.status == server::OrderStatus::Invalid {
                    break Err(OpaqueError::from_display("Order is invalid state").into());
                }

                sleep(retry_wait.unwrap_or(Duration::from_millis(1000))).await;
            }
        })
        .await
        .context(format!("poll until status {status:?}"))??;

        Ok(&self.inner)
    }

    /// Create [`KeyAuthorization`] for the given challenge
    pub fn create_key_authorization(
        &self,
        challenge: &server::Challenge,
    ) -> Result<KeyAuthorization, OpaqueError> {
        KeyAuthorization::new(&challenge.token, &self.account.credentials.key.create_jwk())
    }

    /// Create challenge data need for tls-alpn challenge
    ///
    /// This function returns a private private key and certificate which a TLS
    /// backend should expose on port 443 (on the configured domain)
    pub fn create_tls_challenge_data(
        &self,
        challenge: &server::Challenge,
        identifier: &common::Identifier,
    ) -> Result<(PrivatePkcs8KeyDer<'_>, Certificate), OpaqueError> {
        let key_authz = self.create_key_authorization(challenge)?;

        let mut cert_params = rcgen::CertificateParams::new(vec![identifier.clone().into()])
            .context("create certificate params")?;
        cert_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        cert_params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(
            key_authz.digest().as_ref(),
        )];

        let key_pair = rcgen::KeyPair::generate().context("generate temporary keypair")?;
        let key_der = key_pair.serialize_der();

        let cert = cert_params
            .self_signed(&key_pair)
            .context("sign certificate params")?;
        let pk = PrivatePkcs8KeyDer::from(key_der);
        Ok((pk, cert))
    }

    async fn post(
        &self,
        url: &str,
        payload: Option<&impl Serialize>,
    ) -> Result<Response, OpaqueError> {
        self.account.post(url, payload).await
    }
}

async fn parse_response<T: serde::de::DeserializeOwned + Send + 'static>(
    response: Response,
) -> Result<T, ClientError> {
    let body = response.into_body();
    let bytes = body.collect().await.context("collect body")?.to_bytes();

    let result = serde_json::from_slice::<T>(&bytes);
    match result {
        Ok(result) => Ok(result),
        Err(err) => {
            let problem = serde_json::from_slice::<server::Problem>(&bytes);
            match problem {
                Ok(problem) => Err(problem.into()),
                Err(_err) => Err(err.context("parse problem response").into()),
            }
        }
    }
}

fn get_retry_after_duration(response: &Response) -> Option<Duration> {
    response
        .headers()
        .typed_get::<RetryAfter>()
        .and_then(|after| match after.after() {
            rama_http::headers::After::DateTime(http_date) => SystemTime::from(http_date)
                .duration_since(SystemTime::now())
                .ok(),
            rama_http::headers::After::Delay(seconds) => Some(Duration::from(seconds)),
        })
}

async fn retry_bad_nonce<F, Fut, T>(do_request: F) -> Result<T, ClientError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, ClientError>>,
{
    let result = do_request().await;
    if matches!(result, Err(ClientError::Problem(Problem::BadNonce(_)))) {
        do_request().await
    } else {
        result
    }
}

/// Error type which can be returned by the [`AcmeClient`]
pub enum ClientError {
    /// Normal [`OpaqueError`] like we use everywhere else
    OpaqueError(OpaqueError),
    /// Error returned by the acme server
    Problem(Problem),
}

impl std::fmt::Debug for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::OpaqueError(opaque_error) => write!(f, "opaque error: {opaque_error:?}"),
            Self::Problem(problem) => write!(f, "problem: {problem:?}"),
        }
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpaqueError(opaque_error) => write!(f, "opaque error: {opaque_error}"),
            Self::Problem(problem) => write!(f, "problem: {problem}"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OpaqueError(opaque_error) => opaque_error.source(),
            Self::Problem(problem) => problem.source(),
        }
    }
}

impl From<OpaqueError> for ClientError {
    fn from(value: OpaqueError) -> Self {
        Self::OpaqueError(value)
    }
}

impl From<Problem> for ClientError {
    fn from(value: Problem) -> Self {
        Self::Problem(value)
    }
}
