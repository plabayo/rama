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
    Context, Service,
    bytes::Bytes,
    error::{ErrorContext, OpaqueError},
    service::BoxService,
};
use rama_crypto::{
    dep::{
        pki_types::PrivatePkcs8KeyDer,
        rcgen::{self, Certificate},
        x509_parser::pem::Pem,
    },
    jose::{EMPTY_PAYLOAD, EcdsaKey, Empty, Headers, JWSBuilder, NO_PAYLOAD, Signer},
};
use rama_http::{
    BodyExtractExt, Request, Response,
    body::util::BodyExt,
    headers::{ContentType, HeaderMapExt, Location, RetryAfter, TypedHeader, UserAgent},
    response::Parts,
    service::client::HttpClientExt,
    utils::HeaderValueGetter,
};
use rama_utils::macros::generate_set_and_with;
use serde::Serialize;
use std::{
    borrow::Cow,
    time::{Duration, SystemTime},
};
use tokio::time::sleep;

#[derive(Debug)]
/// Acme client that will used for all acme operations
pub struct AcmeClient {
    https_client: BoxService<Request, Response, OpaqueError>,
    directory: server::Directory,
    nonce: Mutex<Option<String>>,
    default_retry_duration: Duration,
}

impl AcmeClient {
    /// Create a new acme [`AcmeClient`] for the given directory url and using the provided https client
    pub async fn new<S>(
        directory_url: &str,
        https_client: S,
        ctx: Context,
    ) -> Result<Self, OpaqueError>
    where
        S: Service<Request, Response = Response, Error = OpaqueError>,
    {
        let https_client = https_client.boxed();

        let directory = https_client
            .get(directory_url)
            .send(ctx)
            .await?
            .try_into_json::<server::Directory>()
            .await?;

        Ok(Self {
            https_client,
            directory,
            nonce: Mutex::new(None),
            default_retry_duration: Duration::from_secs(1),
        })
    }

    /// Create a new acme [`AcmeClient`] for the given [`AcmeProvider`] and using the provided https client
    pub async fn new_for_provider<S>(
        provider: &AcmeProvider,
        https_client: S,
        ctx: Context,
    ) -> Result<Self, OpaqueError>
    where
        S: Service<Request, Response = Response, Error = OpaqueError>,
    {
        Self::new(provider.as_directory_url(), https_client, ctx).await
    }

    generate_set_and_with! {
        /// Set the default retry duration in case the ACME server doesn't include a [`RetryAfter`] header
        pub fn default_retry_duration(mut self, duration: Duration) -> Self {
            self.default_retry_duration = duration;
            self
        }
    }

    /// Fetch a nonce for making requests
    pub async fn fetch_nonce(&self, ctx: Context) -> Result<String, OpaqueError> {
        let response = self
            .https_client
            .head(&self.directory.new_nonce)
            .send(ctx)
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

    /// Load acme account that is associated with the given [`EcdsaKey`]. If no account
    /// exists yet a new account will be created using the given [`CreateAccountOptions`].
    ///
    /// If you don't wont this double functionality use: [`Self::create_account`], or
    /// [`Self::load_account`] instead.
    pub async fn create_or_load_account(
        &self,
        ctx: Context,
        account_key: EcdsaKey,
        options: CreateAccountOptions,
    ) -> Result<Account<'_>, ClientError> {
        self.create_or_load_account_inner(
            ctx,
            account_key,
            options,
            CreateAccountMode::CreateOrLoad,
        )
        .await
    }

    /// Create a new acme account
    ///
    /// Internally this will generate a new [`EcdsaKey`] which will be associated with this account
    pub async fn create_account(
        &self,
        ctx: Context,
        options: CreateAccountOptions,
    ) -> Result<Account<'_>, ClientError> {
        let account_key = EcdsaKey::generate().expect("generate key for account");
        self.create_or_load_account_inner(ctx, account_key, options, CreateAccountMode::Create)
            .await
    }

    /// Create a new acme account using the provided [`EcdsaKey`]
    pub async fn create_account_with_key(
        &self,
        ctx: Context,
        account_key: EcdsaKey,
        options: CreateAccountOptions,
    ) -> Result<Account<'_>, ClientError> {
        self.create_or_load_account_inner(ctx, account_key, options, CreateAccountMode::Create)
            .await
    }

    /// Load acme account which is associated with the given [`EcdsaKey`]
    pub async fn load_account(
        &self,
        ctx: Context,
        account_key: EcdsaKey,
    ) -> Result<Account<'_>, ClientError> {
        self.create_or_load_account_inner(
            ctx,
            account_key,
            CreateAccountOptions {
                only_return_existing: Some(true),
                ..CreateAccountOptions::default()
            },
            CreateAccountMode::Load,
        )
        .await
    }

    async fn create_or_load_account_inner(
        &self,
        ctx: Context,
        account_key: EcdsaKey,
        options: CreateAccountOptions,
        mode: CreateAccountMode,
    ) -> Result<Account<'_>, ClientError> {
        let do_request = async || {
            let ctx = ctx.clone();

            let response = self
                .post(
                    ctx,
                    &self.directory.new_account,
                    Some(&options),
                    &account_key,
                )
                .await
                .context("create account request")?;

            if mode == CreateAccountMode::Create && response.status() == 200 {
                return Err(OpaqueError::from_display(
                    "Tried creating new account, but account already exists",
                )
                .into());
            }

            let location = response
                .header_str(Location::name())
                .map(|location| location.to_owned())
                .context("get location header");

            let account = parse_response::<server::Account>(response).await?;
            // Do this after parsing response, in case we have a failure it will also parse that
            // into a proper Problem error
            let location = location?;

            Ok((location, account))
        };

        let (location, account) = retry_bad_nonce(do_request).await?;

        Ok(Account {
            client: self,
            inner: account,
            credentials: AccountCredentials {
                key: account_key,
                kid: location,
            },
        })
    }

    async fn post(
        &self,
        ctx: Context,
        url: &str,
        payload: Option<&impl Serialize>,
        signer: &impl Signer,
    ) -> Result<Response, ClientError> {
        let mut builder = JWSBuilder::new();
        if let Some(payload) = payload {
            let payload = serde_json::to_vec(payload).context("serialize payload")?;
            builder.set_payload(payload);
        }

        let nonce = if let Some(nonce) = self.nonce.lock().take() {
            nonce
        } else {
            self.fetch_nonce(ctx.clone()).await?
        };

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

        let response = request.send(ctx).await?;

        match Self::get_nonce_from_response(&response) {
            Ok(nonce) => {
                *self.nonce.lock() = Some(nonce);
            }
            Err(_) => return Err(response_into_error(response).await),
        }

        Ok(response)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CreateAccountMode {
    Create,
    Load,
    CreateOrLoad,
}

#[derive(Clone, Debug)]
/// Enum of popular acme providers and their directory url
pub enum AcmeProvider {
    LetsEncryptProduction,
    LetsEncryptStaging,
    ZeroSslProduction,
    GoogleTrustServicesProduction,
    GoogleTrustServicesStaging,
}

impl AcmeProvider {
    #[must_use]
    pub fn as_directory_url(&self) -> &str {
        match self {
            Self::LetsEncryptProduction => "https://acme-v02.api.letsencrypt.org/directory",
            Self::LetsEncryptStaging => "https://acme-staging-v02.api.letsencrypt.org/directory",
            Self::ZeroSslProduction => "https://acme.zerossl.com/v2/DV90",
            Self::GoogleTrustServicesProduction => "https://dv.acme-v02.api.pki.goog/directory",
            Self::GoogleTrustServicesStaging => "https://dv.acme-v02.test-api.pki.goog/directory",
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

    #[must_use]
    /// Get reference to [`EcdsaKey`] used by this [`Account`]
    pub fn key(&self) -> &EcdsaKey {
        &self.credentials.key
    }

    /// Place a new [`Order`] using this [`Account`]
    pub async fn new_order(
        &self,
        ctx: Context,
        new_order: NewOrderPayload,
    ) -> Result<Order<'_>, ClientError> {
        let do_request = async || {
            let ctx = ctx.clone();
            let response = self
                .post(ctx, &self.client.directory.new_order, Some(&new_order))
                .await?;

            let location = response
                .header_str(Location::name())
                .map(|location| location.to_owned())
                .context("get location header");

            let order = parse_response::<server::Order>(response).await?;
            // Do this after parsing response, in case we have a failure it will also parse that
            // into a proper Problem error
            let location = location?;

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
    pub async fn orders(&self, ctx: Context) -> Result<server::OrdersList, ClientError> {
        let do_request = async || {
            let ctx = ctx.clone();
            let response = self
                .post(
                    ctx,
                    self.inner.orders.as_deref().unwrap_or_default(),
                    NO_PAYLOAD,
                )
                .await?;

            let orders = parse_response::<server::OrdersList>(response).await?;
            Ok(orders)
        };
        let orders = retry_bad_nonce(do_request).await?;

        Ok(orders)
    }

    /// Get [`Order`] which is stored on the given url
    pub async fn get_order(&self, ctx: Context, order_url: &str) -> Result<Order<'_>, ClientError> {
        let do_request = async || {
            let ctx = ctx.clone();
            let response = self.post(ctx, order_url, NO_PAYLOAD).await?;

            let location = response
                .header_str(Location::name())
                .map(|location| location.to_owned())
                .context("get location header");

            let order = parse_response::<server::Order>(response).await?;

            // Do this after parsing response, in case we have a failure it will also parse that
            // into a proper Problem error
            let location = location?;

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
        ctx: Context,
        url: &str,
        payload: Option<&impl Serialize>,
    ) -> Result<Response, ClientError> {
        self.client.post(ctx, url, payload, &self.credentials).await
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
    pub async fn refresh(
        &mut self,
        ctx: Context,
    ) -> Result<(&server::Order, Option<Duration>), ClientError> {
        let do_request = async || {
            let ctx = ctx.clone();
            let response = self.account.post(ctx, &self.url, NO_PAYLOAD).await?;
            let retry_after = get_retry_after_duration(&response);
            let order = parse_response::<server::Order>(response).await?;
            Ok((order, retry_after))
        };
        let result = retry_bad_nonce(do_request).await?;
        self.inner = result.0;

        Ok((&self.inner, result.1))
    }

    /// Get list of [`server::Authorization`]s linked to this [`Order`]
    pub async fn get_authorizations(
        &self,
        ctx: Context,
    ) -> Result<Vec<server::Authorization>, ClientError> {
        let mut authz: Vec<server::Authorization> =
            Vec::with_capacity(self.inner.authorizations.len());

        for auth_url in self.inner.authorizations.iter() {
            let auth = self
                .get_authorization(ctx.clone(), auth_url.as_str())
                .await?;
            authz.push(auth);
        }

        Ok(authz)
    }

    /// Get [`server::Authorization`] which is stored on the given url
    pub async fn get_authorization(
        &self,
        ctx: Context,
        authorization_url: &str,
    ) -> Result<server::Authorization, ClientError> {
        let do_request = async || {
            let ctx = ctx.clone();
            let response = self
                .account
                .post(ctx, authorization_url, NO_PAYLOAD)
                .await?;

            let authorization = parse_response::<server::Authorization>(response).await?;
            Ok(authorization)
        };

        let authorization = retry_bad_nonce(do_request).await?;

        Ok(authorization)
    }

    /// Finish the current challenge
    ///
    /// This does two things behind the scene
    /// 1. Notify acme server that challenge is ready and should be verified by the server ([`Self::notify_challenge_ready`])
    /// 2. Polls the acme server until the server has verified this challenge and has updated its internal status ([`Self::wait_until_challenge_finished`])
    ///
    /// Note that this (1) has the pre-condition that your challenge is indeed ready:
    /// - for http/tls this means your server is ready to serve the challenge to incoming  clients
    /// - for dns this means your record exists and has the correct value
    ///
    /// An error (underlying http 403) is returned in case the challenge is not ready.
    pub async fn finish_challenge(
        &self,
        ctx: Context,
        challenge: &mut server::Challenge,
    ) -> Result<(), ClientError> {
        self.notify_challenge_ready(ctx.clone(), challenge).await?;
        self.wait_until_challenge_finished(ctx, challenge).await
    }

    /// Notify ACME server that the given challenge is ready
    ///
    /// Server will now try to verify this and we should keep polling the server
    /// with [`Self::wait_until_challenge_finished()`] to wait for the result.
    pub async fn notify_challenge_ready(
        &self,
        ctx: Context,
        challenge: &server::Challenge,
    ) -> Result<(), ClientError> {
        let do_request = async || {
            let ctx = ctx.clone();
            let response = self.post(ctx, &challenge.url, EMPTY_PAYLOAD).await?;

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
        ctx: Context,
        challenge: &mut server::Challenge,
    ) -> Result<Option<Duration>, ClientError> {
        let do_request = async || {
            let ctx = ctx.clone();
            let response = self
                .post(ctx, &challenge.url, NO_PAYLOAD)
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

    /// Poll acme server until the challenge is finished (challenge.status == server::ChallengeStatus::Valid | server::ChallengeStatus::Invalid)
    pub async fn wait_until_challenge_finished(
        &self,
        ctx: Context,
        challenge: &mut server::Challenge,
    ) -> Result<(), ClientError> {
        loop {
            let retry_wait = self.refresh_challenge(ctx.clone(), challenge).await?;

            match challenge.status {
                server::ChallengeStatus::Pending | server::ChallengeStatus::Processing => (),
                server::ChallengeStatus::Valid => return Ok(()),
                server::ChallengeStatus::Invalid => {
                    return Err(
                        OpaqueError::from_display("challenge is detected as invalid").into(),
                    );
                }
            }

            sleep(retry_wait.unwrap_or(self.account.client.default_retry_duration)).await;
        }
    }

    /// Keep polling acme server until all [`server::Authorization`]s have finished
    ///
    /// Note for this to work each [`server::Authorization`] needs to have one valid challenge
    pub async fn wait_until_all_authorizations_finished(
        &mut self,
        ctx: Context,
    ) -> Result<&server::Order, ClientError> {
        self.wait_until_status(ctx, server::OrderStatus::Ready)
            .await
    }

    /// Finalize the order and request ACME server to generate a certifcate from the provided certificate params
    ///
    /// Note: for this to work all [`server::Authorization`]s need to have finished (order.status == server::OrderStatus::Ready)
    pub async fn finalize<T: AsRef<[u8]>>(
        &mut self,
        ctx: Context,
        csr_der: T,
    ) -> Result<&server::Order, ClientError> {
        let csr = BASE64_URL_SAFE_NO_PAD.encode(csr_der.as_ref());
        let payload = FinalizePayload { csr };

        let do_request = async || {
            let ctx = ctx.clone();
            let response = self
                .account
                .post(ctx, &self.inner.finalize, Some(&payload))
                .await?;

            let order = parse_response::<server::Order>(response).await?;
            Ok(order)
        };

        self.inner = retry_bad_nonce(do_request).await?;

        Ok(&self.inner)
    }

    /// Keep polling acme server until the certificate is ready (order.status == server::OrderStatus::Valid)
    pub async fn wait_until_certificate_ready(
        &mut self,
        ctx: Context,
    ) -> Result<&server::Order, ClientError> {
        self.wait_until_status(ctx, server::OrderStatus::Valid)
            .await
    }

    /// Download the certificate generated by the server
    ///
    /// Note: for this to work the certificate needs to be ready (order.status == server::OrderStatus::Valid).
    /// Use [`Self::download_certificate`] instead to also wait for this correct status before downloading.
    pub async fn download_certificate_no_checks_as_pem_stack(
        &self,
        ctx: Context,
    ) -> Result<Vec<Pem>, ClientError> {
        let bytes = self.download_certificate_no_checks(ctx).await?;

        let certificate = str::from_utf8(bytes.as_ref())
            .context("parse response to pem")?
            .to_owned();

        let pems = Pem::iter_from_buffer(certificate.as_bytes())
            .collect::<Result<Vec<Pem>, _>>()
            .context("failed to parse pem")?;

        Ok(pems)
    }

    /// Download the certificate generated by the server
    ///
    /// Note: for this to work the certificate needs to be ready (order.status == server::OrderStatus::Valid).
    /// Use [`Self::download_certificate`] instead to also wait for this correct status before downloading.
    pub async fn download_certificate_no_checks(&self, ctx: Context) -> Result<Bytes, ClientError> {
        let certificate_url = self
            .inner
            .certificate
            .as_ref()
            .context("read stored certificate url")?;
        let response = self.account.post(ctx, certificate_url, NO_PAYLOAD).await?;

        let body = response.into_body();
        let bytes = body.collect().await.context("collect body")?.to_bytes();

        Ok(bytes)
    }

    /// Wait until certificate is ready and then download it
    ///
    /// To directly download the certificate without waiting for the correct status
    /// use [`Self::download_certificate_no_checks`] instead
    pub async fn download_certificate(&mut self, ctx: Context) -> Result<Bytes, ClientError> {
        self.wait_until_certificate_ready(ctx.clone()).await?;
        self.download_certificate_no_checks(ctx).await
    }

    /// Wait until certificate is ready and then download it
    ///
    /// To directly download the certificate without waiting for the correct status
    /// use [`Self::download_certificate_no_checks`] instead
    pub async fn download_certificate_as_pem_stack(
        &mut self,
        ctx: Context,
    ) -> Result<Vec<Pem>, ClientError> {
        self.wait_until_certificate_ready(ctx.clone()).await?;
        self.download_certificate_no_checks_as_pem_stack(ctx).await
    }

    /// Keep polling until the order has reached the given status
    pub async fn wait_until_status(
        &mut self,
        ctx: Context,
        status: server::OrderStatus,
    ) -> Result<&server::Order, ClientError> {
        loop {
            let (_, retry_wait) = self.refresh(ctx.clone()).await?;
            if self.inner.status == status {
                return Ok::<_, ClientError>(&self.inner);
            }
            if self.inner.status == server::OrderStatus::Invalid {
                return Err(OpaqueError::from_display("Order is invalid state").into());
            }

            sleep(retry_wait.unwrap_or(self.account.client.default_retry_duration)).await;
        }
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
        let key_authorization = self.create_key_authorization(challenge)?;

        let mut cert_params = rcgen::CertificateParams::new(vec![identifier.clone().into()])
            .context("create certificate params")?;
        cert_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        cert_params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(
            key_authorization.digest().as_ref(),
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
        ctx: Context,
        url: &str,
        payload: Option<&impl Serialize>,
    ) -> Result<Response, ClientError> {
        self.account.post(ctx, url, payload).await
    }
}

async fn parse_response<T: serde::de::DeserializeOwned + Send + 'static>(
    response: Response,
) -> Result<T, ClientError> {
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.context("collect body")?.to_bytes();

    let result = serde_json::from_slice::<T>(&bytes);
    match result {
        Ok(result) => Ok(result),
        Err(_) => Err(bytes_into_error(parts, bytes).await),
    }
}

async fn response_into_error(response: Response) -> ClientError {
    let (parts, body) = response.into_parts();
    match body.collect().await.context("collect body") {
        Ok(bytes) => bytes_into_error(parts, bytes.to_bytes()).await,
        Err(err) => err.into(),
    }
}

async fn bytes_into_error(response_parts: Parts, bytes: Bytes) -> ClientError {
    let problem = serde_json::from_slice::<server::Problem>(&bytes);
    if let Ok(problem) = problem {
        problem.into()
    } else {
        let body_str = bytes
            .try_into_string()
            .await
            .unwrap_or_else(|err| format!("body collect err post-error: {err}"));
        OpaqueError::from_display(format!(
            "Unexpected problem response with status code {}: {}",
            response_parts.status, body_str
        ))
        .into()
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
    /// Error returned by the acme server
    Problem(Problem),
    /// Normal [`OpaqueError`] like we use everywhere else
    Other(OpaqueError),
}

impl std::fmt::Debug for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Other(opaque_error) => write!(f, "opaque error: {opaque_error:?}"),
            Self::Problem(problem) => write!(f, "problem: {problem:?}"),
        }
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Other(opaque_error) => write!(f, "opaque error: {opaque_error}"),
            Self::Problem(problem) => write!(f, "problem: {problem}"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Other(opaque_error) => opaque_error.source(),
            Self::Problem(problem) => problem.source(),
        }
    }
}

impl From<OpaqueError> for ClientError {
    fn from(value: OpaqueError) -> Self {
        Self::Other(value)
    }
}

impl From<Problem> for ClientError {
    fn from(value: Problem) -> Self {
        Self::Problem(value)
    }
}
