use rama::{
    error::OpaqueError,
    http::proto::h1::Http1HeaderMap,
    net::tls::client::ClientHello,
    ua::{Http1Settings, Http2Settings},
};

#[derive(Debug, Clone)]
pub(super) struct Storage;

impl Storage {
    pub(super) async fn new(pg_url: &str) -> Result<Self, OpaqueError> {
        tracing::info!("create new storage with PG URL: {}", pg_url);
        Ok(Self)
    }
}

impl Storage {
    pub(super) async fn store_h1_settings(
        &self,
        ua: String,
        settings: Http1Settings,
    ) -> Result<(), OpaqueError> {
        tracing::info!("store h1 settings for UA '{ua}': {settings:?}");
        Ok(())
    }

    pub(super) async fn store_h1_headers_navigate(
        &self,
        ua: String,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::info!("store h1 navigateheaders for UA '{ua}': {headers:?}");
        Ok(())
    }

    pub(super) async fn store_h1_headers_fetch(
        &self,
        ua: String,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::info!("store h1 fetch headers for UA '{ua}': {headers:?}");
        Ok(())
    }

    pub(super) async fn store_h1_headers_xhr(
        &self,
        ua: String,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::info!("store h1 xhr headers for UA '{ua}': {headers:?}");
        Ok(())
    }

    pub(super) async fn store_h1_headers_form(
        &self,
        ua: String,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::info!("store h1 form headers for UA '{ua}': {headers:?}");
        Ok(())
    }

    pub(super) async fn store_h2_settings(
        &self,
        ua: String,
        settings: Http2Settings,
    ) -> Result<(), OpaqueError> {
        tracing::info!("store h2 settings for UA '{ua}': {settings:?}");
        Ok(())
    }

    pub(super) async fn store_h2_headers_navigate(
        &self,
        ua: String,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::info!("store h2 navigate headers for UA '{ua}': {headers:?}");
        Ok(())
    }

    pub(super) async fn store_h2_headers_fetch(
        &self,
        ua: String,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::info!("store h2 fetch headers for UA '{ua}': {headers:?}");
        Ok(())
    }

    pub(super) async fn store_h2_headers_xhr(
        &self,
        ua: String,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::info!("store h2 xhr headers for UA '{ua}': {headers:?}");
        Ok(())
    }

    pub(super) async fn store_h2_headers_form(
        &self,
        ua: String,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::info!("store h2 form headers for UA '{ua}': {headers:?}");
        Ok(())
    }

    pub(super) async fn store_tls_client_hello(
        &self,
        ua: String,
        tls_client_hello: ClientHello,
    ) -> Result<(), OpaqueError> {
        tracing::info!("store tls client hello for UA '{ua}': {tls_client_hello:?}");
        Ok(())
    }
}
