use rama::{
    error::{ErrorContext, OpaqueError},
    http::proto::h1::Http1HeaderMap,
    net::tls::client::ClientHello,
    ua::{Http1Settings, Http2Settings},
};

mod postgres;
use postgres::Pool;
use tokio_postgres::types;

#[derive(Debug, Clone)]
pub(super) struct Storage {
    pool: Pool,
}

impl Storage {
    pub(super) async fn new(pg_url: String) -> Result<Self, OpaqueError> {
        tracing::debug!("create new storage with PG URL: {}", pg_url);
        let pool = postgres::new_pool(pg_url).await?;
        Ok(Self { pool })
    }
}

impl Storage {
    pub(super) async fn store_h1_settings(
        &self,
        ua: String,
        settings: Http1Settings,
    ) -> Result<(), OpaqueError> {
        tracing::debug!("store h1 settings for UA '{ua}': {settings:?}");

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            "INSERT INTO \"ua-profiles\" (uastr, h1_settings) VALUES ($1, $2) ON CONFLICT (uastr) DO UPDATE SET h1_settings = $2",
            &[&ua, &types::Json(settings)],
        ).await.context("store h1 settings in postgres")?;

        if n != 1 {
            tracing::error!(
                "unexpected number of rows affected to store h1 settings for UA '{ua}': {n}"
            );
        }

        Ok(())
    }

    pub(super) async fn store_h1_headers_navigate(
        &self,
        ua: String,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::debug!("store h1 navigateheaders for UA '{ua}': {headers:?}");

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            "INSERT INTO \"ua-profiles\" (uastr, h1_headers_navigate) VALUES ($1, $2) ON CONFLICT (uastr) DO UPDATE SET h1_headers_navigate = $2",
            &[&ua, &types::Json(headers)],
        ).await.context("store h1 navigate headers in postgres")?;

        if n != 1 {
            tracing::error!(
                "unexpected number of rows affected to store h1 navigate headers for UA '{ua}': {n}"
            );
        }

        Ok(())
    }

    pub(super) async fn store_h1_headers_fetch(
        &self,
        ua: String,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::debug!("store h1 fetch headers for UA '{ua}': {headers:?}");

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            "INSERT INTO \"ua-profiles\" (uastr, h1_headers_fetch) VALUES ($1, $2) ON CONFLICT (uastr) DO UPDATE SET h1_headers_fetch = $2",
            &[&ua, &types::Json(headers)],
        ).await.context("store h1 fetch headers in postgres")?;

        if n != 1 {
            tracing::error!(
                "unexpected number of rows affected to store h1 fetch headers for UA '{ua}': {n}"
            );
        }

        Ok(())
    }

    pub(super) async fn store_h1_headers_xhr(
        &self,
        ua: String,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::debug!("store h1 xhr headers for UA '{ua}': {headers:?}");

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            "INSERT INTO \"ua-profiles\" (uastr, h1_headers_xhr) VALUES ($1, $2) ON CONFLICT (uastr) DO UPDATE SET h1_headers_xhr = $2",
            &[&ua, &types::Json(headers)],
        ).await.context("store h1 xhr headers in postgres")?;

        if n != 1 {
            tracing::error!(
                "unexpected number of rows affected to store h1 xhr headers for UA '{ua}': {n}"
            );
        }

        Ok(())
    }

    pub(super) async fn store_h1_headers_form(
        &self,
        ua: String,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::debug!("store h1 form headers for UA '{ua}': {headers:?}");

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            "INSERT INTO \"ua-profiles\" (uastr, h1_headers_form) VALUES ($1, $2) ON CONFLICT (uastr) DO UPDATE SET h1_headers_form = $2",
            &[&ua, &types::Json(headers)],
        ).await.context("store h1 form headers in postgres")?;

        if n != 1 {
            tracing::error!(
                "unexpected number of rows affected to store h1 form headers for UA '{ua}': {n}"
            );
        }

        Ok(())
    }

    pub(super) async fn store_h2_settings(
        &self,
        ua: String,
        settings: Http2Settings,
    ) -> Result<(), OpaqueError> {
        tracing::debug!("store h2 settings for UA '{ua}': {settings:?}");

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            "INSERT INTO \"ua-profiles\" (uastr, h2_settings) VALUES ($1, $2) ON CONFLICT (uastr) DO UPDATE SET h2_settings = $2",
            &[&ua, &types::Json(settings)],
        ).await.context("store h2 settings in postgres")?;

        if n != 1 {
            tracing::error!(
                "unexpected number of rows affected to store h2 settings for UA '{ua}': {n}"
            );
        }

        Ok(())
    }

    pub(super) async fn store_h2_headers_navigate(
        &self,
        ua: String,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::debug!("store h2 navigate headers for UA '{ua}': {headers:?}");

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            "INSERT INTO \"ua-profiles\" (uastr, h2_headers_navigate) VALUES ($1, $2) ON CONFLICT (uastr) DO UPDATE SET h2_headers_navigate = $2",
            &[&ua, &types::Json(headers)],
        ).await.context("store h2 navigate headers in postgres")?;

        if n != 1 {
            tracing::error!(
                "unexpected number of rows affected to store h2 navigate headers for UA '{ua}': {n}"
            );
        }

        Ok(())
    }

    pub(super) async fn store_h2_headers_fetch(
        &self,
        ua: String,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::debug!("store h2 fetch headers for UA '{ua}': {headers:?}");

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            "INSERT INTO \"ua-profiles\" (uastr, h2_headers_fetch) VALUES ($1, $2) ON CONFLICT (uastr) DO UPDATE SET h2_headers_fetch = $2",
            &[&ua, &types::Json(headers)],
        ).await.context("store h2 fetch headers in postgres")?;

        if n != 1 {
            tracing::error!(
                "unexpected number of rows affected to store h2 fetch headers for UA '{ua}': {n}"
            );
        }

        Ok(())
    }

    pub(super) async fn store_h2_headers_xhr(
        &self,
        ua: String,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::debug!("store h2 xhr headers for UA '{ua}': {headers:?}");

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            "INSERT INTO \"ua-profiles\" (uastr, h2_headers_xhr) VALUES ($1, $2) ON CONFLICT (uastr) DO UPDATE SET h2_headers_xhr = $2",
            &[&ua, &types::Json(headers)],
        ).await.context("store h2 xhr headers in postgres")?;

        if n != 1 {
            tracing::error!(
                "unexpected number of rows affected to store h2 xhr headers for UA '{ua}': {n}"
            );
        }

        Ok(())
    }

    pub(super) async fn store_h2_headers_form(
        &self,
        ua: String,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::debug!("store h2 form headers for UA '{ua}': {headers:?}");

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            "INSERT INTO \"ua-profiles\" (uastr, h2_headers_form) VALUES ($1, $2) ON CONFLICT (uastr) DO UPDATE SET h2_headers_form = $2",
            &[&ua, &types::Json(headers)],
        ).await.context("store h2 form headers in postgres")?;

        if n != 1 {
            tracing::error!(
                "unexpected number of rows affected to store h2 form headers for UA '{ua}': {n}"
            );
        }

        Ok(())
    }

    pub(super) async fn store_tls_client_hello(
        &self,
        ua: String,
        tls_client_hello: ClientHello,
    ) -> Result<(), OpaqueError> {
        tracing::debug!("store tls client hello for UA '{ua}': {tls_client_hello:?}");

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            "INSERT INTO \"ua-profiles\" (uastr, tls_client_hello) VALUES ($1, $2) ON CONFLICT (uastr) DO UPDATE SET tls_client_hello = $2",
            &[&ua, &types::Json(tls_client_hello)],
        ).await.context("store tls client hello in postgres")?;

        if n != 1 {
            tracing::error!(
                "unexpected number of rows affected to store tls client hello for UA '{ua}': {n}"
            );
        }

        Ok(())
    }
}
