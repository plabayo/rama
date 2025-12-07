use chrono::Utc;
use rama::{
    error::{ErrorContext, OpaqueError},
    http::proto::h1::Http1HeaderMap,
    net::tls::client::ClientHello,
    telemetry::tracing,
    ua::profile::{
        Http1Settings, Http2Settings, JsProfileWebApis, UserAgentSourceInfo,
        WsClientConfigOverwrites,
    },
};

mod postgres;
use postgres::Pool;
use tokio_postgres::types;

#[derive(Debug, Clone)]
pub(super) struct Storage {
    pool: Pool,
}

impl Storage {
    pub(super) async fn try_new(pg_url: String) -> Result<Self, OpaqueError> {
        tracing::debug!(
            url.full = %pg_url,
            "create new PG storage",
        );
        let pool = postgres::try_new_pool(pg_url).await?;
        Ok(Self { pool })
    }
}

macro_rules! insert_stmt {
    ($auth:expr, $query:literal $(,)?) => {
        if ($auth) {
            concat!("INSERT INTO \"ua-profiles\" ", $query)
        } else {
            concat!("INSERT INTO \"public-ua-profiles\" ", $query)
        }
    };
}

impl Storage {
    pub(super) async fn store_h1_settings(
        &self,
        ua: String,
        auth: bool,
        settings: Http1Settings,
    ) -> Result<(), OpaqueError> {
        tracing::debug!(
            user_agent.original = %ua,
            "store h1 settings for UA: {settings:?}",
        );

        let updated_at = Utc::now();

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            insert_stmt!(
                auth,
                "(uastr, h1_settings, updated_at) VALUES ($1, $2, $3) ON CONFLICT (uastr) DO UPDATE SET h1_settings = $2, updated_at = $3",
            ),
            &[&ua, &types::Json(settings), &updated_at],
        ).await.context("store h1 settings in postgres")?;

        if n != 1 {
            tracing::error!(
                user_agent.original = %ua,
                "unexpected number of rows affected to store h1 settings for UA: {n}",
            );
        }

        Ok(())
    }

    pub(super) async fn store_h1_headers_navigate(
        &self,
        ua: String,
        auth: bool,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::debug!(
            user_agent.original = %ua,
            "store h1 navigateheaders for UA: {headers:?}",
        );

        let updated_at = Utc::now();

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            insert_stmt!(
                auth,
                "(uastr, h1_headers_navigate, updated_at) VALUES ($1, $2, $3) ON CONFLICT (uastr) DO UPDATE SET h1_headers_navigate = $2, updated_at = $3",
            ),
            &[&ua, &types::Json(headers), &updated_at],
        ).await.context("store h1 navigate headers in postgres")?;

        if n != 1 {
            tracing::error!(
                user_agent.original = %ua,
                "unexpected number of rows affected to store h1 navigate headers for UA: {n}",
            );
        }

        Ok(())
    }

    pub(super) async fn store_h1_headers_fetch(
        &self,
        ua: String,
        auth: bool,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::debug!(
            user_agent.original = %ua,
            "store h1 fetch headers for UA: {headers:?}",
        );

        let updated_at = Utc::now();

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            insert_stmt!(
                auth,
                "(uastr, h1_headers_fetch, updated_at) VALUES ($1, $2, $3) ON CONFLICT (uastr) DO UPDATE SET h1_headers_fetch = $2, updated_at = $3",
            ),
            &[&ua, &types::Json(headers), &updated_at],
        ).await.context("store h1 fetch headers in postgres")?;

        if n != 1 {
            tracing::error!(
                user_agent.original = %ua,
                "unexpected number of rows affected to store h1 fetch headers for UA: {n}",
            );
        }

        Ok(())
    }

    pub(super) async fn store_h1_headers_xhr(
        &self,
        ua: String,
        auth: bool,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::debug!(
            user_agent.original = %ua,
            "store h1 xhr headers for UA: {headers:?}",
        );

        let updated_at = Utc::now();

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            insert_stmt!(
                auth,
                "(uastr, h1_headers_xhr, updated_at) VALUES ($1, $2, $3) ON CONFLICT (uastr) DO UPDATE SET h1_headers_xhr = $2, updated_at = $3",
            ),
            &[&ua, &types::Json(headers), &updated_at],
        ).await.context("store h1 xhr headers in postgres")?;

        if n != 1 {
            tracing::error!(
                user_agent.original = %ua,
                "unexpected number of rows affected to store h1 xhr headers for UA: {n}",
            );
        }

        Ok(())
    }

    pub(super) async fn store_h1_headers_form(
        &self,
        ua: String,
        auth: bool,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::debug!(
            user_agent.original = %ua,
            "store h1 form headers for UA: {headers:?}",
        );

        let updated_at = Utc::now();

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            insert_stmt!(
                auth,
                "(uastr, h1_headers_form, updated_at) VALUES ($1, $2, $3) ON CONFLICT (uastr) DO UPDATE SET h1_headers_form = $2, updated_at = $3",
            ),
            &[&ua, &types::Json(headers), &updated_at],
        ).await.context("store h1 form headers in postgres")?;

        if n != 1 {
            tracing::error!(
                user_agent.original = %ua,
                "unexpected number of rows affected to store h1 form headers for UA: {n}",
            );
        }

        Ok(())
    }

    pub(super) async fn store_h1_headers_ws(
        &self,
        ua: String,
        auth: bool,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::debug!(
            user_agent.original = %ua,
            "store h1 ws headers for UA: {headers:?}",
        );

        let updated_at = Utc::now();

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
                insert_stmt!(
                    auth,
                    "(uastr, h1_headers_ws, updated_at) VALUES ($1, $2, $3) ON CONFLICT (uastr) DO UPDATE SET h1_headers_ws = $2, updated_at = $3",
                ),
                &[&ua, &types::Json(headers), &updated_at],
            ).await.context("store h1 ws headers in postgres")?;

        if n != 1 {
            tracing::error!(
                user_agent.original = %ua,
                "unexpected number of rows affected to store h1 ws headers for UA: {n}",
            );
        }

        Ok(())
    }

    pub(super) async fn store_h2_settings(
        &self,
        ua: String,
        auth: bool,
        settings: Http2Settings,
    ) -> Result<(), OpaqueError> {
        tracing::debug!(
            user_agent.original = %ua,
            "store h2 settings for UA: {settings:?}",
        );

        let updated_at = Utc::now();

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            insert_stmt!(
                auth,
                "(uastr, h2_settings, updated_at) VALUES ($1, $2, $3) ON CONFLICT (uastr) DO UPDATE SET h2_settings = $2, updated_at = $3",
            ),
            &[&ua, &types::Json(settings), &updated_at],
        ).await.context("store h2 settings in postgres")?;

        if n != 1 {
            tracing::error!(
                user_agent.original = %ua,
                "unexpected number of rows affected to store h2 settings for UA: {n}",
            );
        }

        Ok(())
    }

    pub(super) async fn store_h2_headers_navigate(
        &self,
        ua: String,
        auth: bool,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::debug!(
            user_agent.original = %ua,
            "store h2 navigate headers for UA: {headers:?}",
        );

        let updated_at = Utc::now();

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            insert_stmt!(
                auth,
                "(uastr, h2_headers_navigate, updated_at) VALUES ($1, $2, $3) ON CONFLICT (uastr) DO UPDATE SET h2_headers_navigate = $2, updated_at = $3",
            ),
            &[&ua, &types::Json(headers), &updated_at],
        ).await.context("store h2 navigate headers in postgres")?;

        if n != 1 {
            tracing::error!(
                user_agent.original = %ua,
                "unexpected number of rows affected to store h2 navigate headers for UA: {n}",
            );
        }

        Ok(())
    }

    pub(super) async fn store_h2_headers_fetch(
        &self,
        ua: String,
        auth: bool,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::debug!(
            user_agent.original = %ua,
            "store h2 fetch headers for UA: {headers:?}",
        );

        let updated_at = Utc::now();

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            insert_stmt!(
                auth,
                "(uastr, h2_headers_fetch, updated_at) VALUES ($1, $2, $3) ON CONFLICT (uastr) DO UPDATE SET h2_headers_fetch = $2, updated_at = $3",
            ),
            &[&ua, &types::Json(headers), &updated_at],
        ).await.context("store h2 fetch headers in postgres")?;

        if n != 1 {
            tracing::error!(
                user_agent.original = %ua,
                "unexpected number of rows affected to store h2 fetch headers for UA: {n}",
            );
        }

        Ok(())
    }

    pub(super) async fn store_h2_headers_xhr(
        &self,
        ua: String,
        auth: bool,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::debug!(
            user_agent.original = %ua,
            "store h2 xhr headers for UA: {headers:?}",
        );

        let updated_at = Utc::now();

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            insert_stmt!(
                auth,
                "(uastr, h2_headers_xhr, updated_at) VALUES ($1, $2, $3) ON CONFLICT (uastr) DO UPDATE SET h2_headers_xhr = $2, updated_at = $3",
            ),
            &[&ua, &types::Json(headers), &updated_at],
        ).await.context("store h2 xhr headers in postgres")?;

        if n != 1 {
            tracing::error!(
                user_agent.original = %ua,
                "unexpected number of rows affected to store h2 xhr headers for UA: {n}",
            );
        }

        Ok(())
    }

    pub(super) async fn store_h2_headers_form(
        &self,
        ua: String,
        auth: bool,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::debug!(
            user_agent.original = %ua,
            "store h2 form headers for UA: {headers:?}",
        );

        let updated_at = Utc::now();

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            insert_stmt!(
                auth,
                "(uastr, h2_headers_form, updated_at) VALUES ($1, $2, $3) ON CONFLICT (uastr) DO UPDATE SET h2_headers_form = $2, updated_at = $3",
            ),
            &[&ua, &types::Json(headers), &updated_at],
        ).await.context("store h2 form headers in postgres")?;

        if n != 1 {
            tracing::error!(
                user_agent.original = %ua,
                "unexpected number of rows affected to store h2 form headers for UA: {n}",
            );
        }

        Ok(())
    }

    pub(super) async fn store_h2_headers_ws(
        &self,
        ua: String,
        auth: bool,
        headers: Http1HeaderMap,
    ) -> Result<(), OpaqueError> {
        tracing::debug!(
            user_agent.original = %ua,
            "store h2 ws headers for UA: {headers:?}",
        );

        let updated_at = Utc::now();

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
                insert_stmt!(
                    auth,
                    "(uastr, h2_headers_ws, updated_at) VALUES ($1, $2, $3) ON CONFLICT (uastr) DO UPDATE SET h2_headers_ws = $2, updated_at = $3",
                ),
                &[&ua, &types::Json(headers), &updated_at],
            ).await.context("store h2 ws headers in postgres")?;

        if n != 1 {
            tracing::error!(
                user_agent.original = %ua,
                "unexpected number of rows affected to store h2 ws headers for UA: {n}",
            );
        }

        Ok(())
    }

    pub(super) async fn store_tls_client_hello(
        &self,
        ua: String,
        auth: bool,
        tls_client_hello: ClientHello,
    ) -> Result<(), OpaqueError> {
        tracing::debug!(
            user_agent.original = %ua,
            "store tls client hello for UA: {tls_client_hello:?}",
        );

        let updated_at = Utc::now();

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            insert_stmt!(
                auth,
                "(uastr, tls_client_hello, updated_at) VALUES ($1, $2, $3) ON CONFLICT (uastr) DO UPDATE SET tls_client_hello = $2, updated_at = $3",
            ),
            &[&ua, &types::Json(tls_client_hello), &updated_at],
        ).await.context("store tls client hello in postgres")?;

        if n != 1 {
            tracing::error!(
                user_agent.original = %ua,
                "unexpected number of rows affected to store tls client hello for UA: {n}",
            );
        }

        Ok(())
    }

    pub(super) async fn store_tls_ws_client_overwrites_from_client_hello(
        &self,
        ua: String,
        auth: bool,
        tls_client_hello: ClientHello,
    ) -> Result<(), OpaqueError> {
        tracing::debug!(
            user_agent.original = %ua,
            "store tls ws client config overwritesfor UA: {tls_client_hello:?}",
        );

        let updated_at = Utc::now();

        let overwrites = WsClientConfigOverwrites {
            alpn: tls_client_hello.ext_alpn().map(ToOwned::to_owned),
        };

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            insert_stmt!(
                auth,
                "(uastr, tls_ws_client_config_overwrites, updated_at) VALUES ($1, $2, $3) ON CONFLICT (uastr) DO UPDATE SET tls_ws_client_config_overwrites = $2, updated_at = $3",
            ),
            &[&ua, &types::Json(overwrites), &updated_at],
        ).await.context("store tls client config overwrites in postgres")?;

        if n != 1 {
            tracing::error!(
                user_agent.original = %ua,
                "unexpected number of rows affected to store tls ws client config overwrites for UA: {n}",
            );
        }

        Ok(())
    }

    pub(super) async fn store_js_web_apis(
        &self,
        ua: String,
        auth: bool,
        js_web_apis: JsProfileWebApis,
    ) -> Result<(), OpaqueError> {
        tracing::debug!(
            user_agent.original = %ua,
            "store js web apis for UA: {js_web_apis:?}",
        );

        let updated_at = Utc::now();

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            insert_stmt!(
                auth,
                "(uastr, js_web_apis, updated_at) VALUES ($1, $2, $3) ON CONFLICT (uastr) DO UPDATE SET js_web_apis = $2, updated_at = $3",
            ),
            &[&ua, &types::Json(js_web_apis), &updated_at],
        ).await.context("store js web apis in postgres")?;

        if n != 1 {
            tracing::error!(
                user_agent.original = %ua,
                "unexpected number of rows affected to store js web apis for UA: {n}",
            );
        }

        Ok(())
    }

    pub(super) async fn store_source_info(
        &self,
        ua: String,
        auth: bool,
        source_info: UserAgentSourceInfo,
    ) -> Result<(), OpaqueError> {
        tracing::debug!(
            user_agent.original = %ua,
            "store source info for UA: {source_info:?}",
        );

        let updated_at = Utc::now();

        let client = self.pool.get().await.context("get postgres client")?;
        let n = client.execute(
            insert_stmt!(
                auth,
                "(uastr, source_info, updated_at) VALUES ($1, $2, $3) ON CONFLICT (uastr) DO UPDATE SET source_info = $2, updated_at = $3",
            ),
            &[&ua, &types::Json(source_info), &updated_at],
        ).await.context("store source info in postgres")?;

        if n != 1 {
            tracing::error!(
                user_agent.original = %ua,
                "unexpected number of rows affected to store js source info for UA: {n}",
            );
        }

        Ok(())
    }
}
