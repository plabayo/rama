use crate::error::Error;
use crate::http::dep::http_body_util::BodyExt;
use std::future::Future;

/// An extension trait for [`Body`] that provides methods to extract data from it.
///
/// [`Body`]: crate::http::Body
pub trait BodyExtractExt: private::Sealed {
    /// Try to deserialize the (contained) body as a JSON object.
    fn try_into_json<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> impl Future<Output = Result<T, Error>> + Send;

    /// Try to turn the (contained) body in an utf-8 string.
    fn try_into_string(self) -> impl Future<Output = Result<String, Error>> + Send;
}

impl<Body> BodyExtractExt for crate::http::Response<Body>
where
    Body: crate::http::dep::http_body::Body + Send + 'static,
    Body::Data: Send + 'static,
    Body::Error: Send + Sync + 'static,
{
    async fn try_into_json<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> Result<T, Error> {
        // TODO: use actual collect error instead of ignoring it
        let body = self
            .into_body()
            .collect()
            .await
            .map_err(|_| Error::new("Failed to collect body"))?;
        Ok(serde_json::from_slice(body.to_bytes().as_ref())?)
    }

    async fn try_into_string(self) -> Result<String, Error> {
        // TODO: use actual collect error instead of ignoring it
        let body = self
            .into_body()
            .collect()
            .await
            .map_err(|_| Error::new("Failed to collect body"))?;
        let bytes = body.to_bytes();
        Ok(String::from_utf8(bytes.to_vec())?)
    }
}

impl<Body> BodyExtractExt for crate::http::Request<Body>
where
    Body: crate::http::dep::http_body::Body + Send + 'static,
    Body::Data: Send + 'static,
    Body::Error: Send + Sync + 'static,
{
    async fn try_into_json<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> Result<T, Error> {
        // TODO: use actual collect error instead of ignoring it
        let body = self
            .into_body()
            .collect()
            .await
            .map_err(|_| Error::new("Failed to collect body"))?;
        Ok(serde_json::from_slice(body.to_bytes().as_ref())?)
    }

    async fn try_into_string(self) -> Result<String, Error> {
        // TODO: use actual collect error instead of ignoring it
        let body = self
            .into_body()
            .collect()
            .await
            .map_err(|_| Error::new("Failed to collect body"))?;
        let bytes = body.to_bytes();
        Ok(String::from_utf8(bytes.to_vec())?)
    }
}

impl<B: Into<crate::http::Body> + Send + 'static> BodyExtractExt for B {
    async fn try_into_json<T: serde::de::DeserializeOwned + Send + 'static>(
        self,
    ) -> Result<T, Error> {
        let body = self.into().collect().await?;
        Ok(serde_json::from_slice(body.to_bytes().as_ref())?)
    }

    async fn try_into_string(self) -> Result<String, Error> {
        // TODO: use actual collect error instead of ignoring it
        let body = self.into().collect().await?;
        let bytes = body.to_bytes();
        Ok(String::from_utf8(bytes.to_vec())?)
    }
}

mod private {
    pub trait Sealed {}

    impl<Body> Sealed for crate::http::Response<Body> {}
    impl<Body> Sealed for crate::http::Request<Body> {}
    impl<B: Into<crate::http::Body> + Send + 'static> Sealed for B {}
}
