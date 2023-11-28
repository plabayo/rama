use std::marker::PhantomData;

use serde::de::DeserializeOwned;

use crate::{
    http::{HeaderValueGetter, Request},
    service::{Layer, Service},
    BoxError,
};

#[derive(Debug)]
pub struct HeaderConfigService<T, S> {
    inner: S,
    key: String,
    _marker: PhantomData<T>,
}

impl<T, S> HeaderConfigService<T, S> {
    pub fn new(inner: S, key: String) -> Self {
        Self {
            inner,
            key,
            _marker: PhantomData,
        }
    }
}

impl<T, S> Clone for HeaderConfigService<T, S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            key: self.key.clone(),
            _marker: PhantomData,
        }
    }
}

impl<T, S, Body, E> Service<Request<Body>> for HeaderConfigService<T, S>
where
    S: Service<Request<Body>, Error = E>,
    T: DeserializeOwned + Clone + Send + Sync + 'static,
    E: Into<BoxError>,
{
    type Response = S::Response;
    type Error = BoxError;

    async fn call(&self, mut request: Request<Body>) -> Result<Self::Response, Self::Error> {
        let value = request.header_str(&self.key)?;
        let config = serde_urlencoded::from_str::<T>(value)?;
        request.extensions_mut().insert(config);
        self.inner.call(request).await.map_err(Into::into)
    }
}

pub struct HeaderConfigLayer<T> {
    key: String,
    _marker: PhantomData<T>,
}

impl<T> HeaderConfigLayer<T> {
    pub fn new(key: String) -> Self {
        Self {
            key,
            _marker: PhantomData,
        }
    }
}

impl<T, S> Layer<S> for HeaderConfigLayer<T>
where
    S: Service<Request<()>>,
{
    type Service = HeaderConfigService<T, S>;

    fn layer(&self, inner: S) -> Self::Service {
        HeaderConfigService {
            inner,
            key: self.key.clone(),
            _marker: PhantomData,
        }
    }
}

#[cfg(test)]
mod test {
    use serde::Deserialize;

    use crate::http::Method;

    use super::*;

    #[crate::rt::test]
    async fn test_header_config_happy_path() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-config", "s=E%26G&n=1&b=true")
            .body(())
            .unwrap();

        let inner_service = crate::service::service_fn(|req: Request<()>| async move {
            let cfg: &Config = req.extensions().get().unwrap();
            assert_eq!(cfg.s, "E&G");
            assert_eq!(cfg.n, 1);
            assert!(cfg.m.is_none());
            assert!(cfg.b);

            Ok::<_, std::convert::Infallible>(())
        });

        let service =
            HeaderConfigService::<Config, _>::new(inner_service, "x-proxy-config".to_string());

        service.call(request).await.unwrap();
    }

    #[crate::rt::test]
    async fn test_header_config_missing_header() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .body(())
            .unwrap();

        let inner_service = crate::service::service_fn(|_: Request<()>| async move {
            Ok::<_, std::convert::Infallible>(())
        });

        let service =
            HeaderConfigService::<Config, _>::new(inner_service, "x-proxy-config".to_string());

        let result = service.call(request).await;
        assert!(result.is_err());
    }

    #[crate::rt::test]
    async fn test_header_config_invalid_config() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-config", "s=bar&n=1&b=invalid")
            .body(())
            .unwrap();

        let inner_service = crate::service::service_fn(|_: Request<()>| async move {
            Ok::<_, std::convert::Infallible>(())
        });

        let service =
            HeaderConfigService::<Config, _>::new(inner_service, "x-proxy-config".to_string());

        let result = service.call(request).await;
        assert!(result.is_err());
    }

    #[derive(Debug, Deserialize, Clone)]
    struct Config {
        s: String,
        n: i32,
        m: Option<i32>,
        b: bool,
    }
}
