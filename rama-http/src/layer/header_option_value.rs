//! Similar to [`super::header_config::HeaderConfigLayer`],
//! but storing the [`Default`] value of type `T` in case
//! the header with the given [`HeaderName`] is present
//! and has a bool-like value.

use crate::{HeaderName, Request, utils::HeaderValueGetter};
use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorExt, OpaqueError},
    extensions::{Extension, ExtensionsMut},
    telemetry::tracing,
};
use rama_utils::macros::define_inner_service_accessors;
use std::{fmt, marker::PhantomData};

/// A [`Service`] which stores the [`Default`] value of type `T` in case
/// the header with the given [`HeaderName`] is present
/// and has a bool-like value.
pub struct HeaderOptionValueService<T, S> {
    inner: S,
    header_name: HeaderName,
    optional: bool,
    _marker: PhantomData<fn() -> T>,
}

impl<T, S> HeaderOptionValueService<T, S> {
    /// Create a new [`HeaderOptionValueService`].
    ///
    /// Alias for [`HeaderOptionValueService::required`] if `!optional`
    /// and [`HeaderOptionValueService::optional`] if `optional`.
    pub const fn new(inner: S, header_name: HeaderName, optional: bool) -> Self {
        Self {
            inner,
            header_name,
            optional,
            _marker: PhantomData,
        }
    }

    define_inner_service_accessors!();

    /// Create a new [`HeaderOptionValueService`] with the given inner service
    /// and header name, on which optionally create the value,
    /// and which will fail if the header is missing.
    pub const fn required(inner: S, header_name: HeaderName) -> Self {
        Self::new(inner, header_name, false)
    }

    /// Create a new [`HeaderOptionValueService`] with the given inner service
    /// and header name, on which optionally create the value,
    /// and which will gracefully accept if the header is missing.
    pub const fn optional(inner: S, header_name: HeaderName) -> Self {
        Self::new(inner, header_name, true)
    }
}

impl<T, S: fmt::Debug> fmt::Debug for HeaderOptionValueService<T, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HeaderOptionValueService")
            .field("inner", &self.inner)
            .field("header_name", &self.header_name)
            .field("optional", &self.optional)
            .field(
                "_marker",
                &format_args!("{}", std::any::type_name::<fn() -> T>()),
            )
            .finish()
    }
}

impl<T, S> Clone for HeaderOptionValueService<T, S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            header_name: self.header_name.clone(),
            optional: self.optional,
            _marker: PhantomData,
        }
    }
}

impl<T, S, Body, E> Service<Request<Body>> for HeaderOptionValueService<T, S>
where
    S: Service<Request<Body>, Error = E>,
    T: Default + Extension + Clone,
    Body: Send + Sync + 'static,
    E: Into<BoxError> + Send + Sync + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, mut request: Request<Body>) -> Result<Self::Output, Self::Error> {
        match request.header_str(&self.header_name) {
            Ok(str_value) => {
                let str_value = str_value.trim();
                if str_value == "1" || str_value.eq_ignore_ascii_case("true") {
                    request.extensions_mut().insert(T::default());
                } else if str_value != "0" && !str_value.eq_ignore_ascii_case("false") {
                    return Err(OpaqueError::from_display(format!(
                        "invalid '{}' header option: '{}'",
                        self.header_name, str_value
                    ))
                    .into_boxed());
                }
            }
            Err(err) => {
                if self.optional && matches!(err, crate::utils::HeaderValueErr::HeaderMissing(_)) {
                    tracing::debug!(
                        http.header.name  = %self.header_name,
                        "failed to determine header option: {err:?}",
                    );
                    return self.inner.serve(request).await.map_err(Into::into);
                } else {
                    return Err(err
                        .with_context(|| format!("determine '{}' header option", self.header_name))
                        .into_boxed());
                }
            }
        };
        self.inner.serve(request).await.map_err(Into::into)
    }
}

/// Layer which stores the [`Default`] value of type `T` in case
/// the header with the given [`HeaderName`] is present
/// and has a bool-like value.
pub struct HeaderOptionValueLayer<T> {
    header_name: HeaderName,
    optional: bool,
    _marker: PhantomData<fn() -> T>,
}

impl<T> fmt::Debug for HeaderOptionValueLayer<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HeaderOptionValueLayer")
            .field("header_name", &self.header_name)
            .field("optional", &self.optional)
            .field(
                "_marker",
                &format_args!("{}", std::any::type_name::<fn() -> T>()),
            )
            .finish()
    }
}

impl<T> Clone for HeaderOptionValueLayer<T> {
    fn clone(&self) -> Self {
        Self {
            header_name: self.header_name.clone(),
            optional: self.optional,
            _marker: PhantomData,
        }
    }
}

impl<T> HeaderOptionValueLayer<T> {
    /// Create a new [`HeaderOptionValueLayer`] with the given header name,
    /// on which optionally create the valu,
    /// and which will fail if the header is missing.
    pub fn required(header_name: HeaderName) -> Self {
        Self {
            header_name,
            optional: false,
            _marker: PhantomData,
        }
    }

    /// Create a new [`HeaderOptionValueLayer`] with the given header name,
    /// on which optionally create the valu,
    /// and which will gracefully accept if the header is missing.
    pub fn optional(header_name: HeaderName) -> Self {
        Self {
            header_name,
            optional: true,
            _marker: PhantomData,
        }
    }
}

impl<T, S> Layer<S> for HeaderOptionValueLayer<T> {
    type Service = HeaderOptionValueService<T, S>;

    fn layer(&self, inner: S) -> Self::Service {
        HeaderOptionValueService::new(inner, self.header_name.clone(), self.optional)
    }

    fn into_layer(self, inner: S) -> Self::Service {
        HeaderOptionValueService::new(inner, self.header_name, self.optional)
    }
}

#[cfg(test)]
mod test {
    use rama_core::extensions::ExtensionsRef;

    use super::*;
    use crate::Method;

    #[derive(Debug, Clone, Default)]
    struct UnitValue;

    #[tokio::test]
    async fn test_header_option_value_required_happy_path() {
        let test_cases = [
            ("1", true),
            ("true", true),
            ("True", true),
            ("TrUE", true),
            ("TRUE", true),
            ("0", false),
            ("false", false),
            ("False", false),
            ("FaLsE", false),
            ("FALSE", false),
        ];
        for (str_value, expected_output) in test_cases {
            let request = Request::builder()
                .method(Method::GET)
                .uri("https://www.example.com")
                .header("x-unit-value", str_value)
                .body(())
                .unwrap();

            let inner_service =
                rama_core::service::service_fn(move |req: Request<()>| async move {
                    assert_eq!(expected_output, req.extensions().contains::<UnitValue>());
                    Ok::<_, std::convert::Infallible>(())
                });

            let service = HeaderOptionValueService::<UnitValue, _>::required(
                inner_service,
                HeaderName::from_static("x-unit-value"),
            );

            service.serve(request).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_header_option_value_optional_found() {
        let test_cases = [
            ("1", true),
            ("true", true),
            ("True", true),
            ("TrUE", true),
            ("TRUE", true),
            ("0", false),
            ("false", false),
            ("False", false),
            ("FaLsE", false),
            ("FALSE", false),
        ];
        for (str_value, expected_output) in test_cases {
            let request = Request::builder()
                .method(Method::GET)
                .uri("https://www.example.com")
                .header("x-unit-value", str_value)
                .body(())
                .unwrap();

            let inner_service =
                rama_core::service::service_fn(move |req: Request<()>| async move {
                    assert_eq!(expected_output, req.extensions().contains::<UnitValue>());
                    Ok::<_, std::convert::Infallible>(())
                });

            let service = HeaderOptionValueService::<UnitValue, _>::optional(
                inner_service,
                HeaderName::from_static("x-unit-value"),
            );

            service.serve(request).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_header_option_value_optional_missing() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .body(())
            .unwrap();

        let inner_service = rama_core::service::service_fn(async |req: Request<()>| {
            assert!(!req.extensions().contains::<UnitValue>());

            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderOptionValueService::<UnitValue, _>::optional(
            inner_service,
            HeaderName::from_static("x-unit-value"),
        );

        service.serve(request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_option_value_required_missing_header() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .body(())
            .unwrap();

        let inner_service = rama_core::service::service_fn(async |_: Request<()>| {
            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderOptionValueService::<UnitValue, _>::required(
            inner_service,
            HeaderName::from_static("x-unit-value"),
        );

        let result = service.serve(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_header_option_value_required_invalid_value() {
        let test_cases = ["", "foo", "yes"];

        for test_case in test_cases {
            let request = Request::builder()
                .method(Method::GET)
                .uri("https://www.example.com")
                .header("x-unit-value", test_case)
                .body(())
                .unwrap();

            let inner_service = rama_core::service::service_fn(async |_: Request<()>| {
                Ok::<_, std::convert::Infallible>(())
            });

            let service = HeaderOptionValueService::<UnitValue, _>::required(
                inner_service,
                HeaderName::from_static("x-unit-value"),
            );

            let result = service.serve(request).await;
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn test_header_option_value_optional_invalid_value() {
        let test_cases = ["", "foo", "yes"];

        for test_case in test_cases {
            let request = Request::builder()
                .method(Method::GET)
                .uri("https://www.example.com")
                .header("x-unit-value", test_case)
                .body(())
                .unwrap();

            let inner_service = rama_core::service::service_fn(async |_: Request<()>| {
                Ok::<_, std::convert::Infallible>(())
            });

            let service = HeaderOptionValueService::<UnitValue, _>::optional(
                inner_service,
                HeaderName::from_static("x-unit-value"),
            );

            let result = service.serve(request).await;
            assert!(result.is_err());
        }
    }
}
