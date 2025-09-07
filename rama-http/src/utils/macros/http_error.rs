#[doc(hidden)]
#[macro_export]
macro_rules! __log_http_rejection {
    (
        rejection_type = $ty:ident,
        body_text = $body_text:expr,
        status = $status:expr,
    ) => {
        ::rama_core::telemetry::tracing::event!(
            target: "rama_core::servicerejection",
            ::rama_core::telemetry::tracing::Level::TRACE,
            status = $status.as_u16(),
            body = $body_text,
            rejection_type = std::any::type_name::<$ty>(),
            "rejecting http request",
        );
    };
}
pub(crate) use crate::__log_http_rejection as log_http_rejection;

#[doc(hidden)]
#[macro_export]
macro_rules! __define_http_rejection {
    (
        #[status = $status:ident]
        #[body = $body:expr]
        $(#[$m:meta])*
        pub struct $name:ident;
    ) => {
        $(#[$m])*
        #[derive(Debug)]
        #[non_exhaustive]
        pub struct $name;

        impl $crate::service::web::endpoint::IntoResponse for $name {
            fn into_response(self) -> $crate::Response {
                $crate::__log_http_rejection!(
                    rejection_type = $name,
                    body_text = $body,
                    status = $crate::StatusCode::$status,
                );
                (self.status(), $body).into_response()
            }
        }

        impl $name {
            /// Get the response body text used for this rejection.
            #[must_use] pub fn body_text(&self) -> String {
                $body.into()
            }

            /// Get the status code used for this rejection.
            #[must_use] pub fn status(&self) -> $crate::StatusCode {
                $crate::StatusCode::$status
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", $body)
            }
        }

        impl std::error::Error for $name {}

        impl Default for $name {
            fn default() -> Self {
                Self
            }
        }
    };

    (
        #[status = $status:ident]
        #[body = $body:expr]
        $(#[$m:meta])*
        pub struct $name:ident (Error);
    ) => {
        $(#[$m])*
        #[derive(Debug)]
        pub struct $name(pub(crate) rama_core::error::OpaqueError);

        impl $name {
            #[allow(dead_code)]
            pub(crate) fn from_err<E>(err: E) -> Self
            where
                E: std::error::Error + Send + Sync + 'static,
            {
                Self(::rama_core::error::OpaqueError::from_std(err))
            }

            #[allow(dead_code)]
            pub(crate) fn from_display<C>(msg: C) -> Self
            where
                C: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
            {
                Self(::rama_core::error::OpaqueError::from_display(msg))
            }
        }

        impl $crate::service::web::endpoint::IntoResponse for $name {
            fn into_response(self) -> $crate::Response {
                $crate::__log_http_rejection!(
                    rejection_type = $name,
                    body_text = self.body_text(),
                    status = $crate::StatusCode::$status,
                );
                (self.status(), self.body_text()).into_response()
            }
        }

        impl $name {
            /// Get the response body text used for this rejection.
            #[must_use] pub fn body_text(&self) -> String {
                format!(concat!($body, ": {}"), self.0).into()
            }

            /// Get the status code used for this rejection.
            #[must_use] pub fn status(&self) -> $crate::StatusCode {
                $crate::StatusCode::$status
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", $body)
            }
        }

        impl std::error::Error for $name {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
    };
}
pub(crate) use crate::__define_http_rejection as define_http_rejection;

#[doc(hidden)]
#[macro_export]
macro_rules! __composite_http_rejection {
    (
        $(#[$m:meta])*
        pub enum $name:ident {
            $($variant:ident),+
            $(,)?
        }
    ) => {
        $(#[$m])*
        #[derive(Debug)]
        #[non_exhaustive]
        pub enum $name {
            $(
                #[allow(missing_docs)]
                $variant($variant)
            ),+
        }

        impl $crate::service::web::endpoint::IntoResponse for $name {
            fn into_response(self) -> $crate::Response {
                match self {
                    $(
                        Self::$variant(inner) => inner.into_response(),
                    )+
                }
            }
        }

        impl $name {
            /// Get the response body text used for this rejection.
            #[must_use] pub fn body_text(&self) -> String {
                match self {
                    $(
                        Self::$variant(inner) => inner.body_text(),
                    )+
                }
            }

            /// Get the status code used for this rejection.
            #[must_use] pub fn status(&self) -> $crate::StatusCode {
                match self {
                    $(
                        Self::$variant(inner) => inner.status(),
                    )+
                }
            }
        }

        $(
            impl From<$variant> for $name {
                fn from(inner: $variant) -> Self {
                    Self::$variant(inner)
                }
            }
        )+

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(
                        Self::$variant(inner) => write!(f, "{inner}"),
                    )+
                }
            }
        }

        impl std::error::Error for $name {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    $(
                        Self::$variant(inner) => inner.source(),
                    )+
                }
            }
        }
    };
}
pub(crate) use crate::__composite_http_rejection as composite_http_rejection;
