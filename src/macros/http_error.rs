/// Private API.
#[doc(hidden)]
#[macro_export]
macro_rules! __log_http_rejection {
    (
        rejection_type = $ty:ident,
        body_text = $body_text:expr,
        status = $status:expr,
    ) => {
        tracing::event!(
            target: "rama::rejection",
            tracing::Level::TRACE,
            status = $status.as_u16(),
            body = $body_text,
            rejection_type = std::any::type_name::<$ty>(),
            "rejecting http request",
        );
    };
}

/// Private API.
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

        impl $crate::http::IntoResponse for $name {
            fn into_response(self) -> $crate::http::Response {
                $crate::__log_http_rejection!(
                    rejection_type = $name,
                    body_text = $body,
                    status = $crate::http::StatusCode::$status,
                );
                (self.status(), $body).into_response()
            }
        }

        impl $name {
            /// Get the response body text used for this rejection.
            pub fn body_text(&self) -> String {
                $body.into()
            }

            /// Get the status code used for this rejection.
            pub fn status(&self) -> $crate::http::StatusCode {
                $crate::http::StatusCode::$status
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
        pub struct $name(pub(crate) $crate::error::OpaqueError);

        impl $name {
            #[allow(dead_code)]
            pub(crate) fn from_err<E>(err: E) -> Self
            where
                E: std::error::Error + Send + Sync + 'static,
            {
                Self($crate::error::OpaqueError::from_std(err))
            }

            #[allow(dead_code)]
            pub(crate) fn from_display<C>(msg: C) -> Self
            where
                C: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
            {
                Self($crate::error::OpaqueError::from_display(msg))
            }
        }

        impl $crate::http::IntoResponse for $name {
            fn into_response(self) -> $crate::http::Response {
                $crate::__log_http_rejection!(
                    rejection_type = $name,
                    body_text = self.body_text(),
                    status = $crate::http::StatusCode::$status,
                );
                (self.status(), self.body_text()).into_response()
            }
        }

        impl $name {
            /// Get the response body text used for this rejection.
            pub fn body_text(&self) -> String {
                format!(concat!($body, ": {}"), self.0).into()
            }

            /// Get the status code used for this rejection.
            pub fn status(&self) -> $crate::http::StatusCode {
                $crate::http::StatusCode::$status
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

/// Private API.
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

        impl $crate::http::IntoResponse for $name {
            fn into_response(self) -> $crate::http::Response {
                match self {
                    $(
                        Self::$variant(inner) => inner.into_response(),
                    )+
                }
            }
        }

        impl $name {
            /// Get the response body text used for this rejection.
            pub fn body_text(&self) -> String {
                match self {
                    $(
                        Self::$variant(inner) => inner.body_text(),
                    )+
                }
            }

            /// Get the status code used for this rejection.
            pub fn status(&self) -> $crate::http::StatusCode {
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
