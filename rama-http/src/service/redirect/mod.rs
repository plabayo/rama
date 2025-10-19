//! Service that redirects all requests.

mod r#static;
pub use r#static::RedirectStatic;

mod http_to_https;
pub use http_to_https::RedirectHttpToHttps;
