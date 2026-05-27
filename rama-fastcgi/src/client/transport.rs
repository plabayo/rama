//! Turnkey FastCGI client transports.
//!
//! These connectors implement `Service<FastCgiClientRequest>` and plug
//! straight into [`FastCgiClient`][crate::client::FastCgiClient] or
//! [`FastCgiHttpClient`][crate::http::FastCgiHttpClient] — no custom
//! connector wrapper required for the common cases.
//!
//! Each connector also lets you stage CGI params (typically the php-fpm
//! mandatory pair `SCRIPT_FILENAME` + `DOCUMENT_ROOT`) that get pushed onto
//! the request's `params` vec before it's forwarded. There's a `php_fpm`
//! preset on each side that fills these for you.
//!
//! Available behind the default-on `transport` feature.
//!
//! ## Examples
//!
//! Pointing rama at php-fpm over TCP:
//!
//! ```ignore
//! use rama_fastcgi::client::transport::FastCgiTcpConnector;
//! use rama_fastcgi::FastCgiHttpClient;
//!
//! let connector = FastCgiTcpConnector::php_fpm(
//!     "127.0.0.1:9000".parse().unwrap(),
//!     exec,
//!     "/var/www/index.php",
//! );
//! let client = FastCgiHttpClient::new(connector);
//! ```
//!
//! Over a Unix socket (Unix-family targets only):
//!
//! ```ignore
//! # #[cfg(target_family = "unix")] {
//! use rama_fastcgi::client::transport::FastCgiUnixConnector;
//! use rama_fastcgi::FastCgiHttpClient;
//!
//! let connector = FastCgiUnixConnector::php_fpm(
//!     "/run/php/php8.3-fpm.sock",
//!     "/var/www/index.php",
//! );
//! let client = FastCgiHttpClient::new(connector);
//! # }
//! ```
//!
//! Advanced — explicit param injection (any backend, not just PHP):
//!
//! ```ignore
//! use rama_fastcgi::client::transport::FastCgiTcpConnector;
//! use rama_fastcgi::proto::cgi;
//!
//! let connector = FastCgiTcpConnector::new(addr, exec)
//!     .with_script_filename("/srv/app.py")
//!     .with_document_root("/srv")
//!     .with_param(cgi::REDIRECT_STATUS, "200");
//! ```

mod tcp;
pub use tcp::FastCgiTcpConnector;

#[cfg(target_family = "unix")]
mod unix;
#[cfg(target_family = "unix")]
pub use unix::FastCgiUnixConnector;
