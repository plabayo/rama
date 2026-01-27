#[cfg(feature = "http-full")]
#[cfg_attr(docsrs, doc(cfg(feature = "http-full")))]
pub mod http;

#[cfg(feature = "net")]
#[cfg_attr(docsrs, doc(cfg(feature = "net")))]
pub mod types;

#[cfg(feature = "net")]
#[cfg_attr(docsrs, doc(cfg(feature = "net")))]
pub mod stream;
