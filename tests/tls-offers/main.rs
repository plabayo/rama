//! Native ALPN configuration through the public Rama facade, without UA.

#[cfg(any(
    feature = "boring",
    all(feature = "rustls", any(feature = "ring", feature = "aws-lc"))
))]
mod tcp;

#[cfg(all(
    feature = "http-backend",
    feature = "dns",
    feature = "tcp",
    any(
        feature = "boring",
        all(feature = "rustls", any(feature = "ring", feature = "aws-lc"))
    )
))]
mod quic;
