//! Certificate compression ([RFC 8879](https://datatracker.ietf.org/doc/html/rfc8879))
//! shared by the connector, the acceptor and the MITM relay.

use rama_boring::ssl::SslContextBuilder;
use rama_core::error::BoxError;
use rama_core::telemetry::tracing::debug;
use rama_tls::CertificateCompressionAlgorithm;

#[cfg(feature = "compression")]
use rama_core::error::ErrorContext as _;

#[cfg(feature = "compression")]
pub(crate) mod codecs;

/// Register a compressor for each algorithm, which serves both directions.
///
/// Unknown algorithms are skipped.
#[cfg(feature = "compression")]
pub(crate) fn add_certificate_compressors(
    builder: &mut SslContextBuilder,
    algorithms: &[CertificateCompressionAlgorithm],
) -> Result<(), BoxError> {
    for algorithm in algorithms {
        match algorithm {
            CertificateCompressionAlgorithm::Zlib => builder
                .add_certificate_compression_algorithm(codecs::ZlibCertificateCompressor::default())
                .context("add certificate compression algorithm: zlib")?,
            CertificateCompressionAlgorithm::Brotli => builder
                .add_certificate_compression_algorithm(
                    codecs::BrotliCertificateCompressor::default(),
                )
                .context("add certificate compression algorithm: brotli")?,
            CertificateCompressionAlgorithm::Zstd => builder
                .add_certificate_compression_algorithm(codecs::ZstdCertificateCompressor::default())
                .context("add certificate compression algorithm: zstd")?,
            CertificateCompressionAlgorithm::Unknown(_) => {
                debug!(%algorithm, "certificate compression algorithm unknown: ignore");
            }
        }
    }
    Ok(())
}

/// Without the `compression` feature no algorithm is available, so none is registered.
#[cfg(not(feature = "compression"))]
pub(crate) fn add_certificate_compressors(
    _builder: &mut SslContextBuilder,
    algorithms: &[CertificateCompressionAlgorithm],
) -> Result<(), BoxError> {
    for algorithm in algorithms {
        debug!(%algorithm, "certificate compression requires the compression feature: ignore");
    }
    Ok(())
}
