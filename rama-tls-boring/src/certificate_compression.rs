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

#[cfg(all(test, feature = "compression"))]
pub(crate) mod test_util {
    use std::{
        io::{Result, Write},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use rama_boring::ssl::{CertificateCompressionAlgorithm, CertificateCompressor};

    use super::codecs::BrotliCertificateCompressor;

    /// A brotli decompressor that counts the certificates a peer compressed.
    pub(crate) struct CountingBrotli(pub(crate) Arc<AtomicUsize>);

    impl CertificateCompressor for CountingBrotli {
        const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
        const CAN_COMPRESS: bool = false;
        const CAN_DECOMPRESS: bool = true;

        fn decompress<W>(&self, input: &[u8], output: &mut W) -> Result<()>
        where
            W: Write,
        {
            self.0.fetch_add(1, Ordering::SeqCst);
            BrotliCertificateCompressor::default().decompress(input, output)
        }
    }
}
