//! zstd-compressed profile archives, the form in which profiles are embedded.

use std::{
    fmt,
    io::{self, Read as _, Write},
};

use rama_core::error::{BoxError, ErrorContext as _};

use crate::profile::{
    format::{
        archive::ProfileArchiveLimits, canonical::ProfileDataError, input::try_load_profiles_json,
    },
    model::ua::UserAgentProfile,
};

// Fixed single-threaded parameters keep the output reproducible.
const LEVEL: i32 = 19;
const WINDOW_LOG: u32 = 23;
const MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// Streaming compressor for a profile archive document.
pub struct CompressedProfileArchiveWriter<W: Write> {
    encoder: zstd::Encoder<'static, W>,
}

impl<W: Write> fmt::Debug for CompressedProfileArchiveWriter<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompressedProfileArchiveWriter")
            .finish_non_exhaustive()
    }
}

impl<W: Write> CompressedProfileArchiveWriter<W> {
    pub fn new(writer: W) -> io::Result<Self> {
        let mut encoder = zstd::Encoder::new(writer, LEVEL)?;
        encoder.window_log(WINDOW_LOG)?;
        encoder.include_checksum(true)?;
        Ok(Self { encoder })
    }

    /// Complete the frame and return the inner writer.
    pub fn finish(self) -> io::Result<W> {
        self.encoder.finish()
    }
}

impl<W: Write> Write for CompressedProfileArchiveWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.encoder.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.encoder.flush()
    }
}

/// Whether `bytes` start like a compressed profile archive.
#[must_use]
pub fn is_compressed_profile_archive(bytes: &[u8]) -> bool {
    bytes.starts_with(&MAGIC)
}

/// Decompress a profile archive, failing once it exceeds `limit` bytes.
pub fn decompress_profile_archive(bytes: &[u8], limit: usize) -> Result<Vec<u8>, BoxError> {
    let mut decoder = zstd::Decoder::with_buffer(bytes).context("init profile archive decoder")?;
    decoder
        .window_log_max(WINDOW_LOG)
        .context("init profile archive decoder")?;
    let mut output = Vec::new();
    decoder
        .take(limit as u64 + 1)
        .read_to_end(&mut output)
        .context("decompress profile archive")?;
    if output.len() > limit {
        return Err(ProfileDataError::LimitExceeded("decompressed profile archive bytes").into());
    }
    Ok(output)
}

/// Decompress and load a non-empty profile archive within the default archive limits.
pub fn try_load_compressed_profiles(bytes: &[u8]) -> Result<Vec<UserAgentProfile>, BoxError> {
    let json = decompress_profile_archive(bytes, ProfileArchiveLimits::default().bytes)?;
    let profiles = try_load_profiles_json(&json)?;
    if profiles.is_empty() {
        return Err(ProfileDataError::Incomplete("compressed profile archive profiles").into());
    }
    Ok(profiles)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compress(bytes: &[u8]) -> Vec<u8> {
        let mut writer = CompressedProfileArchiveWriter::new(Vec::new()).unwrap();
        writer.write_all(bytes).unwrap();
        writer.finish().unwrap()
    }

    #[test]
    fn compression_round_trips_deterministically_within_bounds() {
        let input = br#"{"format_version":1,"profiles":[]}"#.repeat(64);
        let compressed = compress(&input);
        assert!(is_compressed_profile_archive(&compressed));
        assert_eq!(compress(&input), compressed);
        assert_eq!(
            decompress_profile_archive(&compressed, input.len()).unwrap(),
            input
        );
        decompress_profile_archive(&compressed, input.len() - 1).unwrap_err();
        decompress_profile_archive(&input, input.len()).unwrap_err();
        let mut corrupt = compressed;
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        decompress_profile_archive(&corrupt, input.len()).unwrap_err();
    }

    #[test]
    fn empty_compressed_archives_are_rejected() {
        let empty =
            compress(br#"{"format_version":1,"generated_day":100,"horizon":14,"profiles":[]}"#);
        try_load_compressed_profiles(&empty).unwrap_err();
        try_load_compressed_profiles(&compress(b"[]")).unwrap_err();
    }
}
