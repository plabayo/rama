use std::{
    fs::File as StdFile,
    io::{BufWriter, Seek as _, SeekFrom},
    pin::Pin,
    task::{Context, Poll},
    time::SystemTime,
};

use rama::{
    stream::io::ReaderStream,
    tls::boring::core::rand::rand_bytes,
    ua::{
        inspect::ProfileExport,
        profile::{
            ProfileArchiveEntry, ProfileArchiveLimits, ProfileArchiveWriter, ProfileDataError,
            profile_utc_day,
        },
    },
    utils::{
        fs::{CreatedFilePermissions, OpenOptionsSync, TempDir},
        octets::kib,
    },
};
use tokio::{
    fs::File,
    io::{AsyncRead, ReadBuf},
    sync::OwnedSemaphorePermit,
};

use super::*;

// The blocking writer owns its staging directory and admission. If its caller
// cancels during serialization, both survive until the blocking operation ends.
struct StagedProfiles {
    file: ProfileArchiveWriter<BufWriter<StdFile>>,
    staging: TempDir,
    permit: Option<OwnedSemaphorePermit>,
}

pub(super) struct ProfileDownload {
    file: File,
    _staging: TempDir,
    _permit: Option<OwnedSemaphorePermit>,
    length: u64,
}

impl AsyncRead for ProfileDownload {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.file).poll_read(cx, buffer)
    }
}

impl IntoResponse for ProfileDownload {
    fn into_response(self) -> Response {
        (
            Headers((
                ContentType::json(),
                ContentLength(self.length),
                ContentDisposition::attachment("rama-emulation-profiles.json"),
                CacheControl::new().with_no_store(),
            )),
            Body::from_stream(ReaderStream::new(self)),
        )
            .into_response()
    }
}

pub(super) async fn download(
    capture: &CaptureStore,
    requests: &BTreeSet<u64>,
    connections: &BTreeSet<u64>,
    permit: Option<OwnedSemaphorePermit>,
) -> Result<ProfileDownload, BoxError> {
    let mut export = ProfileExport::new(capture, requests, connections);
    if export.is_empty() {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "the selection has no captured user-agent profile observations",
        )
        .into());
    }
    let day = profile_utc_day(SystemTime::now())?;
    let horizon = 14;
    let limits = ProfileArchiveLimits::default();
    let mut seed = [0; 32];
    rand_bytes(&mut seed)?;
    let mut staged =
        tokio::task::spawn_blocking(move || StagedProfiles::create(permit, day, horizon, limits))
            .await??;
    let mut wrote = false;
    while let Some(entry) = export
        .next_evidence(day, horizon, seed, limits.profile)
        .await?
    {
        staged = tokio::task::spawn_blocking(move || staged.write(entry)).await??;
        wrote = true;
    }
    if !wrote {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "the selection has no profiles in the freshness window",
        )
        .into());
    }
    tokio::task::spawn_blocking(move || staged.finish()).await?
}

impl StagedProfiles {
    // Serde's writer is synchronous. Write directly to a buffered file on the
    // blocking pool instead of collecting a profile-sized JSON buffer or
    // bouncing each write between synchronous and asynchronous file handles.
    fn create(
        permit: Option<OwnedSemaphorePermit>,
        day: u32,
        horizon: u32,
        limits: ProfileArchiveLimits,
    ) -> Result<Self, BoxError> {
        let staging = TempDir::with_prefix("rama-proxy-profiles-")?;
        let file = OpenOptionsSync::new()
            .read(true)
            .write(true)
            .create_new(true)
            .created_file_permissions(CreatedFilePermissions::OwnerReadWrite)
            .jail(staging.path())
            .open("profiles.json")?;
        Ok(Self {
            file: ProfileArchiveWriter::new(
                BufWriter::with_capacity(kib(16), file),
                false,
                day,
                horizon,
                limits,
            )?,
            staging,
            permit,
        })
    }

    fn write(mut self, entry: ProfileArchiveEntry) -> Result<Self, BoxError> {
        self.file = self.file.write_profile(entry).map_err(|error| {
            if error.downcast_ref::<ProfileDataError>().is_some() {
                BoxError::from(IoError::new(ErrorKind::InvalidInput, error))
            } else {
                error
            }
        })?;
        Ok(self)
    }

    fn finish(self) -> Result<ProfileDownload, BoxError> {
        let mut file = self
            .file
            .finish()?
            .into_inner()
            .map_err(|error| error.into_error())?;
        let length = file.metadata()?.len();
        file.seek(SeekFrom::Start(0))?;
        Ok(ProfileDownload {
            file: File::from_std(file),
            _staging: self.staging,
            _permit: self.permit,
            length,
        })
    }
}

#[cfg(test)]
mod tests;
