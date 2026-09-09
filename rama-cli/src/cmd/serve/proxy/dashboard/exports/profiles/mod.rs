use std::{
    fs::File as StdFile,
    io::{BufWriter, Seek as _, SeekFrom, Write as _},
    pin::Pin,
    task::{Context, Poll},
};

use rama::{
    stream::io::ReaderStream,
    ua::{inspect::ProfileExport, profile::UserAgentProfileInput},
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
    file: BufWriter<StdFile>,
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
    let mut staged = tokio::task::spawn_blocking(move || StagedProfiles::create(permit)).await??;
    let mut first = true;
    while let Some(profile) = export.next_profile().await? {
        staged = tokio::task::spawn_blocking(move || staged.write(profile, first)).await??;
        first = false;
    }
    tokio::task::spawn_blocking(move || staged.finish()).await?
}

impl StagedProfiles {
    // Serde's writer is synchronous. Write directly to a buffered file on the
    // blocking pool instead of collecting a profile-sized JSON buffer or
    // bouncing each write between synchronous and asynchronous file handles.
    fn create(permit: Option<OwnedSemaphorePermit>) -> Result<Self, BoxError> {
        let staging = TempDir::with_prefix("rama-proxy-profiles-")?;
        let file = OpenOptionsSync::new()
            .read(true)
            .write(true)
            .create_new(true)
            .created_file_permissions(CreatedFilePermissions::OwnerReadWrite)
            .jail(staging.path())
            .open("profiles.json")?;
        Ok(Self {
            file: BufWriter::with_capacity(kib(16), file),
            staging,
            permit,
        })
    }

    fn write(mut self, profile: UserAgentProfileInput, first: bool) -> Result<Self, BoxError> {
        self.file.write_all(if first { b"[" } else { b"," })?;
        serde_json::to_writer(&mut self.file, &profile)?;
        // Do not publish partially valid output. The typed conversion moves its
        // headers; no second decoded input or complete JSON buffer is created.
        profile.try_into_profile().map_err(|error| {
            IoError::new(
                ErrorKind::InvalidInput,
                format!(
                    "the selected observations do not form a complete emulation profile: {error}"
                ),
            )
        })?;
        Ok(self)
    }

    fn finish(mut self) -> Result<ProfileDownload, BoxError> {
        self.file.write_all(b"]")?;
        self.file.flush()?;
        let length = self.file.get_ref().metadata()?.len();
        self.file.seek(SeekFrom::Start(0))?;
        let file = self.file.into_inner().map_err(|error| error.into_error())?;
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
