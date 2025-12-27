use rama_core::Service;
use rama_http_types::Uri;

use crate::status::ConnectError;

#[cfg(not(target_os = "windows"))]
use tokio::net::UnixStream;

#[cfg(not(target_os = "windows"))]
async fn connect_uds(uds_path: &str) -> Result<UnixStream, ConnectError> {
    UnixStream::connect(uds_path)
        .await
        .map_err(|err| ConnectError(From::from(err)))
}

// Dummy type that will allow us to compile and match trait bounds
// but is never used.
#[cfg(target_os = "windows")]
#[allow(dead_code)]
type UnixStream = tokio::io::DuplexStream;

#[cfg(target_os = "windows")]
async fn connect_uds(_uds_path: &str) -> Result<UnixStream, ConnectError> {
    Err(ConnectError(
        "uds connections are not allowed on windows".into(),
    ))
}

pub(crate) struct UdsConnector {
    uds_filepath: String,
}

impl UdsConnector {
    pub(crate) fn new(uds_filepath: &str) -> Self {
        UdsConnector {
            uds_filepath: uds_filepath.to_string(),
        }
    }
}

impl Service<Uri> for UdsConnector {
    type Output = UnixStream;
    type Error = ConnectError;

    async fn serve(&self, _: Uri) -> Result<Self::Output, Self::Error> {
        connect_uds(&self.uds_filepath).await
    }
}
