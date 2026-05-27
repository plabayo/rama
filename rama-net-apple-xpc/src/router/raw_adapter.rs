use rama_core::{
    Service,
    error::{BoxError, ErrorContext as _},
};

use crate::XpcMessage;

/// Adapts a raw [`Service<XpcMessage, Output = Option<XpcMessage>>`] whose
/// `Error` type implements `Into<BoxError>` for use as a router entry.
pub(super) struct RawAdapter<S>(pub(super) S);

impl<S> Service<XpcMessage> for RawAdapter<S>
where
    S: Service<XpcMessage, Output = Option<XpcMessage>, Error: Into<BoxError>>,
{
    type Output = Option<XpcMessage>;
    type Error = BoxError;

    async fn serve(&self, input: XpcMessage) -> Result<Self::Output, Self::Error> {
        self.0
            .serve(input)
            .await
            .context("RawAdapter: serve XpcMessage with inner")
    }
}
