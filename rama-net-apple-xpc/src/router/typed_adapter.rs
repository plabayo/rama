use rama_core::{
    Service,
    error::{BoxError, ErrorContext as _},
};
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    XpcMessage,
    call::XpcCall,
    xpc_serde::{from_xpc_message, to_xpc_message},
};

use super::RESULT_KEY;

/// Adapts a [`Service<Req>`] with Serde-capable request/response types into a
/// raw [`Service<XpcMessage>`] that wraps the reply in `{"$result": …}`.
///
/// - The first `XpcMessage` in the incoming `$arguments` array is deserialized
///   as `Req`.
/// - The `Res` value returned by the service is serialized and wrapped as
///   `{"$result": <value>}`.
/// - If the service returns `()`, the reply is `{"$result": null}`.
pub(super) struct TypedAdapter<Req, Res, S> {
    service: S,
    _marker: std::marker::PhantomData<fn(Req) -> Res>,
}

impl<Req, Res, S> TypedAdapter<Req, Res, S> {
    pub(super) fn new(service: S) -> Self {
        Self {
            service,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<Req, Res, S> Service<XpcMessage> for TypedAdapter<Req, Res, S>
where
    Req: DeserializeOwned + Send + 'static,
    Res: Serialize + Send + 'static,
    S: Service<Req, Output = Res, Error: Into<BoxError>>,
{
    type Output = Option<XpcMessage>;
    type Error = BoxError;

    async fn serve(&self, input: XpcMessage) -> Result<Self::Output, Self::Error> {
        // Decode the call to extract arguments.
        let call = XpcCall::try_from(input).context("create Xpc call")?;

        // Take the first argument as the request payload.
        let arg = call
            .arguments
            .into_iter()
            .next()
            .unwrap_or(XpcMessage::Null);
        let req: Req = from_xpc_message(arg).context("convert arg as Xpc Message")?;

        // Call the inner service.
        let res: Res = self
            .service
            .serve(req)
            .await
            .context("TypeAdapter: serve xpc message")?;

        // Serialize the result and wrap it.
        let result_msg = to_xpc_message(&res).map_err(BoxError::from)?;
        let mut map = std::collections::BTreeMap::new();
        map.insert(RESULT_KEY.to_owned(), result_msg);
        Ok(Some(XpcMessage::Dictionary(map)))
    }
}
