use crate::Request;
use crate::request_context::RequestContext;
use rama_core::error::BoxError;
use rama_core::extensions::ExtensionsRef;
use rama_net::client::pool::ReqToConnID;
use rama_net::client::pool::http::{BasicHttpConId, BasicHttpConnIdentifier};

impl<Body> ReqToConnID<Request<Body>> for BasicHttpConnIdentifier {
    type ID = BasicHttpConId;

    fn id(&self, req: &Request<Body>) -> Result<Self::ID, BoxError> {
        let RequestContext {
            http_version: _,
            protocol,
            authority,
        } = RequestContext::try_from(req)?;

        Ok(BasicHttpConId {
            protocol,
            authority,
            proxy_address: req.extensions().get_ref().cloned(),
            connector_target: req.extensions().get_ref().cloned(),
        })
    }
}
