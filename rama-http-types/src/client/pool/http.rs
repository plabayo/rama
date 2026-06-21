use crate::Request;
use rama_core::error::BoxError;
use rama_core::error::BoxErrorExt as _;
use rama_core::extensions::ExtensionsRef;
use rama_net::client::pool::ReqToConnID;
use rama_net::client::pool::http::{BasicHttpConId, BasicHttpConnIdentifier};
use rama_net::{AuthorityInputExt, Protocol, ProtocolInputExt};

impl<Body> ReqToConnID<Request<Body>> for BasicHttpConnIdentifier {
    type ID = BasicHttpConId;

    fn id(&self, req: &Request<Body>) -> Result<Self::ID, BoxError> {
        let authority = req
            .authority()
            .ok_or_else(|| BoxError::from_static_str("no authority found in http request"))?;
        let protocol = req.protocol().unwrap_or(Protocol::HTTP);

        Ok(BasicHttpConId {
            protocol,
            authority,
            proxy_address: req.extensions().get_ref().cloned(),
            connector_target: req.extensions().get_ref().cloned(),
        })
    }
}
