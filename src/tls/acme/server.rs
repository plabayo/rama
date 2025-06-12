use super::proto::server::Directory;
use parking_lot::Mutex;
use rama_core::Context;
use rama_http::{Request, Response};
/// Very very basic acme server implementation, currently only useful
/// for testing but can extended to a full one
use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, atomic::AtomicU64},
};

struct AcmeServer {
    // This is not secure at all... Never us this for anything production related
    current_nonce: AtomicU64,
    // This will have very bad performance on scale...
    nonces: Mutex<Vec<u64>>,
    directory: Directory,
}

const REPLAY_NONCE_HEADER: &str = "replay-nonce";

impl AcmeServer {
    fn new(host: &str) -> Self {
        Self {
            current_nonce: AtomicU64::default(),
            nonces: Mutex::new(vec![]),
            directory: Directory {
                new_nonce: "/nonce".to_owned(),
                key_change: "/key_change".to_owned(),
                meta: None,
                new_order: "/new_order".to_owned(),
                new_account: "/new_account".to_owned(),
                new_authz: None,
                revoke_cert: "/revoke_cert".to_owned(),
            },
        }
    }

    fn nonce<State>(&self, ctx: Context<State>, req: Request) -> Result<Response, Infallible> {
        let nonce = self
            .current_nonce
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.nonces.lock().push(nonce);

        let resp = Response::builder()
            .header(REPLAY_NONCE_HEADER, nonce.clone())
            .body(rama_http::Body::empty())
            .unwrap();

        Ok(resp)
    }

    fn account<State>(ctx: Context<State>, req: Request) -> Result<Response, Infallible> {}
}
