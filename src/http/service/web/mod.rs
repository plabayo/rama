//! basic web service

mod service;
pub use service::WebService;

/// create a k8s web health service
pub fn k8s_health<State>() -> WebService<State> {
    WebService::default()
        .get_fn("/k8s/alive", || async { Ok("ok") })
        .get_fn("/k8s/ready", || async { Ok("ok") })
}
