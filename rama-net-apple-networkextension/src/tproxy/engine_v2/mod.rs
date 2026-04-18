use rama_core::graceful::Shutdown;
use std::sync::Arc;
use tokio::sync::mpsc;

mod svc_context;
pub use self::svc_context::TransparentProxyServiceContext;

mod handler;
pub use self::handler::{FlowAction, TransparentProxyHandler, TransparentProxyHandlerFactory};

mod builder;

mod runtime;
pub use self::runtime::{
    DefaultTransparentProxyAsyncRuntimeFactory, TransparentProxyAsyncRuntime,
    TransparentProxyAsyncRuntimeFactory,
};

pub struct TransparentProxyEngine<H> {
    rt: tokio::runtime::Runtime,
    handler: H,
    tcp_flow_buffer_size: usize,
    shutdown: Shutdown, //running is implicitly checked via shutdown
    stop_trigger: mpsc::UnboundedSender<()>,
    opaque_config: Option<Arc<[u8]>>,
} // no seperate state :)
