use std::sync::Arc;

use rama_core::{
    error::{BoxError, ErrorContext},
    graceful::Shutdown,
    rt::Executor,
};
use tokio::sync::mpsc;

use super::{
    DefaultTransparentProxyAsyncRuntimeFactory, TransparentProxyAsyncRuntimeFactory,
    TransparentProxyEngine, TransparentProxyHandlerFactory, TransparentProxyServiceContext,
};

const DEFAULT_TCP_FLOW_BUFFER_SIZE: usize = 64 * 1024; // 64 KiB

pub struct TransparentProxyEngineBuilder<F, R = DefaultTransparentProxyAsyncRuntimeFactory> {
    handler_factory: F,
    tcp_flow_buffer_size: Option<usize>,
    opaque_config: Option<Arc<[u8]>>,
    runtime_factory: R,
}

impl<F> TransparentProxyEngineBuilder<F>
where
    F: TransparentProxyHandlerFactory,
{
    #[must_use]
    pub fn new(factory: F) -> Self {
        Self {
            handler_factory: factory,
            tcp_flow_buffer_size: None,
            opaque_config: None,
            runtime_factory: DefaultTransparentProxyAsyncRuntimeFactory::default(),
        }
    }

    /// define a custom runtime async factory
    pub fn with_runtime_factory<R: TransparentProxyAsyncRuntimeFactory>(
        self,
        runtime_factory: R,
    ) -> TransparentProxyEngineBuilder<F, R> {
        TransparentProxyEngineBuilder {
            handler_factory: self.handler_factory,
            tcp_flow_buffer_size: self.tcp_flow_buffer_size,
            opaque_config: self.opaque_config,
            runtime_factory,
        }
    }
}

impl<F, RF> TransparentProxyEngineBuilder<F, RF>
where
    F: TransparentProxyHandlerFactory,
    RF: TransparentProxyAsyncRuntimeFactory,
{
    rama_utils::macros::generate_set_and_with! {
        /// Define what size to use for the TCP flow buffer (`None` will use default)
        pub fn tcp_flow_buffer_size(mut self, size: Option<usize>) -> Self
        {
            self.tcp_flow_buffer_size = size;
            self
        }
    }

    #[must_use]
    pub fn opaque_config(mut self, opaque_config: Option<Arc<[u8]>>) -> Self {
        self.opaque_config = opaque_config;
        self
    }

    #[must_use]
    pub fn build(self) -> Result<TransparentProxyEngine<F::Handler>, BoxError> {
        let Self {
            handler_factory,
            tcp_flow_buffer_size,
            opaque_config,
            runtime_factory,
        } = self;

        let rt = runtime_factory
            .create_async_runtime(opaque_config.as_deref())
            .context("TransparentProxyEngineBuilder: create async runtime")?;

        let (stop_tx, mut stop_rx) = mpsc::unbounded_channel::<()>();
        let shutdown = {
            let _enter = rt.enter();
            Shutdown::new(async move {
                let _ = stop_rx.recv().await;
            })
        };
        let guard = shutdown.guard();
        let ctx = TransparentProxyServiceContext {
            executor: Executor::graceful(guard),
            opaque_config: opaque_config.clone(),
        };

        let handler = rt
            .block_on(handler_factory.create_transparent_proxy_handler(ctx))
            .context("create tproxy handler")?;

        Ok(TransparentProxyEngine {
            rt,
            handler,
            tcp_flow_buffer_size: tcp_flow_buffer_size.unwrap_or(DEFAULT_TCP_FLOW_BUFFER_SIZE),
            shutdown,
            stop_trigger: stop_tx,
            opaque_config,
        })
    }
}
