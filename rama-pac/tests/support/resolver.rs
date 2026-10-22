pub(crate) fn builder() -> rama_pac::PacResolverBuilder {
    rama_pac::PacResolver::builder()
        .with_runtime(crate::runtime_support::builder().without_loop_iteration_limit())
}
