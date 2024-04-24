//! A retry "budget" for allowing only a certain amount of retries over time.
//!
//! # Why budgets and not max retries?
//!
//! The most common way of configuring retries is to specify a maximum
//! number of retry attempts to perform before giving up. This is a familiar idea to anyone
//! who’s used a web browser: you try to load a webpage, and if it doesn’t load, you try again.
//! If it still doesn’t load, you try a third time. Finally you give up.
//!
//! Unfortunately, there are at least two problems with configuring retries this way:
//!
//! **Choosing the maximum number of retry attempts is a guessing game.**
//! You need to pick a number that’s high enough to make a difference when things are somewhat failing,
//! but not so high that it generates extra load on the system when it’s really failing. In practice,
//! you usually pick a maximum retry attempts number out of a hat (e.g. 3) and hope for the best.
//!
//! **Systems configured this way are vulnerable to retry storms.**
//! A retry storm begins when one service starts to experience a larger than normal failure rate.
//! This causes its clients to retry those failed requests. The extra load from the retries causes the
//! service to slow down further and fail more requests, triggering more retries. If each client is
//! configured to retry up to 3 times, this can quadruple the number of requests being sent! To make
//! matters even worse, if any of the clients’ clients are configured with retries, the number of retries
//! compounds multiplicatively and can turn a small number of errors into a self-inflicted denial of service attack.
//!
//! It's generally dangerous to implement retries without some limiting factor. [`Budget`]s are that limit.
//!
//! # Examples
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use rama::service::Context;
//! use rama::http::Request;
//! use rama::http::layer::retry::{budget::{Budget, TpsBudget}, Policy, PolicyResult, RetryBody};
//!
//! #[derive(Clone, Debug)]
//! struct RetryPolicy {
//!     budget: Arc<TpsBudget>,
//! }
//!
//! impl<S, R, E> Policy<S, R, E> for RetryPolicy
//!     where
//!         S: Send + Sync + 'static,
//!         R: Send + 'static,
//!         E: Send + Sync + 'static,
//! {
//!     async fn retry(&self, ctx: Context<S>, req: Request<RetryBody>, result: Result<R, E>) -> PolicyResult<S, R, E> {
//!         match result {
//!             Ok(_) => {
//!                 // Treat all `Response`s as success,
//!                 // so deposit budget and don't retry...
//!                 self.budget.deposit();
//!                 PolicyResult::Abort(result)
//!             }
//!             Err(_) => {
//!                 // Treat all errors as failures...
//!                 // Withdraw the budget, don't retry if we overdrew.
//!                 let withdrew = self.budget.withdraw();
//!                 if !withdrew {
//!                     return PolicyResult::Abort(result);
//!                 }
//!
//!                 // Try again!
//!                 PolicyResult::Retry{
//!                    ctx,
//!                    req,
//!                 }
//!             }
//!         }
//!     }
//!
//!     fn clone_input(&self, ctx: &Context<S>, req: &Request<RetryBody>) -> Option<(Context<S>, Request<RetryBody>)> {
//!         Some((ctx.clone(), req.clone()))
//!     }
//! }
//! ```

pub mod tps_budget;

pub use tps_budget::TpsBudget;

/// For more info about [`Budget`], please see the [module-level documentation].
///
/// [module-level documentation]: self
pub trait Budget {
    /// Store a "deposit" in the budget, which will be used to permit future
    /// withdrawals.
    fn deposit(&self);

    /// Check whether there is enough "balance" in the budget to issue a new
    /// retry.
    ///
    /// If there is not enough, false is returned.
    fn withdraw(&self) -> bool;
}
