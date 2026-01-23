//! Default Error type for Abortable middleware.

rama_utils::macros::error::static_str_error! {
    #[doc = "service was aborted via controller"]
    pub struct Aborted;
}
