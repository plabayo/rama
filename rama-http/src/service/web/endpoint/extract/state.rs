use std::ops::{Deref, DerefMut};

use rama_core::conversion::FromRef;
use rama_http_types::request::Parts;

use crate::service::web::extract::FromPartsStateRefPair;

#[derive(Debug, Default, Clone, Copy)]
/// Extractor for static State provided by the caller of [`IntoEndpointServiceWithState`]
///
/// `S` can be the exact provided `State` or any type that implements [`FromRef<State>`]
///
/// [`IntoEndpointServiceWithState`]: crate::service::web::IntoEndpointServiceWithState
pub struct State<S>(pub S);

impl<OuterState, InnerState> FromPartsStateRefPair<OuterState> for State<InnerState>
where
    OuterState: Send + Sync,
    InnerState: FromRef<OuterState> + Send + Sync + 'static,
{
    type Rejection = std::convert::Infallible;

    async fn from_parts_state_ref_pair(
        _parts: &Parts,
        state: &OuterState,
    ) -> Result<Self, Self::Rejection> {
        let inner_state = InnerState::from_ref(state);
        Ok(Self(inner_state))
    }
}

impl<S> Deref for State<S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> DerefMut for State<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
