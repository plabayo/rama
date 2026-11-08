//! The scope an input runs in, carried in its extensions.

use std::fmt;

use crate::extensions::{Extension, Extensions};

use super::{Scope, WeakScope};

/// The only form in which a scope travels in extensions: weak, so a retained copy of the
/// extensions never holds a drain open, and private, so it is only set through
/// [`attach_scope`] and [`enter_scope`].
#[derive(Debug, Clone, Extension)]
struct ScopeContext(WeakScope);

/// The scope an input runs in: every scope attached to its extensions, merged; `None` if
/// none is attached.
#[must_use]
pub fn scope_context(extensions: &Extensions) -> Option<WeakScope> {
    let mut contexts = extensions
        .iter_ref::<ScopeContext>()
        .map(|context| context.0.clone())
        .peekable();
    contexts.peek()?;
    Some(WeakScope::fold(contexts))
}

/// Make the input of `extensions` also run in `scope`.
///
/// Attaching holds nothing: whoever runs the input holds the scopes it runs in.
pub fn attach_scope(extensions: &Extensions, scope: &Scope) {
    if !scope.is_detached() {
        extensions.insert(ScopeContext(scope.clone_weak()));
    }
}

/// Run the input of `extensions` in a new scope below the scope it runs in, and attach it.
///
/// Returns that scope for the caller to hold while it serves the input. Without a scope to
/// run in it is a new root, so every input can be ended on its own.
///
/// # Errors
///
/// [`ScopeClosed`] once the scope the input runs in is closing: it admits no new work.
pub fn enter_scope(extensions: &Extensions) -> Result<Scope, ScopeClosed> {
    enter(extensions, None)
}

/// Like [`enter_scope`], with the new scope also below `own` (see [`Scope::child_of`]), such
/// as the scope of the server that serves the input.
///
/// # Errors
///
/// [`ScopeClosed`] once the scope the input runs in, or `own`, is closed.
pub fn enter_scope_with(extensions: &Extensions, own: &WeakScope) -> Result<Scope, ScopeClosed> {
    let own = own.try_hold()?;
    enter(extensions, Some(&own))
}

fn enter(extensions: &Extensions, own: Option<&Scope>) -> Result<Scope, ScopeClosed> {
    let context = match scope_context(extensions) {
        Some(context) => Some(context.into_scope().ok_or(ScopeClosed)?),
        None => None,
    };
    let scope = Scope::child_of(context.iter().chain(own));
    attach_scope(extensions, &scope);
    Ok(scope)
}

/// The scope an input runs in is closing and admits no new work, see [`enter_scope`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ScopeClosed;

impl fmt::Display for ScopeClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the input's scope is closed")
    }
}

impl std::error::Error for ScopeClosed {}
