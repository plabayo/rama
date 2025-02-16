use super::{endpoint::Endpoint, IntoEndpointService, WebService};
use crate::{
    matcher::{HttpMatcher, UriParams},
    service::fs::ServeDir,
    Body, IntoResponse, Request, Response, StatusCode, Uri,
};
use rama_core::{
    context::Extensions,
    matcher::Matcher,
    service::{service_fn, BoxService, Service},
    Context,
};
use std::{convert::Infallible, fmt, future::Future, marker::PhantomData, sync::Arc};
use std::collections::HashMap;
use http::Method;

/// A basic web router that can be used to serve HTTP requests based on path matching.
/// It will also provide extraction of path parameters and wildcards out of the box so
/// you can define your paths accordingly.

#[derive(Debug)]
enum RouterError {
    NotFound,
    MethodNotAllowed,
    InternalServerError,
}

impl std::fmt::Display for RouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for RouterError {}

struct TrieNode<State> {
    children: HashMap<String, TrieNode<State>>,
    param_child: Option<Box<TrieNode<State>>>,
    wildcard_child: Option<Box<TrieNode<State>>>,
    param_name: Option<String>,
    handlers: HashMap<Method, Arc<BoxService<State, Request<Body>, Response<Body>, RouterError>>>
}

impl<State> TrieNode<State> {
    fn new() -> Self {
        Self {
            children: HashMap::new(),
            param_child: None,
            wildcard_child: None,
            handlers: HashMap::new(),
            param_name: None,
        }
    }
}

impl<State> Clone for TrieNode<State> {
    fn clone(&self) -> Self {
        Self {
            children: self.children.clone(),
            param_child: self.param_child.as_ref().map(|child| child.clone()),
            wildcard_child: self.wildcard_child.as_ref().map(|child| child.clone()),
            handlers: self.handlers.clone(),
            param_name: self.param_name.clone(),
        }
    }
}

pub struct Router<State> {
    routes: TrieNode<State>
}

impl<State> std::fmt::Debug for Router<State> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router").finish()
    }
}

impl<State> Clone for Router<State> {
    fn clone(&self) -> Self {
        Self {
            routes: self.routes.clone(),
        }
    }
}

/// default trait
impl<State> Default for Router<State>
where
    State: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<State> Router<State>
where
    State: Clone + Send + Sync + 'static,
{
    /// create a new web router
    pub(crate) fn new() -> Self {
        Self {
            routes: TrieNode::new(),
        }
    }
}
