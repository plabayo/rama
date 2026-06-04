//! A minimal in-memory element tree that implements [`SelectorSubject`].
//!
//! This is a convenience for matching selectors against a materialized
//! tree (and for testing the engine); the streaming HTML parser does not
//! use it. Only element nodes and their attributes are modelled — text and
//! comments are irrelevant to selector matching.

use super::matcher::SelectorSubject;

/// Handle to an element within a [`Dom`].
///
/// Returned by [`Dom::create`] / [`Dom::append`]; only valid for the
/// `Dom` that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeId(usize);

#[derive(Debug)]
struct Attribute {
    name: String,
    value: String,
}

#[derive(Debug)]
struct NodeData {
    name: String,
    attributes: Vec<Attribute>,
    parent: Option<usize>,
    children: Vec<usize>,
}

/// A simple arena-backed element tree.
///
/// ```
/// use rama_http::protocols::html::selector::{Dom, Selector};
///
/// let mut dom = Dom::new();
/// let ul = dom.create("ul");
/// let first = dom.append(ul, "li");
/// let second = dom.append(ul, "li");
///
/// let odd: Selector = "li:nth-child(odd)".parse().unwrap();
/// assert!(odd.matches(&dom.element(first)));
/// assert!(!odd.matches(&dom.element(second)));
/// ```
#[derive(Debug, Default)]
pub struct Dom {
    nodes: Vec<NodeData>,
}

impl Dom {
    /// Creates an empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a parentless (root) element with the given tag name.
    pub fn create(&mut self, name: &str) -> NodeId {
        self.push(name, None)
    }

    /// Appends a new child element to `parent` and returns its id.
    pub fn append(&mut self, parent: NodeId, name: &str) -> NodeId {
        let id = self.push(name, Some(parent.0));
        if let Some(node) = self.nodes.get_mut(parent.0) {
            node.children.push(id.0);
        }
        id
    }

    /// Sets (or replaces) an attribute on `node`.
    pub fn set_attr(&mut self, node: NodeId, name: &str, value: &str) {
        let Some(data) = self.nodes.get_mut(node.0) else {
            return;
        };
        if let Some(existing) = data
            .attributes
            .iter_mut()
            .find(|attr| attr.name.eq_ignore_ascii_case(name))
        {
            existing.value = value.to_owned();
        } else {
            data.attributes.push(Attribute {
                name: name.to_owned(),
                value: value.to_owned(),
            });
        }
    }

    /// Returns a [`SelectorSubject`] handle for `node`.
    #[must_use]
    pub fn element(&self, node: NodeId) -> Element<'_> {
        Element {
            dom: self,
            id: node.0,
        }
    }

    fn push(&mut self, name: &str, parent: Option<usize>) -> NodeId {
        let id = self.nodes.len();
        self.nodes.push(NodeData {
            name: name.to_owned(),
            attributes: Vec::new(),
            parent,
            children: Vec::new(),
        });
        NodeId(id)
    }
}

/// A cheap, copyable view of an element in a [`Dom`].
#[derive(Debug, Clone, Copy)]
pub struct Element<'a> {
    dom: &'a Dom,
    id: usize,
}

impl Element<'_> {
    fn data(&self) -> Option<&NodeData> {
        self.dom.nodes.get(self.id)
    }
}

impl SelectorSubject for Element<'_> {
    fn local_name(&self) -> &str {
        self.data().map_or("", |d| d.name.as_str())
    }

    fn attribute(&self, name: &str) -> Option<&str> {
        self.data()?
            .attributes
            .iter()
            .find(|attr| attr.name.eq_ignore_ascii_case(name))
            .map(|attr| attr.value.as_str())
    }

    fn parent(&self) -> Option<Self> {
        let parent = self.data()?.parent?;
        Some(Self {
            dom: self.dom,
            id: parent,
        })
    }

    fn nth_child_index(&self) -> usize {
        let Some(data) = self.data() else {
            return 1;
        };
        let Some(parent) = data.parent.and_then(|p| self.dom.nodes.get(p)) else {
            return 1;
        };
        parent
            .children
            .iter()
            .position(|&c| c == self.id)
            .map_or(1, |i| i + 1)
    }

    fn nth_of_type_index(&self) -> usize {
        let Some(data) = self.data() else {
            return 1;
        };
        let Some(parent) = data.parent.and_then(|p| self.dom.nodes.get(p)) else {
            return 1;
        };
        let mut index = 0;
        for &child in &parent.children {
            if let Some(sibling) = self.dom.nodes.get(child)
                && sibling.name.eq_ignore_ascii_case(&data.name)
            {
                index += 1;
            }
            if child == self.id {
                return index.max(1);
            }
        }
        index.max(1)
    }
}
