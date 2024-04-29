#[derive(Debug)]
/// An iterator over the chain of errors.
///
/// Created by the [`ErrorExt::chain`](super::ErrorExt::chain) method.
///
/// See the [module level documentation](crate::error) for more information.
pub struct Chain<'a> {
    state: ChainState<'a>,
}

#[derive(Debug, Clone)]
pub(crate) enum ChainState<'a> {
    Linked {
        next: Option<&'a (dyn std::error::Error + 'static)>,
    },
    Buffered {
        rest: std::vec::IntoIter<&'a (dyn std::error::Error + 'static)>,
    },
}

use ChainState::{Buffered, Linked};

impl<'a> Chain<'a> {
    pub(crate) fn new(head: &'a (dyn std::error::Error + 'static)) -> Self {
        Chain {
            state: ChainState::Linked { next: Some(head) },
        }
    }
}

impl<'a> Iterator for Chain<'a> {
    type Item = &'a (dyn std::error::Error + 'static);

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.state {
            Linked { next } => {
                let error = (*next)?;
                *next = error.source();
                Some(error)
            }
            Buffered { rest } => rest.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl DoubleEndedIterator for Chain<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match &mut self.state {
            Linked { mut next } => {
                let mut rest = Vec::new();
                while let Some(cause) = next {
                    next = cause.source();
                    rest.push(cause);
                }
                let mut rest = rest.into_iter();
                let last = rest.next_back();
                self.state = Buffered { rest };
                last
            }
            Buffered { rest } => rest.next_back(),
        }
    }
}

impl ExactSizeIterator for Chain<'_> {
    fn len(&self) -> usize {
        match &self.state {
            Linked { mut next } => {
                let mut len = 0;
                while let Some(cause) = next {
                    next = cause.source();
                    len += 1;
                }
                len
            }
            Buffered { rest } => rest.len(),
        }
    }
}
