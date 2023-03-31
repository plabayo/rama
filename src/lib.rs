pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub mod runtime;
pub mod service;
pub mod tcp;

mod error;
pub use error::{Error, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
