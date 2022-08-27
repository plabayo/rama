use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error")]
    IO(#[from] std::io::Error),
    #[error("non-specific error")]
    Any(String),
}
