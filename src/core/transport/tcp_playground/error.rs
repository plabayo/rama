use std::io;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("std I/O error")]
    Disconnect(#[from] io::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
