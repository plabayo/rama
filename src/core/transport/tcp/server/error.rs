use std::io;

// TODO: delete this file (Instead keep errors local),
// and also try to do without thiserror and anyhow,
// as to see how well we can live without these deps

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("std I/O error")]
    IO(#[from] io::Error),
    #[error("Graceful interupt error")]
    Interupt,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
