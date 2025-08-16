//! Code adapted from
//! <https://github.com/graphform/ratchet/blob/ef05a54eeec533f8fdf308053f65e5a1f5bd34ff/ratchet_deflate/src/lib.rs>
//! Original code was Apache licensed by Swim Inc.

use crate::protocol::{PerMessageDeflateConfig, Role};
use flate2::{
    Compress, CompressError, Compression, Decompress, DecompressError, FlushCompress,
    FlushDecompress, Status,
};
use rama_core::error::{ErrorContext, OpaqueError};
use std::slice;

#[derive(Debug)]
pub(super) struct PerMessageDeflateState {
    pub(super) decompress_next_incomplete_msg: bool,
    pub(super) decompress_next_incomplete_msg_as_txt: bool,
    pub(super) encoder: DeflateEncoder,
    pub(super) decoder: DeflateDecoder,
}

impl PerMessageDeflateState {
    pub(super) fn new(role: Role, cfg: PerMessageDeflateConfig) -> Self {
        match role {
            Role::Server => Self {
                decompress_next_incomplete_msg: false,
                decompress_next_incomplete_msg_as_txt: false,

                // server -> client
                encoder: DeflateEncoder::new(
                    Compression::default(),
                    cfg.server_max_window_bits.unwrap_or(15),
                    cfg.server_no_context_takeover,
                ),
                // client -> server
                decoder: DeflateDecoder::new(
                    cfg.client_max_window_bits.unwrap_or(15),
                    cfg.client_no_context_takeover,
                ),
            },
            Role::Client => Self {
                decompress_next_incomplete_msg: false,
                decompress_next_incomplete_msg_as_txt: false,

                // client -> server
                encoder: DeflateEncoder::new(
                    Compression::default(),
                    cfg.client_max_window_bits.unwrap_or(15),
                    cfg.client_no_context_takeover,
                ),
                // server -> client
                decoder: DeflateDecoder::new(
                    cfg.server_max_window_bits.unwrap_or(15),
                    cfg.server_no_context_takeover,
                ),
            },
        }
    }
}

const DEFLATE_TRAILER: [u8; 4] = [0, 0, 255, 255];

/// A permessage-deflate compressor.
#[derive(Debug)]
pub(super) struct DeflateEncoder {
    compress: Compress,
    compress_reset: bool,
}

impl DeflateEncoder {
    pub(super) fn new(compression: Compression, mut window_size: u8, compress_reset: bool) -> Self {
        // https://github.com/madler/zlib/blob/cacf7f1d4e3d44d871b605da3b647f07d718623f/deflate.c#L303
        if window_size == 8 {
            window_size = 9;
        }

        Self {
            compress: Compress::new_with_window_bits(compression, false, window_size),
            compress_reset,
        }
    }

    pub(super) fn encode(&mut self, input_data: &[u8]) -> Result<Vec<u8>, OpaqueError> {
        if input_data.is_empty() {
            return Ok(vec![0x00]);
        }

        let mut buf = Vec::with_capacity(input_data.len() * 2);

        let before_in = self.compress.total_in();

        while self.compress.total_in() - before_in < input_data.as_ref().len() as u64 {
            let i = self.compress.total_in() as usize - before_in as usize;
            match self
                .compress
                .buf_compress(&input_data[i..], &mut buf, FlushCompress::Sync)
                .context("deflate encode next chunk")?
            {
                Status::BufError => buf.reserve((buf.len() as f64 * 1.5) as usize),
                Status::Ok => (),
                Status::StreamEnd => break,
            }
        }

        while !buf.ends_with(&[0, 0, 0xFF, 0xFF]) {
            buf.reserve(5);
            match self
                .compress
                .buf_compress(&[], &mut buf, FlushCompress::Sync)
                .context("enforce buf to finish")?
            {
                Status::Ok | Status::BufError => (),
                Status::StreamEnd => break,
            }
        }

        buf.truncate(buf.len() - DEFLATE_TRAILER.len());

        if self.compress_reset {
            self.compress.reset();
        }

        Ok(buf)
    }
}

/// A permessage-deflate decompressor.
#[derive(Debug)]
pub(super) struct DeflateDecoder {
    decompress: Decompress,
    decompress_reset: bool,
}

impl DeflateDecoder {
    pub(super) fn new(mut window_size: u8, decompress_reset: bool) -> Self {
        // https://github.com/madler/zlib/blob/cacf7f1d4e3d44d871b605da3b647f07d718623f/deflate.c#L303
        if window_size == 8 {
            window_size = 9;
        }

        Self {
            decompress: Decompress::new_with_window_bits(false, window_size),
            decompress_reset,
        }
    }

    pub(super) fn decode(&mut self, compressed_data: &[u8]) -> Result<Vec<u8>, OpaqueError> {
        let mut buf = Vec::with_capacity((compressed_data.len() + DEFLATE_TRAILER.len()) * 2);

        for payload in [compressed_data, &DEFLATE_TRAILER] {
            let before_in = self.decompress.total_in();

            while self.decompress.total_in() - before_in < payload.as_ref().len() as u64 {
                let i = self.decompress.total_in() as usize - before_in as usize;
                match self
                    .decompress
                    .buf_decompress(&payload[i..], &mut buf, FlushDecompress::Sync)
                    .context("flate2 decode next chunk")?
                {
                    Status::BufError => buf.reserve((buf.len() as f64 * 1.5) as usize),
                    Status::Ok => (),
                    Status::StreamEnd => break,
                }
            }
        }

        if self.decompress_reset {
            self.decompress.reset(false);
        }

        Ok(buf)
    }
}

trait BufCompress {
    fn buf_compress(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
        flush: FlushCompress,
    ) -> Result<Status, CompressError>;
}

trait BufDecompress {
    fn buf_decompress(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
        flush: FlushDecompress,
    ) -> Result<Status, DecompressError>;
}

impl BufCompress for Compress {
    fn buf_compress(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
        flush: FlushCompress,
    ) -> Result<Status, CompressError> {
        op_buf(input, output, self.total_out(), |input, out| {
            let ret = self.compress(input, out, flush);
            (ret, self.total_out())
        })
    }
}

impl BufDecompress for Decompress {
    fn buf_decompress(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
        flush: FlushDecompress,
    ) -> Result<Status, DecompressError> {
        op_buf(input, output, self.total_out(), |input, out| {
            let ret = self.decompress(input, out, flush);
            (ret, self.total_out())
        })
    }
}

// This function's body is a copy of the Compress::compress_vec and Decompress::decompress_vec
// functions to work with a Vec<u8>.
fn op_buf<Fn, E>(input: &[u8], output: &mut Vec<u8>, before: u64, op: Fn) -> Result<Status, E>
where
    Fn: FnOnce(&[u8], &mut [u8]) -> (Result<Status, E>, u64),
{
    let cap = output.capacity();
    let len = output.len();

    unsafe {
        let ptr = output.as_mut_ptr().add(len);
        let out = slice::from_raw_parts_mut(ptr, cap - len);
        let (ret, total_out) = op(input, out);
        output.set_len((total_out - before) as usize + len);
        ret
    }
}
