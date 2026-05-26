//! Wire/line-format parsers and writers (sans-I/O).
//!
//! Each submodule handles one canboat-recognised input format. Parsers
//! return a [`RawFrame`]; writers consume one. None of them do I/O.

pub mod ngt1;
pub mod plain;

pub use ngt1::{
    Ngt1Decoder, NgtError, NgtEvent, NgtMessage, N2K_MSG_RECEIVED, N2K_MSG_SEND, NGT_MSG_RECEIVED,
    NGT_MSG_SEND,
};
pub use plain::{parse_line as parse_plain, write_line as write_plain, ParseError as PlainError};
