//! Wire/line-format parsers and writers (sans-I/O).
//!
//! Each submodule handles one canboat-recognised input format. Parsers
//! return a [`RawFrame`]; writers consume one. None of them do I/O.

pub mod plain;

pub use plain::{parse_line as parse_plain, write_line as write_plain, ParseError as PlainError};
