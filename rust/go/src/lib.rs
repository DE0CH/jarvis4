//! Go's formats, for the Rust parts of Jarvis 4 that read and write what the Go parts did (and still do): JSON as
//! encoding/json reads and writes it, time.Time's JSON, and the fmt/strconv/time formatting the logs and messages use.

pub mod fmt;
pub mod json;
pub mod time;

pub use json::{marshal, unmarshal};
pub use time::GoTime;
