//! The Go package's tests (machine/*_test.go), ported: one file each. They share global state (the machine's directory,
//! HOME, the test seams), so each takes the one lock (testutil::TestEnv).
#![allow(clippy::unwrap_used)]

pub mod apiproxy;
pub mod claudelogin;
pub mod deploykeys;
pub mod fabric;
pub mod grants;
pub mod jarvis1import;
pub mod misc;
pub mod outcomes;
pub mod output;
pub mod restore;
pub mod secrets;
pub mod small;
pub mod snapdirect;
pub mod snapstream;
pub mod task;
pub mod testutil;
pub mod vouch;
pub mod watchdogs;
