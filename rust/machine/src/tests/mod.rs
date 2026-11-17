//! The Go package's tests (machine/*_test.go), ported: one file each. They share global state (the machine's directory,
//! HOME, the test seams), so each takes the one lock (testutil::TestEnv).
#![allow(clippy::unwrap_used)]

pub mod testutil;
pub mod vouch;
pub mod grants;
pub mod outcomes;
pub mod watchdogs;
pub mod misc;
pub mod task;
