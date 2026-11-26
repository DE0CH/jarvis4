//! Jarvis 4's kernel in Rust (the port of kernel/, Go, which serves until the kernel's cut; docs/PLAN-grants.md,
//! docs/PLAN-cluster.md). Each component is a binary of its own (src/bin/<role>.rs), as kernel/cmd/<role> is.

pub mod files;
pub mod flip;
pub mod merger;
pub mod minter;
pub mod mover;
pub mod notarizer;
pub mod notary;
pub mod serve;
pub mod signers;
