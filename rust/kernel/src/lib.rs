//! Jarvis 4's kernel (docs/PLAN-grants.md, docs/PLAN-cluster.md; the Go kernel's port, DECISIONS 280). Each component
//! is a binary of its own (src/bin/<role>.rs), built into one image (rust/kernel/Dockerfile).

pub mod files;
pub mod flip;
pub mod kerneltest;
pub mod kt;
pub mod merger;
pub mod minter;
pub mod mover;
pub mod notarizer;
pub mod notary;
pub mod secrets;
pub mod serve;
pub mod signers;
pub mod spawner;
