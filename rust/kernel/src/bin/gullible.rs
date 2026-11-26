//! The gullible signer's process (signers.rs): no state.
fn main() {
    jarvis_kernel::serve::main("gullible", |s| {
        jarvis_kernel::signers::register_gullible(s);
        Ok(())
    });
}
