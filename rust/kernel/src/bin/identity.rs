//! The identity signer's process (signers.rs): no state.
fn main() {
    jarvis_kernel::serve::main("identity", |s| {
        jarvis_kernel::signers::register_identity(s);
        Ok(())
    });
}
