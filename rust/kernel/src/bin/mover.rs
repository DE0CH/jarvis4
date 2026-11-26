//! The grant mover's process (mover.rs): no state.
fn main() {
    jarvis_kernel::serve::main("mover", |s| {
        jarvis_kernel::mover::register(s);
        Ok(())
    });
}
