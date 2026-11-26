//! The grant merger's process (merger.rs): no state.
fn main() {
    jarvis_kernel::serve::main("merger", |s| {
        jarvis_kernel::merger::register(s);
        Ok(())
    });
}
