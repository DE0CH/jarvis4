//! The succession notarizer's process (notarizer.rs): its state in KERNEL_DATA (its own volume).
fn main() {
    jarvis_kernel::serve::main("notarizer", |s| {
        let dir = std::env::var("KERNEL_DATA").unwrap_or_default();
        let n = jarvis_kernel::notarizer::Notarizer::open(
            &std::path::Path::new(&dir).join("notarizer.jsonl"),
            &s.trust,
        )?;
        jarvis_kernel::notarizer::register(s, std::sync::Arc::new(n));
        Ok(())
    });
}
