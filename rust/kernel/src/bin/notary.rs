//! The log notary's process (notary.rs): its log in KERNEL_DATA (its own volume).
fn main() {
    jarvis_kernel::serve::main("notary", |s| {
        let dir = std::env::var("KERNEL_DATA").unwrap_or_default();
        let n = jarvis_kernel::notary::Notary::open(
            &std::path::Path::new(&dir).join("notary-log.jsonl"),
        )?;
        jarvis_kernel::notary::register(s, std::sync::Arc::new(n));
        Ok(())
    });
}
