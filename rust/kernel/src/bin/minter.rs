//! The minter's process (minter.rs): no state; the only kernel component with GitHub egress.
fn main() {
    jarvis_kernel::serve::main("minter", |s| {
        let m =
            jarvis_kernel::minter::Minter::new(Box::new(jarvis_kernel::minter::GitHubApi::new()));
        jarvis_kernel::minter::register(s, std::sync::Arc::new(m));
        Ok(())
    });
}
