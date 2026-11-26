//! The spawner's process (spawner/): its state in KERNEL_DATA (its own volume); KERNEL_MACHINE_URL is the router's
//! address its Fly machines get (on Fly's private network), KERNEL_AWS_MACHINE_URL its AWS machines' (the m-gateway on
//! the tailnet), KERNEL_FABRIC_HERMIT_URL and KERNEL_FABRIC_MACHINE_URL the fabric runner's hermit and its machines'.
use jarvis_kernel::spawner::{Spawner, aws::AwsApi, fabric::FabricApi, fly::FlyApi, register};
use std::collections::BTreeMap;
use std::sync::Arc;

fn url_env(k: &str) -> Option<BTreeMap<String, String>> {
    std::env::var(k)
        .ok()
        .filter(|u| !u.is_empty())
        .map(|u| BTreeMap::from([("JARVIS2_URL".to_string(), u)]))
}

fn main() {
    jarvis_kernel::serve::main("spawner", |s| {
        let dir = std::env::var("KERNEL_DATA").unwrap_or_default();
        let sp = Arc::new(Spawner::open(
            &std::path::Path::new(&dir).join("spawner.json"),
            jarvis_sig::Signer::from_scalar(&s.c.signer.scalar())?,
            jarvis_sig::Opener::from_scalar(&s.c.agreement.scalar())?,
            s.trust.clone(),
            Arc::new(FlyApi::new()),
            Some(Arc::new(AwsApi::new())),
            url_env("KERNEL_MACHINE_URL"),
            url_env("KERNEL_AWS_MACHINE_URL"),
        )?);
        let hermit = std::env::var("KERNEL_FABRIC_HERMIT_URL").unwrap_or_default();
        if let (false, Some(env)) = (hermit.is_empty(), url_env("KERNEL_FABRIC_MACHINE_URL")) {
            sp.set_fabric(Arc::new(FabricApi::new(&hermit)), env);
        }
        register(s, sp);
        Ok(())
    });
}
