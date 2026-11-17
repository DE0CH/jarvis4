//! Plain HTTPS from the machine itself (Anthropic's APIs, the bucket's presigned URLs): reqwest with rustls, on the one
//! runtime, waited on from the calling thread.

use crate::rt;
use anyhow::{Result, anyhow};
use std::sync::LazyLock;
use std::time::Duration;

static CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    // building a client needs no runtime (first used inside an async block: no block_on here)
    reqwest::Client::builder()
        .http1_only()
        .build()
        .unwrap_or_default()
});

/// a GET with headers → status and body (at most `max` bytes), within `limit`
pub fn get(
    url: &str,
    headers: &[(&str, &str)],
    limit: Duration,
    max: usize,
) -> Result<(u16, Vec<u8>)> {
    let mut req = CLIENT.get(url);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    rt::block_on(async {
        tokio::time::timeout(limit, async {
            let mut resp = req.send().await?;
            let status = resp.status().as_u16();
            let mut body = vec![];
            while let Some(c) = resp.chunk().await? {
                let room = max.saturating_sub(body.len());
                body.extend_from_slice(&c[..c.len().min(room)]);
                if room == 0 {
                    break;
                }
            }
            Ok::<_, anyhow::Error>((status, body))
        })
        .await
        .map_err(|_| anyhow!("{url}: timeout"))?
    })
}
