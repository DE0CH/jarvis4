//! Plain HTTPS from the machine itself (Anthropic's APIs, the bucket's presigned URLs): reqwest with rustls, on the one
//! runtime, waited on from the calling thread. Also plain HTTP to a server on this machine (the aviary harness's
//! gateway), never through a proxy.

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

static LOCAL: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .http1_only()
        .no_proxy()
        .build()
        .unwrap_or_default()
});

/// a JSON POST to a server on this machine → status and body (at most 64 KiB), within `limit`
pub fn post_local_json(
    url: &str,
    body: &serde_json::Value,
    limit: Duration,
) -> Result<(u16, String)> {
    let req = LOCAL.post(url).json(body);
    rt::block_on(async {
        tokio::time::timeout(limit, async {
            let resp = req.send().await?;
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            let text: String = text.chars().take(65536).collect();
            Ok::<_, anyhow::Error>((status, text))
        })
        .await
        .map_err(|_| anyhow!("{url}: timeout"))?
    })
}

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
