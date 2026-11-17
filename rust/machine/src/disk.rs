//! Disk: the machine's own disk report (router/disk.go), every 30 s: the root filesystem and, on a machine with a
//! volume (volume.rs), the volume at /data that holds the session's state.

use crate::client::Client;
use crate::{logf, util};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DISK_EVERY: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct DiskFs {
    pub total_kb: i64,
    pub avail_kb: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DiskSample {
    pub root: Option<DiskFs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<DiskFs>,
}

pub fn read_fs(path: &str) -> Result<DiskFs> {
    let st = nix::sys::statvfs::statvfs(path)?;
    let bs = st.fragment_size() as i64;
    Ok(DiskFs {
        total_kb: st.blocks() as i64 * bs / 1024,
        avail_kb: st.blocks_available() as i64 * bs / 1024,
    })
}

pub fn read_disk() -> Result<DiskSample> {
    let mut s = DiskSample {
        root: Some(read_fs("/")?),
        data: None,
    };
    if crate::volume::has_volume()
        && let Ok(d) = read_fs(crate::volume::VOLUME_ROOT)
    {
        s.data = Some(d);
    }
    Ok(s)
}

/// the supervisor's disk report (started with the status reports, once booted)
pub fn disk_reporter(c: &Client) {
    loop {
        util::sleep(DISK_EVERY);
        match read_disk() {
            Err(e) => logf!("disk: {e:#}"),
            Ok(s) => {
                if let Err(e) = c.json_ok("POST", "/m/disk", Some(&s)) {
                    logf!("disk report failed: {e:#}");
                }
            }
        }
    }
}
