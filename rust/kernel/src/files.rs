//! Files on a stateful component's volume, written whole or not at all

use std::io::Write as _;
use std::path::Path;

/// data at path: a temporary file beside it, synced, then renamed over it (Go's writes in kernel/: tmp, Sync, Rename)
pub fn write_synced(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}
