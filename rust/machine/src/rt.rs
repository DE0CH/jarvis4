//! The one tokio runtime: HTTP (the router client, the local servers) runs on it; the machine's own logic runs on
//! plain threads, as the Go code's goroutines did, and waits on the runtime with [`block_on`]. Never call
//! [`block_on`] from a task on the runtime itself: handlers hand their work to `spawn_blocking`.

use std::future::Future;
use std::sync::LazyLock;
use tokio::runtime::{Builder, Runtime};

static RT: LazyLock<Runtime> = LazyLock::new(|| {
    Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("jarvis-rt")
        .build()
        .unwrap_or_else(|e| panic!("tokio runtime: {e}"))
});

pub fn rt() -> &'static Runtime {
    &RT
}

/// Run `f` on the runtime from a plain thread (or a `spawn_blocking` thread) and wait for it
pub fn block_on<F: Future>(f: F) -> F::Output {
    match tokio::runtime::Handle::try_current() {
        // a spawn_blocking thread of this runtime: its handle may block here
        Ok(h) => h.block_on(f),
        Err(_) => RT.block_on(f),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn block_on_from_spawn_blocking() {
        let v = super::block_on(async {
            tokio::task::spawn_blocking(|| super::block_on(async { 7 }))
                .await
                .unwrap_or(0)
        });
        assert_eq!(v, 7);
    }
}
