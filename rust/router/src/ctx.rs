//! Go's context.Context, as the router uses it: a cancellation that a long poll waits on (a client that went, a
//! router that stops, a parent cancelled), with an optional deadline.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Inner {
    cancelled: Mutex<bool>,
    cv: Condvar,
    children: Mutex<Vec<Ctx>>,
}

#[derive(Clone, Default)]
pub struct Ctx {
    inner: Arc<Inner>,
    deadline: Option<Instant>,
}

impl Ctx {
    /// context.Background()
    pub fn background() -> Ctx {
        Ctx::default()
    }

    /// a child: cancelled with its parent, or by itself
    pub fn child(&self) -> Ctx {
        let c = Ctx {
            inner: Arc::default(),
            deadline: self.deadline,
        };
        if self.cancelled() {
            c.cancel();
        } else if let Ok(mut g) = self.inner.children.lock() {
            g.push(c.clone());
        }
        c
    }

    /// context.WithTimeout
    pub fn with_timeout(&self, d: Duration) -> Ctx {
        let mut c = self.child();
        let end = Instant::now() + d;
        c.deadline = Some(c.deadline.map_or(end, |x| x.min(end)));
        c
    }

    pub fn cancel(&self) {
        if let Ok(mut g) = self.inner.cancelled.lock() {
            *g = true;
        }
        self.inner.cv.notify_all();
        let kids = self
            .inner
            .children
            .lock()
            .map(|mut g| std::mem::take(&mut *g))
            .unwrap_or_default();
        for k in kids {
            k.cancel();
        }
    }

    /// ctx.Err() != nil
    pub fn cancelled(&self) -> bool {
        self.inner.cancelled.lock().map(|g| *g).unwrap_or(true)
            || self.deadline.is_some_and(|d| Instant::now() >= d)
    }

    /// waits at most d (and never past the deadline) → false when cancelled meanwhile
    pub fn sleep(&self, d: Duration) -> bool {
        let end = Instant::now() + d;
        let end = self.deadline.map_or(end, |x| x.min(end));
        let mut g = self
            .inner
            .cancelled
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        loop {
            if *g {
                return false;
            }
            let now = Instant::now();
            if now >= end {
                return !self.cancelled();
            }
            g = self
                .inner
                .cv
                .wait_timeout(g, end - now)
                .map(|(g, _)| g)
                .unwrap_or_else(|e| e.into_inner().0);
        }
    }
}
