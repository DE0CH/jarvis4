//! An in-process pipe (Go's io.Pipe): a writer on one thread, a reader on another, chunks through a bounded channel.
//! A writer closes with an error the reader sees; a reader that goes away makes the writer's next write fail.

use std::io::{Read, Write};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

type Chunk = Result<Vec<u8>, String>;

pub struct PipeWriter {
    tx: Option<SyncSender<Chunk>>,
}

pub struct PipeReader {
    rx: Receiver<Chunk>,
    buf: Vec<u8>,
    off: usize,
    done: bool,
}

pub fn pipe() -> (PipeWriter, PipeReader) {
    let (tx, rx) = sync_channel(8);
    (
        PipeWriter { tx: Some(tx) },
        PipeReader {
            rx,
            buf: vec![],
            off: 0,
            done: false,
        },
    )
}

impl PipeWriter {
    /// the end of the stream: Ok, or the error the reader gets
    pub fn close(mut self, err: Option<String>) {
        if let (Some(tx), Some(e)) = (self.tx.take(), err) {
            let _ = tx.send(Err(e));
        }
    }
}

impl Write for PipeWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| std::io::Error::other("closed"))?;
        tx.send(Ok(b.to_vec())).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "the upload stopped")
        })?;
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Read for PipeReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.off >= self.buf.len() {
            if self.done {
                return Ok(0);
            }
            match self.rx.recv() {
                Ok(Ok(b)) => {
                    self.buf = b;
                    self.off = 0;
                }
                Ok(Err(e)) => {
                    self.done = true;
                    return Err(std::io::Error::other(e));
                }
                Err(_) => {
                    self.done = true;
                    return Ok(0);
                }
            }
        }
        let n = out.len().min(self.buf.len() - self.off);
        out[..n].copy_from_slice(&self.buf[self.off..self.off + n]);
        self.off += n;
        Ok(n)
    }
}
