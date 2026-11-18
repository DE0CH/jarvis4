//! Carried secrets (docs/DESIGN.md "Carried secrets"): every pull that goes through answers a carry blob — the
//! machine's secrets per store, sealed under a key only the core holds, bound to that machine. The router keeps it in
//! its database (router_docs carry/<machine>) and hands it back to the core on the machine's next pull and, right after
//! a successor is certified (a resume) or the machine gets a new cert (an add-store, a downgrade), with the call that
//! makes the new cert, which answers it rebound to that machine beside the cert. The router can't open, alter or move it
//! to another line; it can only lose it, and then the session waits for an unlock. Destroy deletes it with the
//! snapshot.

use crate::core::{Answer, CoreError, Doc};
use crate::router::Router;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex, MutexGuard};

/// a carry blob is a row of router_docs, carry/<machine>
pub fn carry_doc(machine: &str) -> String {
    format!("carry/{machine}")
}

/// one carry read-modify-write per machine at a time (a pull and a forward can race); one lock per machine for the
/// process's life
static CARRY_LOCKS: LazyLock<Mutex<BTreeMap<String, &'static Mutex<()>>>> = LazyLock::new(|| Mutex::new(BTreeMap::new()));

pub fn carry_lock(machine: &str) -> MutexGuard<'static, ()> {
    let m: &'static Mutex<()> = *CARRY_LOCKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(machine.to_string())
        .or_insert_with(|| Box::leak(Box::new(Mutex::new(()))));
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn pred_of(cert: &Doc) -> String {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct C {
        #[serde(rename = "predecessorId")]
        pred_id: String,
    }
    cert.decode::<C>().map(|c| c.pred_id).unwrap_or_default()
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct CarryField {
    carry: String,
}

impl Router {
    pub fn read_carry(&self, machine: &str) -> String {
        if machine.is_empty() {
            return String::new();
        }
        self.st
            .read_doc(&carry_doc(machine))
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    }

    pub fn save_carry(&self, machine: &str, blob: &str) {
        if blob.is_empty() {
            return;
        }
        if let Err(e) = self.st.write_doc(&carry_doc(machine), blob.as_bytes()) {
            crate::logf!("carry for {machine}: {e:#}");
        }
    }

    pub fn drop_carry(&self, machine: &str) {
        self.st.delete_doc(&carry_doc(machine));
    }

    /// the blob to send with a machine's pull — its own, else its predecessor's (a resumed machine whose forward
    /// didn't happen)
    pub fn carry_for_pull(&self, machine: &str, cert: &Doc) -> String {
        let b = self.read_carry(machine);
        if !b.is_empty() {
            return b;
        }
        self.read_carry(&pred_of(cert))
    }

    /// a pull went through; keep the new blob for this machine (the predecessor's is spent)
    pub fn pulled(&self, machine: &str, cert: &Doc, answer: &Doc) {
        let Ok(a) = answer.decode::<CarryField>() else { return };
        if a.carry.is_empty() {
            return; // a core without carried secrets
        }
        self.save_carry(machine, &a.carry);
        let p = pred_of(cert);
        if !p.is_empty() && p != machine {
            self.drop_carry(&p);
        }
    }

    /// a new cert's carry — the blob the core answered beside it (rebound to `to`), else (the core before R2) its
    /// /carry/forward
    pub fn carry_after(&self, from: &str, to: &str, cert: &Doc, ans: &Answer) {
        if ans.carry.is_empty() {
            self.forward_carry(from, cert, to);
            return;
        }
        let _g = carry_lock(to);
        let _g2 = (from != to).then(|| carry_lock(from));
        self.save_carry(to, &ans.carry);
        if from != to {
            self.drop_carry(from);
        }
    }

    /// the core before R2: the line's blob rebound to the machine the new cert names. Best effort.
    pub fn forward_carry(&self, from: &str, cert: &Doc, to: &str) {
        let _g = carry_lock(to);
        let _g2 = (from != to).then(|| carry_lock(from));
        let blob = self.read_carry(from);
        if blob.is_empty() {
            return;
        }
        match self.core.call("/carry/forward", &json!({"carry": blob, "cert": cert})) {
            Err(e) => {
                if !e.downcast_ref::<CoreError>().is_some_and(|c| c.status == 404) {
                    crate::logf!("carry forward {from} → {to}: {e:#}");
                }
            }
            Ok(d) => {
                let Ok(a) = d.decode::<CarryField>() else { return };
                if a.carry.is_empty() {
                    return;
                }
                self.save_carry(to, &a.carry);
                if from != to {
                    self.drop_carry(from);
                }
            }
        }
    }
}
