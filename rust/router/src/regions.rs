//! Session regions (Deyao, 2026-10-29: "choose per session"; Fly has no Hong Kong region, Singapore and Tokyo are the
//! nearest to it).

use crate::router::Router;
use crate::state::Session;

/// the Fly regions New session offers; the router's FLY_REGION (cfg.region) is the default. Every start is a new
/// machine on a new volume from the line's snapshot, so a session's region only says where its next machine runs; the
/// router, its database and the snapshots stay in Falkenstein.
pub const SESSION_REGIONS: &[(&str, &str)] = &[("lhr", "London"), ("sin", "Singapore"), ("nrt", "Tokyo")];

pub fn valid_region(id: &str) -> bool {
    SESSION_REGIONS.iter().any(|(g, _)| *g == id)
}

impl Router {
    /// where the session's machines run (its own region, else the router's default)
    pub fn region_of(&self, s: &Session) -> String {
        if !s.region.is_empty() {
            return s.region.clone();
        }
        self.cfg.region.clone()
    }
}
