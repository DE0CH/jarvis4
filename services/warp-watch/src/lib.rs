//! The rule of warp-watch (main.rs has its effects): a node's WARP session can turn slow rather than dead
//! (claude-env lessons/99): every IPv4 origin outside Cloudflare takes seconds to answer a TLS handshake, so SDK
//! connect timeouts fail (the chat's magpie lost its bucket 05:00-09:00 UTC on 2026-11-18, and hermit OpenRouter),
//! while anything Cloudflare serves itself stays fast. A reconnect gives a new session.
//!
//! One rule: reconnect when [`FAILED_ROUNDS`] rounds in a row had no target answer within the bound, and not again
//! within [`COOLDOWN`] of the last reconnect.

use std::time::{Duration, Instant};

/// How long a target has for its TCP connect and TLS handshake together (the AWS SDK's own connect timeout is 3.1 s).
pub const BOUND: Duration = Duration::from_secs(3);
/// How often a round runs.
pub const EVERY: Duration = Duration::from_secs(60);
/// Rounds in a row with no answer before a reconnect.
pub const FAILED_ROUNDS: u32 = 2;
/// The least time between two reconnects.
pub const COOLDOWN: Duration = Duration::from_secs(600);

/// IPv4 origins outside Cloudflare, each reached through WARP from a node (the chat's bucket, GitHub, AWS). A
/// Cloudflare-hosted target proves nothing: Cloudflare answers it itself.
pub const TARGETS: &[&str] = &[
    "fsn1.your-objectstorage.com",
    "github.com",
    "ec2.eu-central-1.amazonaws.com",
];

/// What the watch remembers between rounds.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Watch {
    failed: u32,
    last_reconnect: Option<Instant>,
}

impl Watch {
    /// Takes a round's outcome (`answered`: some target answered within the bound); true when WARP is to be
    /// reconnected now.
    pub fn after_round(&mut self, answered: bool, now: Instant) -> bool {
        if answered {
            self.failed = 0;
            return false;
        }
        self.failed += 1;
        let cooled = self
            .last_reconnect
            .is_none_or(|t| now.duration_since(t) >= COOLDOWN);
        if self.failed < FAILED_ROUNDS || !cooled {
            return false;
        }
        self.failed = 0;
        self.last_reconnect = Some(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rounds(w: &mut Watch, start: Instant, outcomes: &[bool]) -> Vec<bool> {
        outcomes
            .iter()
            .enumerate()
            .map(|(i, ok)| w.after_round(*ok, start + EVERY * u32::try_from(i).unwrap_or(u32::MAX)))
            .collect()
    }

    #[test]
    fn one_failed_round_is_not_enough() {
        let mut w = Watch::default();
        assert_eq!(
            rounds(&mut w, Instant::now(), &[false, true, false, true]),
            [false; 4]
        );
    }

    #[test]
    fn two_failed_rounds_in_a_row_reconnect() {
        let mut w = Watch::default();
        assert_eq!(
            rounds(&mut w, Instant::now(), &[true, false, false]),
            [false, false, true]
        );
    }

    #[test]
    fn a_reconnect_waits_out_the_cooldown() {
        let mut w = Watch::default();
        // 10 failed rounds a minute apart: reconnect at the 2nd, then not until 10 min after it
        let got = rounds(&mut w, Instant::now(), &[false; 13]);
        let at: Vec<usize> = got
            .iter()
            .enumerate()
            .filter(|(_, r)| **r)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(at, [1, 11]);
    }

    #[test]
    fn an_answer_resets_the_count() {
        let mut w = Watch::default();
        assert_eq!(
            rounds(
                &mut w,
                Instant::now(),
                &[false, true, false, true, false, false]
            ),
            [false, false, false, false, false, true]
        );
    }
}
