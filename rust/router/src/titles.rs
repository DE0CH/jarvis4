//! A session's title (discord.go's sessionTitle).

use crate::state::Session;

/// the name a session's card, channel and archive folder carry — Jarvis 1's pickTitle: the Claude app's own title
/// (app_title, which follows Deyao's rename in the app) beats a name he pinned in the CLI (user_title), which beats the
/// label given at New session, which beats the AI title; else the id.
pub fn session_title(s: &Session) -> String {
    for t in [&s.app_title, &s.user_title, &s.label, &s.title] {
        let t = t.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    s.id.clone()
}
