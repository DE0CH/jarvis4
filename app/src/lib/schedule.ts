// What will wake a session by itself: the router's wakeups, crons and watches, and an aviary session's chat schedule
// (magpie's schedules, which hermit-jarvis reports; rust/router/src/schedule.rs ChatSchedule). The same rule as the router's
// willWake, which the live dashboard's "scheduled" and the chat read: a card that left the chat schedule out said
// "idle" while both said "scheduled" (2026-11-18).
import type { Session } from "./api";

export const hasSchedule = (m: Session) =>
  !!(m.wakeups || []).length || !!(m.crons || []).length || !!(m.watches || []).length || !!m.chatScheduleIso;
