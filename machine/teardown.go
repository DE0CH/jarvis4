package main

// The teardown (Deyao, 2026-10-21: "sigterm sigint etc should trigger a clean but also priority driven teardown. As
// in upload the most important items first quickly. Transcript tail is the most important, artifacts is less."): a
// stop signal reaches the keeper (keeper.go), which kills supervisor-normal and sends supervisor-core SIGUSR1. It uploads, most important
// first, each step on its own so whatever the machine got out before Fly's kill timeout stays with the router:
//
//  1. the transcripts that changed since their last copy (the live sync's, livesync.go), the newest first, then the
//     subagents' (POST /m/live-transcript: the router keeps them in claude-records/.live/<session>/, which the
//     archive and the transcript search take; livearchive.go);
//  2. the final snapshot, streamed in snapshotPaths' order (the transcripts and ~/.claude.json first, the
//     workspace and the artifacts last) and committed with the machine's one signature (snapstream.go): with it the
//     router resumes the session as after a pause. A snapshot is used only whole: one cut off by the kill leaves the
//     router the transcripts of step 1 and the volume's backup (core/volumes.go).
//
// A machine whose final snapshot the router already has (a pause: the snapshot first, then the core's stop) skips
// both: everything is in it.

import (
	"log"
	"time"
)

func teardown(c *client) {
	start := time.Now()
	if snapshotCommitted() {
		log.Printf("teardown: the final snapshot is already with the router; nothing more to upload")
		pushLogOnce(c)
		return
	}
	if booted() && !frozen.Load() {
		l := liveSyncerFor(c)
		n := l.pass(mainTranscripts())
		log.Printf("teardown 1/2: %d changed transcripts sent in %s", n, time.Since(start).Round(time.Millisecond))
		if m := l.pass(subagentTranscripts()); m > 0 {
			log.Printf("teardown 1/2: %d changed subagent transcripts sent", m)
		}
		pushLogOnce(c)
	}
	log.Printf("teardown 2/2: the final snapshot (the transcripts and ~/.claude.json first, the workspace and the artifacts last)")
	runCommand(c, "snapshot")
	log.Printf("teardown done in %s", time.Since(start).Round(time.Millisecond))
	pushLogOnce(c)
}

// snapshotCommitted: the router took this machine's final snapshot
func snapshotCommitted() bool {
	signedMu.Lock()
	defer signedMu.Unlock()
	return committed
}
