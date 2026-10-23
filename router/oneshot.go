package main

// One-shot sessions end by themselves (Jarvis 1 oneShotTick / finishOneShot): once the supervisor marks the
// prompt done (the machine's status report, autopilot.go), the session is destroyed FORCEFULLY — paused for
// its final signed snapshot, archived to the Storage Box, burnt — without stopping for uncommitted or unpushed
// work (one prompt rarely leaves anything valuable) nor for a failed archive. Whenever work WAS lost (dirty
// repos as the final snapshot recorded them, a check that couldn't run, or the archive failed) Deyao gets a
// DM saying exactly what.

import (
	"fmt"
	"log"
	"strings"
)

// finishOneShot: the autopilot's destroy action
func (r *Router) finishOneShot(id string) error {
	return r.destroy(id, destroyOpts{force: true, report: func(s Session, changes map[string]any, archived *ArchiveInfo, aerr error) {
		title := sessionTitle(s)
		if archived != nil && archived.Title != "" {
			title = archived.Title // the title it was archived under (the app's, from the transcript)
		}
		if text := oneShotLostDM(title, changes, archived, aerr); text != "" {
			r.DM(text)
		}
		log.Printf("[oneshot] %s destroyed (archive: %s)", id, archiveWhere(archived, aerr))
	}})
}

// dirtyLines: one line per repo with unsaved work ("claude-env: 2 uncommitted file(s), 1 unpushed commit(s)")
func dirtyLines(repos []RepoChange) []string {
	var out []string
	for _, r := range repos {
		if r.Uncommitted <= 0 && r.Unpushed == 0 {
			continue
		}
		var parts []string
		if r.Uncommitted > 0 {
			parts = append(parts, fmt.Sprintf("%d uncommitted file(s)", r.Uncommitted))
		}
		if r.Unpushed > 0 {
			parts = append(parts, fmt.Sprintf("%d unpushed commit(s)", r.Unpushed))
		} else if r.Unpushed == -1 {
			parts = append(parts, "branch has no upstream (nothing pushed)")
		}
		out = append(out, r.Name+": "+strings.Join(parts, ", "))
	}
	return out
}

func archiveWhere(a *ArchiveInfo, aerr error) string {
	switch {
	case aerr != nil:
		return "FAILED: " + aerr.Error()
	case a == nil:
		return "nothing archived (no snapshot, or records off)"
	}
	return fmt.Sprintf("%s (%d transcript(s), %d artifact file(s))", a.File, len(a.Transcripts), a.Artifacts)
}

// oneShotLostDM: the DM, or "" when nothing was lost
func oneShotLostDM(title string, changes map[string]any, archived *ArchiveInfo, aerr error) string {
	checked, _ := changes["checked"].(bool)
	repos, _ := changes["repos"].([]RepoChange)
	lost := dirtyLines(repos)
	if len(lost) == 0 && checked && aerr == nil {
		return ""
	}
	lines := []string{fmt.Sprintf("Jarvis 4: one-shot session “%s” was destroyed with work lost:", title)}
	for _, l := range lost {
		lines = append(lines, "• "+l)
	}
	if !checked {
		reason, _ := changes["reason"].(string)
		if reason == "" {
			reason = "unknown"
		}
		lines = append(lines, "• could not check the repos for unsaved work ("+reason+")")
	}
	if aerr != nil {
		lines = append(lines, "• the archive to the Storage Box failed — the transcript and ~/artifacts are gone: "+aerr.Error())
	} else {
		lines = append(lines, "Transcript + ~/artifacts: "+archiveWhere(archived, nil)+".")
	}
	return strings.Join(lines, "\n")
}
