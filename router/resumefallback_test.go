package main

// A resume the core won't answer by itself becomes the resume-upgrade approval in the Inbox (Deyao, 2026-10-15), and an
// approved API call's review sheet follows the core requests the call brings about (apicalls.go follow-ups).

import (
	"strings"
	"testing"
	"time"
)

const refusedSame = "store set, image or options differ from the predecessor's (or a one-time input is asked for)"

var (
	bareImage   = "ghcr.io/de0ch/jarvis4-session@sha256:" + strings.Repeat("1", 64)
	pinnedOfIt  = "ghcr.io/de0ch/jarvis4-session:sha-0123456789ab@sha256:" + strings.Repeat("1", 64)
	newestImage = "ghcr.io/de0ch/jarvis4-session:sha-ba9876543210@sha256:" + strings.Repeat("2", 64)
)

func successionImages(vc *v2Core) []string {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	out := []string{}
	for _, b := range vc.bodies["/succession"] {
		img, _ := b["image"].(string)
		out = append(out, img)
	}
	return out
}

func pausedOnAPin(rg *rig) {
	rg.r.cfg.SessionImage, rg.r.cfg.ImageOrder = newestImage, []string{pinnedOfIt, newestImage}
	rg.r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		// the session row names CI's pin; the cert names what Fly reported (repo@digest): the core compares the cert's
		s.Cert, s.Image = v2Cert(rg, "m1", `{"v":1}`), pinnedOfIt
	})
}

func approvalOf(rg *rig, sid string) *Approval {
	var a *Approval
	rg.r.st.Do(func(d *persisted) {
		for _, x := range d.Approvals {
			if x.Session == sid {
				a = x
			}
		}
	})
	return a
}

// the root cause of 2026-10-15: an unattended resume must name the cert's own image string, not CI's pinned ref
func TestAnUnattendedResumeNamesTheCertsOwnImage(t *testing.T) {
	rg, vc := v2Rig(t)
	pausedOnAPin(rg)
	if err := rg.r.Resume("s1", false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "dead-machine asked", func() bool { return vc.last("/approve/by-dead-machine") != nil })
	if imgs := successionImages(vc); len(imgs) != 1 || imgs[0] != bareImage {
		t.Fatalf("the unattended resume named %v, not the cert's %s", imgs, bareImage)
	}
	if a := approvalOf(rg, "s1"); a != nil {
		t.Fatalf("an approval for an unattended resume: %+v", a)
	}
	waitFor(t, "idle", func() bool { _, err := rg.r.lock("s1", "test-end"); return err == nil })
}

func TestARefusedResumeBecomesTheResumeUpgradeApproval(t *testing.T) {
	rg, vc := v2Rig(t)
	pausedOnAPin(rg)
	vc.refuse = refusedSame
	if err := rg.r.Resume("s1", false); err != nil {
		t.Fatal(err)
	}
	var a *Approval
	waitFor(t, "approval", func() bool { a = approvalOf(rg, "s1"); return a != nil })
	if a.Kind != "resume-upgrade" {
		t.Fatalf("%+v", a)
	}
	// the phone's challenge names the same image, as CI pinned (and signed) it
	if imgs := successionImages(vc); len(imgs) != 2 || imgs[0] != bareImage || imgs[1] != pinnedOfIt {
		t.Fatalf("challenges %v", imgs)
	}
	rg.r.st.Do(func(d *persisted) {
		if s := d.Sessions["s1"]; s.State != "approval" || s.Error != "" {
			t.Fatalf("session %s %q", s.State, s.Error)
		}
	})
	// any other refusal stays an error on the paused session (nothing the phone should be asked)
	rg2, vc2 := v2Rig(t)
	pausedOnAPin(rg2)
	vc2.refuse = "predecessor is not a killed, unused machine"
	rg2.r.Resume("s1", false)
	waitFor(t, "paused with the error", func() bool {
		ok := false
		rg2.r.st.Do(func(d *persisted) {
			s := d.Sessions["s1"]
			ok = s.State == "paused" && strings.Contains(s.Error, "killed, unused")
		})
		return ok
	})
	if a := approvalOf(rg2, "s1"); a != nil {
		t.Fatalf("an approval for another refusal: %+v", a)
	}
}

// the session actions' resume (and the app's) reach the same fallback; a resume through an approved API call links
// its approval to the call, so the call's review sheet shows it
func TestAnApprovedResumeCallFollowsItsApproval(t *testing.T) {
	rg, vc := v2Rig(t)
	r := rg.r
	r.cfg.NoAccess = true
	pausedOnAPin(rg)
	vc.refuse = refusedSame
	addSession(r, "sR", "started", "mR", false)
	m, mh := newTestMachine(r, "mR"), r.MachineHandler()

	code, out := m.do(t, mh, "POST", "/m/api/actions/requests/call", `{"method": "POST", "path": "/api/sessions/s1/resume", "explanation": "carry on with s1"}`)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	id := out["id"].(string)
	code, out = inboxDo(t, r, "POST", "/api/requests/"+id+"/approve", "", true)
	if code != 200 || out["state"] != "done" {
		t.Fatalf("approve: %d %v", code, out)
	}
	// right after Approve the sheet knows either the approval or that one may still come, and until when
	if fs, _ := out["followups"].([]any); len(fs) == 0 && out["awaiting"] == nil {
		t.Fatalf("approve answered neither follow-ups nor awaiting: %v", out)
	}
	var f CallFollowups
	waitFor(t, "the follow-up", func() bool {
		f, _ = r.CallFollowupsOf(id)
		return len(f.Followups) == 1
	})
	it := f.Followups[0].Item
	if !f.Followups[0].Open || it == nil || it.Kind != "resume-upgrade" || it.Session != "s1" || it.ViaCall != id || f.Awaiting != nil {
		t.Fatalf("%+v %+v", f, it)
	}
	if code, out := inboxDo(t, r, "GET", "/api/requests/calls/"+id, "", true); code != 200 || len(out["followups"].([]any)) != 1 {
		t.Fatalf("%d %v", code, out)
	}
	// answered (here: denied) → the sheet sees it gone
	if err := r.Reject(f.Followups[0].ID); err != nil {
		t.Fatal(err)
	}
	if f, _ = r.CallFollowupsOf(id); f.Followups[0].Open {
		t.Fatalf("%+v", f)
	}
	if code, _ := inboxDo(t, r, "GET", "/api/requests/calls/nope", "", true); code != 404 {
		t.Fatalf("unknown call: %d", code)
	}
}

// a resume the core answers by itself brings nothing about: the call's wait ends without a follow-up
func TestAnApprovedResumeCallWithNothingToFollow(t *testing.T) {
	rg, _ := v2Rig(t)
	r := rg.r
	r.cfg.NoAccess = true
	pausedOnAPin(rg)
	addSession(r, "sR", "started", "mR", false)
	m, mh := newTestMachine(r, "mR"), r.MachineHandler()
	_, out := m.do(t, mh, "POST", "/m/api/actions/requests/call", `{"method": "POST", "path": "/api/sessions/s1/resume", "explanation": "carry on"}`)
	id := out["id"].(string)
	if code, out := inboxDo(t, r, "POST", "/api/requests/"+id+"/approve", "", true); code != 200 || out["state"] != "done" {
		t.Fatalf("%d %v", code, out)
	}
	waitFor(t, "settled", func() bool { f, _ := r.CallFollowupsOf(id); return f.Awaiting == nil })
	if f, _ := r.CallFollowupsOf(id); len(f.Followups) != 0 {
		t.Fatalf("%+v", f)
	}
	waitFor(t, "idle", func() bool { _, err := r.lock("s1", "test-end"); return err == nil })
}

// a call that fails waits for nothing
func TestAFailedCallAwaitsNothing(t *testing.T) {
	rg, _ := v2Rig(t)
	r := rg.r
	r.cfg.NoAccess = true
	addSession(r, "sR", "started", "mR", false)
	m, mh := newTestMachine(r, "mR"), r.MachineHandler()
	// s1 is being destroyed: the resume is refused at once
	r.st.Do(func(d *persisted) { d.Sessions["s1"].State = "destroying" })
	_, out := m.do(t, mh, "POST", "/m/api/actions/requests/call", `{"method": "POST", "path": "/api/sessions/s1/resume", "explanation": "x"}`)
	id := out["id"].(string)
	code, out := inboxDo(t, r, "POST", "/api/requests/"+id+"/approve", "", true)
	if code != 200 || out["status"].(float64) < 400 || out["awaiting"] != nil {
		t.Fatalf("%d %v", code, out)
	}
}

// a failed session with no machine comes back with Resume: a failed start of a resume (the line is intact) like a paused
// one, and a refusal of it reaches the phone
func TestAFailedStartResumes(t *testing.T) {
	rg, vc := v2Rig(t)
	pausedOnAPin(rg)
	vc.refuse = refusedSame
	rg.r.st.Do(func(d *persisted) {
		d.Sessions["s1"].State, d.Sessions["s1"].Error = "failed", "start: core /start: context deadline exceeded"
	})
	if err := rg.r.Resume("s1", false); err != nil {
		t.Fatal(err)
	}
	var a *Approval
	waitFor(t, "approval", func() bool { a = approvalOf(rg, "s1"); return a != nil })
	if a.Kind != "resume-upgrade" {
		t.Fatalf("%+v", a)
	}
	// (a failed session that still has a machine finishes its pause first: failedsession_test.go)
}

// a new line whose first start failed gets its new-session approval again; Deny leaves it failed
func TestAFailedNewLineStartsAgain(t *testing.T) {
	rg, vc := v2Rig(t)
	rg.r.cfg.SessionImage = newestImage
	rg.r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		s.Cert, s.State, s.Error, s.Prompt, s.Label = nil, "failed", "the start was cut off by a router crash: start it again", "do the thing", "Jarvis 4"
	})
	if err := rg.r.Resume("s1", false); err != nil {
		t.Fatal(err)
	}
	var a *Approval
	waitFor(t, "approval", func() bool { a = approvalOf(rg, "s1"); return a != nil })
	if a.Kind != "new-session" || !a.Again {
		t.Fatalf("%+v", a)
	}
	in := vc.last("/succession")
	if in["predecessor"] != nil || in["image"] != newestImage {
		t.Fatalf("challenge %v", in)
	}
	if cfg, _ := in["options"].(map[string]any)["config"].(string); !strings.Contains(cfg, "do the thing") {
		t.Fatalf("config %v", in["options"])
	}
	if err := rg.r.Reject(a.ID); err != nil {
		t.Fatal(err)
	}
	// failed, and the start's goroutine ended (else it still writes into the test's dir as it is removed)
	if err := rg.r.waitState("s1", "failed", 5*time.Second); err != nil {
		t.Fatalf("after Deny: %v", err)
	}
}

// Restart {upgrade: true}: the resume after the pause goes on the newest image, through its resume-upgrade approval
// (how a fixed supervisor reaches a running session in one Inbox ask)
func TestRestartWithUpgradeAsksForTheNewestImage(t *testing.T) {
	rg, _ := v2Rig(t)
	pausedOnAPin(rg)
	rg.r.cfg.NoAccess = true
	code, out := appDo(t, rg.r, "POST", "/api/sessions/s1/restart", `{"upgrade":true}`)
	if code != 202 || out["upgrade"] != true {
		t.Fatalf("%d %v", code, out)
	}
	var a *Approval
	waitFor(t, "approval", func() bool { a = approvalOf(rg, "s1"); return a != nil })
	if a.Kind != "resume-upgrade" {
		t.Fatalf("%+v", a)
	}
	waitFor(t, "job finished", func() bool { j := rg.r.ops.jobView("s1"); return j != nil && j["finishedAt"] != nil })
}
