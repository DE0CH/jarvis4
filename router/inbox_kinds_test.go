package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// inboxKinds: every kind of Inbox entry the router files (requests in inbox.go and its kin, approvals in flows.go /
// restore.go). A new one goes here, and the test below fails until both apps name it.
var inboxKinds = []string{
	requestKindRepo, requestKindGrant, requestKindUnlock, requestKindRestore, requestKindPeer, requestKindCall, requestKindMsg,
	"new-session", "resume-upgrade", "add-store", kernelApprovalKind, kernelAddApprovalKind,
}

// The iPhone app and the web page each name every Inbox kind the router files (Deyao, 2026-10-21: an Inbox outcome
// waiting as a "message" showed in an older app build as "New session" with "(no API call recorded)", and couldn't be
// approved). Their fallback for an unknown kind says so instead of guessing.
func TestEveryInboxKindIsKnownToTheApps(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join("..", p))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	files := map[string]string{
		"iOS list title (BatchReviewView.swift actionTitle)": read("ios/Jarvis4/Review/BatchReviewView.swift"),
		"iOS kind pill (InboxView.swift kindName)":           read("ios/Jarvis4/Inbox/InboxView.swift"),
		"web title (app/src/lib/inbox.ts inboxTitle)":        read("app/src/lib/inbox.ts"),
		"web kind pill (app/src/views/Inbox.tsx KIND)":       read("app/src/views/Inbox.tsx"),
	}
	for _, k := range inboxKinds {
		q := regexp.QuoteMeta(k)
		pats := map[string]*regexp.Regexp{
			"iOS list title (BatchReviewView.swift actionTitle)": regexp.MustCompile(`case "` + q + `"`),
			"iOS kind pill (InboxView.swift kindName)":           regexp.MustCompile(`"` + q + `": "`),
			"web title (app/src/lib/inbox.ts inboxTitle)":        regexp.MustCompile(`case "` + q + `"`),
			"web kind pill (app/src/views/Inbox.tsx KIND)":       regexp.MustCompile(`(?:"` + q + `"|\b` + q + `): "`),
		}
		for where, re := range pats {
			if !re.MatchString(files[where]) {
				t.Errorf("the Inbox kind %q has no entry in the %s", k, where)
			}
		}
	}
	// the fallbacks name the unknown kind rather than calling it a new session
	if !regexp.MustCompile(`default: return "Unknown request`).MatchString(files["iOS list title (BatchReviewView.swift actionTitle)"]) {
		t.Error("the iOS app's fallback for an unknown Inbox kind must say so")
	}
	if !regexp.MustCompile("return `Unknown request").MatchString(files["web title (app/src/lib/inbox.ts inboxTitle)"]) {
		t.Error("the web page's fallback for an unknown Inbox kind must say so")
	}
}
