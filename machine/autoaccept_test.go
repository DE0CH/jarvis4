package main

import (
	"os"
	"strings"
	"testing"
)

// testdata/permission-dialog.txt: Claude Code 2.1.318's pane (tmux capture-pane -p) on a Bash permission dialog,
// captured 2026-11-04 (the workspace path replaced)
func dialogPane(t *testing.T) string {
	b, err := os.ReadFile("testdata/permission-dialog.txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPermissionDialogFound(t *testing.T) {
	ok, what := permissionDialog(dialogPane(t))
	if !ok || !strings.HasPrefix(what, "Bash command") || !strings.Contains(what, "touch made-by-test.txt") ||
		!strings.HasSuffix(what, "Do you want to proceed?") {
		t.Fatalf("got %v %q", ok, what)
	}
}

func TestPermissionDialogOthersLeftAlone(t *testing.T) {
	pane := dialogPane(t)
	for name, s := range map[string]string{
		// the trust dialog focuses "No, exit"
		"trust": " Quick safety check: Is this a project you created or one you trust?\n ❯ No, exit\n   Yes, I trust this folder\n\n Enter to confirm · Esc to cancel\n",
		// another option focused (someone is moving through it)
		"moved": strings.Replace(strings.Replace(pane, "❯ 1. Yes", "  1. Yes", 1), "  4. No", "❯ 4. No", 1),
		// the API key question
		"apikey": " Do you want to use this API key?\n ❯ 1. Yes\n   2. No (recommended)\n\n Enter to confirm · Esc to cancel\n",
		// a plan's approval
		"plan": " Would you like to proceed?\n ❯ 1. Yes, and auto-accept edits\n   2. Yes, and manually approve edits\n Esc to cancel\n",
		// a dialog quoted in the conversation, then the prompt box below it
		"quoted": pane + "\n● done\n\n────\n❯ \n────\n  ⏵⏵ bypass permissions on\n",
		"empty":  "",
	} {
		if ok, _ := permissionDialog(s); ok {
			t.Errorf("%s: taken for a tool permission dialog", name)
		}
	}
}

func TestPermissionDialogOtherTools(t *testing.T) {
	for _, q := range []string{"Do you want to make this edit to main.go?", "Do you want to create notes.md?",
		"Do you want to allow Claude to fetch this content?"} {
		s := " Edit file\n " + q + "\n ❯ 1. Yes\n   2. Yes, allow all edits during this session\n   3. No\n\n Esc to cancel · Tab to amend\n"
		if ok, _ := permissionDialog(s); !ok {
			t.Errorf("%q: not found", q)
		}
	}
}

func TestAcceptStepOnlyInBypassAndAtMostTwice(t *testing.T) {
	pane := dialogPane(t)
	var s acceptState
	if press, _ := acceptStep(&s, "auto", pane); press {
		t.Fatal("pressed in auto mode")
	}
	for i, want := range []bool{true, true, false, false} {
		if press, _ := acceptStep(&s, "bypass", pane); press != want {
			t.Fatalf("look %d on the same dialog: press %v", i, press)
		}
	}
	if press, _ := acceptStep(&s, "bypass", "❯ \n"); press {
		t.Fatal("pressed with no dialog")
	}
	if press, _ := acceptStep(&s, "bypass", pane); !press {
		t.Fatal("the next dialog (same text, after it had gone) not pressed")
	}
}
