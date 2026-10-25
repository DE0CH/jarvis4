package main

// Helpers shared by the message paths. Every message into a session goes in as a core-attested delivery the machine
// sends into its harness itself (vouch.go deliverVouched, machine/deliver.go); the router runs no command for it, and
// no router feature holds a grant for it (into a session holding a sensitive store, Deyao delivers or denies each
// message: messages.go).

import (
	"strings"
)

const peerMaxText = 16000

// harnesses that take prompts through /usr/local/bin/harness-send rather than a claude host
var harnessSend = map[string]bool{"opencode": true, "openclaw": true, "paseo-claude": true, "cloudcli": true, "dsh": true}

// cleanPeerText: CRLF → LF, trimmed, capped
func cleanPeerText(text string) string {
	text = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n"))
	if len(text) > peerMaxText {
		text = text[:peerMaxText]
	}
	return text
}

func trimTo(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// isGrantRefusal: the machine refused a router feature's shell (no grant, not on the allow list, a sensitive store).
// Retrying won't help until Deyao grants it from the phone.
func isGrantRefusal(err error) bool {
	if err == nil {
		return false
	}
	m := err.Error()
	if !strings.Contains(m, "the machine refused or failed") {
		return false
	}
	for _, k := range []string{"allow list", "sensitive store", "phone grant", "grant is", "standing rule", "not signed by the phone"} {
		if strings.Contains(m, k) {
			return true
		}
	}
	return false
}
