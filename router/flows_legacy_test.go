package main

import "testing"

func TestLegacyLoginImage(t *testing.T) {
	order := []string{
		"ghcr.io/de0ch/jarvis4-session:sha-f07bfc204790@sha256:085b",
		"ghcr.io/de0ch/jarvis4-session:sha-828a6521769c@sha256:449a",
		"ghcr.io/de0ch/jarvis4-session:sha-c5427052a542@sha256:b578",
		"ghcr.io/de0ch/jarvis4-session:sha-bc727daca489@sha256:56bb",
	}
	for img, want := range map[string]bool{
		"ghcr.io/de0ch/jarvis4-session@sha256:085b":                  true, // no tag, an early pin
		"ghcr.io/de0ch/jarvis4-session:sha-828a6521769c@sha256:449a": true,
		"ghcr.io/de0ch/jarvis4-session:sha-c5427052a542@sha256:b578": false,
		"ghcr.io/de0ch/jarvis4-session:sha-bc727daca489@sha256:56bb": false,
		"ghcr.io/de0ch/jarvis4-session@sha256:0000":                  true, // before the list began
		"": false,
	} {
		if got := legacyLoginImage(img, order); got != want {
			t.Errorf("%s: %v", img, got)
		}
	}
	if legacyLoginImage("x@sha256:085b", order[:2]) || legacyLoginImage("x@sha256:085b", nil) {
		t.Fatal("no marker in the order: never legacy")
	}
}

func TestPinnedImage(t *testing.T) {
	order := []string{
		"ghcr.io/de0ch/jarvis4-session:sha-f07bfc204790@sha256:085b",
		"ghcr.io/de0ch/jarvis4-session:sha-828a6521769c@sha256:449a",
	}
	cur := "ghcr.io/de0ch/jarvis4-session:sha-c5427052a542@sha256:b578"
	for img, want := range map[string]string{
		"ghcr.io/de0ch/jarvis4-session@sha256:449a": order[1], // the machine's bare form: the signed pin
		"ghcr.io/de0ch/jarvis4-session@sha256:b578": cur,
		order[0]: order[0],
		"ghcr.io/de0ch/jarvis4-session@sha256:0000": "ghcr.io/de0ch/jarvis4-session@sha256:0000", // never pinned
		"": "",
	} {
		if got := pinnedImage(img, cur, order); got != want {
			t.Errorf("%s: %s", img, got)
		}
	}
}
