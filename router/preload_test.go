package main

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/sig"
)

// the golden volumes asked for: none without PRELOAD_SESSION_IMAGE; the router's region and 20 GB by default; the
// configured regions and size otherwise, one POST /golden each
func TestPreloadAsksForAGoldenPerRegion(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if _, ok := preloadConfigFrom(env(nil), "lhr"); ok {
		t.Fatal("no PRELOAD_SESSION_IMAGE, and golden volumes asked for")
	}
	img := "ghcr.io/de0ch/jarvis4-session@sha256:" + "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4"
	c, ok := preloadConfigFrom(env(map[string]string{"PRELOAD_SESSION_IMAGE": img}), "lhr")
	if !ok || !reflect.DeepEqual(preloadSteps(c), []map[string]any{{"region": "lhr", "image": img, "diskGb": 20}}) {
		t.Fatalf("default: %+v", preloadSteps(c))
	}
	c, _ = preloadConfigFrom(env(map[string]string{"PRELOAD_SESSION_IMAGE": img, "PRELOAD_REGIONS": "lhr, sin,", "PRELOAD_DISK_GB": "40"}), "lhr")
	want := []map[string]any{{"region": "lhr", "image": img, "diskGb": 40}, {"region": "sin", "image": img, "diskGb": 40}}
	if !reflect.DeepEqual(preloadSteps(c), want) {
		t.Fatalf("configured: %+v", preloadSteps(c))
	}
}

// the preloader's answer is a document it signed: its state read from the payload
func TestGoldenStateReadsThePreloadersDocument(t *testing.T) {
	s, _ := sig.NewSigner()
	d, _ := s.SignJSON(map[string]any{"state": "ready", "volume": "vol_1"})
	b, _ := json.Marshal(d)
	if got := goldenState(b); got != "ready vol_1" {
		t.Fatalf("%q", got)
	}
	if got := goldenState([]byte("x")); got != "an answer that isn't the preloader's" {
		t.Fatalf("%q", got)
	}
}
