package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Upgrade keeps going: every step doubles the memory, and each guest is one Fly takes (machine-sizing rules)
func TestTheLadderKeepsGoing(t *testing.T) {
	want := []struct {
		size, kind string
		cpus, gb   int
	}{
		{"small", "shared", 2, 2}, {"medium", "shared", 4, 4}, {"large", "shared", 8, 8}, {"16gb", "shared", 8, 16},
		{"32gb", "performance", 8, 32}, {"64gb", "performance", 8, 64}, {"128gb", "performance", 16, 128},
		{"256gb", "performance", 32, 256}, {"512gb", "performance", 64, 512},
	}
	size := "small"
	for i, w := range want {
		if size != w.size {
			t.Fatalf("step %d: %q, want %q", i, size, w.size)
		}
		kind, cpus, mb := sizeGuest(size)
		if kind != w.kind || cpus != w.cpus || mb != w.gb*1024 || sizeMemGB(size) != w.gb {
			t.Fatalf("%s: %s %d %d", size, kind, cpus, mb)
		}
		// Fly: ≤ 2 GB per shared CPU; 2–8 GB per performance CPU, in steps of 2048 MB
		if kind == "shared" && mb > 2048*cpus || kind == "performance" && (mb > 8192*cpus || mb < 2048*cpus || mb%2048 != 0) {
			t.Fatalf("%s: %s %d×%d MB breaks Fly's sizing rules", size, kind, cpus, mb)
		}
		if got := sizeOf(&flyGuest{CPUKind: kind, CPUs: cpus, MemoryMB: mb}); got != size {
			t.Fatalf("sizeOf(%s guest) = %q", size, got)
		}
		next := nextSize(size)
		if sizeMemGB(next) != 2*w.gb {
			t.Fatalf("after %s comes %s", size, next)
		}
		size = next
	}
	if nextSize("") != "large" || nextSize("medium") != "large" {
		t.Fatal("a session with no size runs medium: its next is large")
	}
	for _, bad := range []string{"", "8gb", "17gb", "24gb", "016gb", "gb", "16GB", "16", "xlarge", "-16gb"} {
		if sizeMemGB(bad) != 0 {
			t.Fatalf("%q is a size", bad)
		}
	}
	if sizeOf(&flyGuest{CPUKind: "shared", CPUs: 4, MemoryMB: 8192}) != "" {
		t.Fatal("a guest no size has")
	}
	if sizeLabel("16gb") != "8×shared · 16 GB" || sizeLabel("32gb") != "8×performance · 32 GB" || sizeText("16gb") != "16 GB" || sizeText("large") != "large (8 GB)" {
		t.Fatal(sizeLabel("16gb"), sizeLabel("32gb"), sizeText("16gb"))
	}
	noteCoreSizes(true)
	t.Cleanup(func() { noteCoreSizes(false) })
	if !strings.Contains(memMessage("x", "large", &MemAlert{Reason: "r"}), "moves it to 16 GB") {
		t.Fatal(memMessage("x", "large", &MemAlert{Reason: "r"}))
	}
}

// the core makes the guest and the machine names the sizes in its "upgraded" text: the same block in all three
func TestSizeBlocksMatch(t *testing.T) {
	block := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		i, j := strings.Index(s, "// ---- machine sizes"), strings.Index(s, "// ---- end of the machine sizes block ----")
		if i < 0 || j < i {
			t.Fatalf("%s has no sizes block", path)
		}
		return s[i:j]
	}
	ours := block("sizes.go")
	for _, p := range []string{filepath.Join("..", "core", "fly.go"), filepath.Join("..", "machine", "deliver.go")} {
		if block(p) != ours {
			t.Fatalf("%s's sizes block differs from router/sizes.go's", p)
		}
	}
	// the kernel's spawner makes guests only (no Upgrade): its block is router/sizes.go's without the parts it doesn't
	// use, each part it has the same
	kernel := block(filepath.Join("..", "kernel", "spawner", "fly.go"))
	for _, part := range strings.Split(kernel, "\n\n") {
		if !strings.Contains(ours, part) {
			t.Fatalf("kernel/spawner/fly.go's sizes block has a part router/sizes.go's lacks:\n%s", part)
		}
	}
	for _, need := range []string{"func sizeMemGB(", "func sizeGuest(", "var namedSizes"} {
		if !strings.Contains(kernel, need) {
			t.Fatalf("kernel/spawner/fly.go's sizes block has no %s", need)
		}
	}
}

// sizeCore: a core whose Fly refuses one guest
type sizeCore struct {
	fakeCore
	refuse string
	mu     sync.Mutex
	sizes  []string
}

func (c *sizeCore) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/start" {
		var b map[string]any
		json.NewDecoder(req.Body).Decode(&b)
		size, _ := b["size"].(string)
		c.mu.Lock()
		c.sizes = append(c.sizes, size)
		c.mu.Unlock()
		if size == c.refuse {
			writeJSON(w, 502, c.key.doc(map[string]string{"kind": "error", "error": `fly create: POST /machines: HTTP 422 {"error":"invalid guest"}`}))
			return
		}
		writeJSON(w, 502, c.key.doc(map[string]string{"kind": "error", "error": "no Fly in tests"}))
		return
	}
	c.fakeCore.ServeHTTP(w, req)
}

func (c *sizeCore) starts() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string{}, c.sizes...)
}

// a size Fly refuses: Upgrade reports Fly's own error and the session goes back to its old size
func TestUpgradeAFlyRefusalGoesBackToTheOldSize(t *testing.T) {
	rg := newRig(t)
	sc := &sizeCore{fakeCore: fakeCore{key: newTestKey()}, refuse: "256gb"}
	cs := httptest.NewServer(sc)
	t.Cleanup(cs.Close)
	rg.r.core = &CoreClient{base: cs.URL, http: http.DefaultClient}
	rg.r.cfg.NoAccess = true
	old := opsPoll
	opsPoll = time.Millisecond
	t.Cleanup(func() { opsPoll = old })
	rg.r.st.Do(func(d *persisted) { d.Sessions["s1"].Cert, d.Sessions["s1"].Size = rg.cert, "128gb" })
	err := rg.r.resumeBigger("s1", "128gb", "256gb")
	if err == nil || !strings.Contains(err.Error(), `256gb: core: fly create: POST /machines: HTTP 422 {"error":"invalid guest"}`) {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(err.Error(), "resuming it on 128gb failed too: core: no Fly in tests") {
		t.Fatalf("the way back: %v", err)
	}
	if got := sc.starts(); len(got) != 2 || got[0] != "256gb" || got[1] != "128gb" {
		t.Fatalf("starts %v", got)
	}
	rg.r.st.Do(func(d *persisted) {
		if d.Sessions["s1"].Size != "128gb" {
			t.Fatalf("size %s", d.Sessions["s1"].Size)
		}
	})
	waitFor(t, "idle", func() bool { _, err := rg.r.lock("s1", "test-end"); return err == nil })
}
