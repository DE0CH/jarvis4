package main

// The core's line state (core/continuity.go, docs/DESIGN.md "Core continuity"): a core set up with the seed from the
// master key seals what it must remember about lines (newest certs, killed/used, spent approvals, the input log's head,
// the deploy-key stores) after every call that changes it, and names the newest number in every answer
// (X-Line-Seq). The router keeps the newest one: on its volume at once (line-state.json, before the call's answer goes
// on), and in the backup bucket at most every few minutes and when it drains (keys/_jarvis2/line-state.json, for a
// router or box that comes back without its volume). At a Recover the app reads it (GET /api/core/line-state), checks
// it and hands it back to the new core in the claim bundle. The router can't read or forge it (sealed and signed by
// the core); it can withhold it (the lines then end, as before continuity) or serve an older one, which the app refuses
// below the newest number it has seen itself.

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	lineSeqHeader    = "X-Line-Seq"
	lineStateObject  = "keys/_jarvis2/line-state.json" // the bucket's copy (the router may only add versions under keys/)
	lineBucketPeriod = 5 * time.Minute
)

// LineStateDoc: as the core answers GET /line-state
type LineStateDoc struct {
	Head   Doc    `json:"head"`
	Sealed string `json:"sealed"`
}

// keptLineState: what the router keeps — the core's doc and the core key that signed its head
type keptLineState struct {
	Core string       `json:"core"`
	Seq  int          `json:"seq"`
	Doc  LineStateDoc `json:"doc"`
	At   time.Time    `json:"at"`
}

type lineKeeper struct {
	mu         sync.Mutex
	docs       docStore // where the kept line state is (router_docs: name)
	name       string
	object     string // its copy in the bucket
	kept       *keptLineState
	bucketSeq  int
	bucketAt   time.Time
	bucket     func() *backupBucket
	fetch      func() (int, []byte, error) // GET /line-state, raw
	coreKey    func() string               // the core's signing key (its identity)
	bucketBusy bool
}

// newKernelLineKeeper: the same for the kernel's secrets (kernel/secrets/continuity.go: its stores and the deploy-key
// stores, which have no backup), kept beside the core's (kernel-line-state.json; keys/_jarvis2/kernel-line-state.json)
func newKernelLineKeeper(docs docStore, k *KernelClient) *lineKeeper {
	lk := &lineKeeper{docs: docs, name: "kernel-line-state.json", object: "keys/_jarvis2/kernel-line-state.json", bucket: backupBucketFromEnv}
	lk.fetch = func() (int, []byte, error) {
		b, err := k.callNoHook("secrets", "GET", "/line-state", nil)
		if err != nil {
			var ke *KernelError
			if errors.As(err, &ke) {
				return ke.Status, nil, nil
			}
			return 0, nil, err
		}
		return 200, b, nil
	}
	lk.coreKey = func() string {
		k.forget("secrets") // a restarted secrets has other keys
		id, err := k.Identity("secrets")
		if err != nil {
			return ""
		}
		return id.SigningKey
	}
	if b, ok := docs.ReadDoc(lk.name); ok {
		var x keptLineState
		if json.Unmarshal(b, &x) == nil && x.Core != "" {
			lk.kept = &x
		}
	}
	return lk
}

// lineKeeperFor: the router's keeper, wired to its core client
func newLineKeeper(docs docStore, c *CoreClient) *lineKeeper {
	k := &lineKeeper{docs: docs, name: "line-state.json", object: lineStateObject, bucket: backupBucketFromEnv}
	k.fetch = func() (int, []byte, error) { return c.rawNoHook("GET", "/line-state", nil) }
	k.coreKey = func() string {
		st, b, err := c.rawNoHook("GET", "/identity", nil)
		if err != nil || st != 200 {
			return ""
		}
		var id struct {
			SigningKey string `json:"signingKey"`
		}
		json.Unmarshal(b, &id)
		return id.SigningKey
	}
	if b, ok := docs.ReadDoc(k.name); ok {
		var x keptLineState
		if json.Unmarshal(b, &x) == nil && x.Core != "" {
			k.kept = &x
		}
	}
	return k
}

// seen: an answer named seq n — fetch and keep the core's line state when it isn't the kept one (a newer one, or
// another core's after a Reset). Synchronous, so the answer that moved it goes on only once it is kept.
func (k *lineKeeper) seen(n int) {
	if n <= 0 {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.kept != nil && k.kept.Seq == n {
		return // already kept (a lower number is another core, or one Recovered from an older state: the running core's word goes)
	}
	st, b, err := k.fetch()
	if err != nil || st != 200 {
		log.Printf("line state %d: GET /line-state: %d %v", n, st, err)
		return
	}
	var d LineStateDoc
	var h struct {
		Kind string `json:"kind"`
		Seq  int    `json:"seq"`
	}
	if json.Unmarshal(b, &d) != nil || d.Head.Decode(&h) != nil || h.Kind != "line-state-head" {
		log.Printf("line state %d: not a line state", n)
		return
	}
	key := k.coreKey()
	if key == "" || !verifyP256(key, []byte(d.Head.Payload), d.Head.Sig) {
		log.Printf("line state %d: its head isn't signed by the running core", h.Seq)
		return
	}
	if k.kept != nil && k.kept.Core == key && k.kept.Seq == h.Seq {
		return
	}
	x := &keptLineState{Core: key, Seq: h.Seq, Doc: d, At: time.Now().UTC()}
	raw, _ := json.Marshal(x)
	if err := k.docs.WriteDoc(k.name, raw); err != nil {
		log.Printf("line state %d: can't write %s: %v", h.Seq, k.name, err)
		return
	}
	k.kept = x
	if time.Since(k.bucketAt) >= lineBucketPeriod && !k.bucketBusy {
		k.bucketBusy = true
		go k.toBucket()
	}
}

// toBucket: the kept state into the bucket (a new version; never deletes one)
func (k *lineKeeper) toBucket() {
	k.mu.Lock()
	x := k.kept
	k.mu.Unlock()
	defer func() { k.mu.Lock(); k.bucketBusy = false; k.mu.Unlock() }()
	if x == nil || x.Seq == k.bucketSeq {
		return
	}
	b := k.bucket()
	if b == nil {
		return
	}
	raw, _ := json.Marshal(x)
	if err := b.put(k.object, raw); err != nil {
		log.Printf("line state %d: bucket: %v", x.Seq, err)
		return
	}
	k.mu.Lock()
	k.bucketSeq, k.bucketAt = x.Seq, time.Now()
	k.mu.Unlock()
}

// flush: the newest into the bucket now (the router's drain)
func (k *lineKeeper) flush() {
	k.mu.Lock()
	busy := k.bucketBusy
	k.bucketBusy = true
	k.mu.Unlock()
	if !busy {
		k.toBucket()
	}
}

// current: the kept state; without one (a router that lost its volume), the bucket's copy
func (k *lineKeeper) current() *keptLineState {
	k.mu.Lock()
	x := k.kept
	k.mu.Unlock()
	if x != nil {
		return x
	}
	b := k.bucket()
	if b == nil {
		return nil
	}
	raw, err := b.get(k.object, nil)
	if err != nil {
		return nil
	}
	var y keptLineState
	if json.Unmarshal(raw, &y) != nil || y.Core == "" {
		return nil
	}
	return &y
}

func (r *Router) registerLineState(app func(string, http.HandlerFunc)) {
	// the kernel's secrets, the same way (KernelSetupView's Recover)
	app("GET /api/kernel/line-state", func(w http.ResponseWriter, req *http.Request) {
		var x *keptLineState
		if r.kernelLines != nil {
			x = r.kernelLines.current()
		}
		if x == nil {
			writeJSON(w, 404, map[string]string{"error": "the router keeps no line state of the kernel's secrets"})
			return
		}
		w.Header().Set(lineSeqHeader, strconv.Itoa(x.Seq))
		writeJSON(w, 200, x.Doc)
	})
	// the app's Recover: the newest line state the router holds (the app checks the head against the derived key and
	// against the newest number it has seen; the router's word decides nothing)
	app("GET /api/core/line-state", func(w http.ResponseWriter, req *http.Request) {
		x := r.lines.current()
		if x == nil {
			writeJSON(w, 404, map[string]string{"error": "the router keeps no line state"})
			return
		}
		w.Header().Set(lineSeqHeader, strconv.Itoa(x.Seq))
		writeJSON(w, 200, x.Doc)
	})
}

// isLineStateObject: the router's own object under keys/, which isn't a key backup (backups.go leaves it out)
func isLineStateObject(key string) bool { return strings.HasPrefix(key, "keys/_jarvis2/") }
