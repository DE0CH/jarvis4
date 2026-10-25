package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBucket: a bucket's part uploads and ranged reads, with the router's side of snapdirect.go in front of it
type fakeBucket struct {
	mu        sync.Mutex
	parts     map[int][]byte
	object    []byte
	failOnce  map[int]bool // a part whose first PUT fails
	puts      int
	direct    bool // the router signs bucket URLs (else 404: the stream through the router)
	streamed  []byte
	aborted   bool
	rangeGets int
}

func newFakeBucket(t *testing.T) (*fakeBucket, *client) {
	b := &fakeBucket{parts: map[int][]byte{}, failOnce: map[int]bool{}, direct: true}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		body, _ := io.ReadAll(req.Body)
		var in map[string]any
		json.Unmarshal(body, &in)
		reply := func(v any) { json.NewEncoder(w).Encode(v) }
		switch {
		case strings.HasPrefix(req.URL.Path, "/m/snapshot-upload") || req.URL.Path == "/m/snapshot-url":
			if !b.direct {
				w.WriteHeader(404)
				return
			}
		}
		switch req.URL.Path {
		case "/m/snapshot-upload":
			reply(map[string]any{"upload": "u1", "partSize": 5 << 20})
		case "/m/snapshot-upload/parts":
			var urls []string
			from, count := int(in["from"].(float64)), int(in["count"].(float64))
			for p := from; p < from+count; p++ {
				urls = append(urls, srv.URL+"/bucket?partNumber="+strconv.Itoa(p))
			}
			reply(map[string]any{"urls": urls})
		case "/bucket":
			if req.Method == "PUT" {
				p, _ := strconv.Atoi(req.URL.Query().Get("partNumber"))
				b.puts++
				if b.failOnce[p] {
					delete(b.failOnce, p)
					w.WriteHeader(500)
					return
				}
				b.parts[p] = body
				w.Header().Set("ETag", fmt.Sprintf(`"e%d"`, p))
				return
			}
			var from, to int
			fmt.Sscanf(req.Header.Get("Range"), "bytes=%d-%d", &from, &to)
			b.rangeGets++
			w.WriteHeader(206)
			w.Write(b.object[from : to+1])
		case "/m/snapshot-upload/done":
			b.object = nil
			for i, p := range in["parts"].([]any) {
				m := p.(map[string]any)
				if int(m["n"].(float64)) != i+1 || m["etag"] != fmt.Sprintf(`"e%d"`, i+1) {
					w.WriteHeader(400)
					return
				}
				b.object = append(b.object, b.parts[i+1]...)
			}
			sum := sha256.Sum256(b.object)
			reply(map[string]any{"sha256": hex.EncodeToString(sum[:]), "bytes": len(b.object)})
		case "/m/snapshot-upload/abort":
			b.aborted = true
			reply(map[string]bool{"ok": true})
		case "/m/snapshot-stream":
			b.streamed = body
			sum := sha256.Sum256(body)
			reply(map[string]any{"sha256": hex.EncodeToString(sum[:]), "bytes": len(body)})
		case "/m/snapshot-url":
			reply(map[string]any{"url": srv.URL + "/bucket", "sha256": "", "bytes": len(b.object), "sig": "the-sig"})
		case "/m/snapshot":
			w.Header().Set("X-Snapshot-Sig", "the-sig")
			w.Write(b.object)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return b, &client{base: srv.URL, me: "m1", sig: newKey().k, http: srv.Client()}
}

// a home whose snapshot is several parts: a large file that doesn't compress and a few small ones
func snapHome(t *testing.T) string {
	home := t.TempDir()
	t.Setenv("HOME", home)
	big := make([]byte, 12<<20)
	rand.Read(big)
	os.MkdirAll(filepath.Join(home, "workspace/repo"), 0o755)
	os.WriteFile(filepath.Join(home, "workspace/repo/big.bin"), big, 0o644)
	os.WriteFile(filepath.Join(home, "workspace/repo/a.txt"), []byte("hello"), 0o600)
	os.MkdirAll(filepath.Join(home, ".claude/projects/p"), 0o755)
	os.WriteFile(filepath.Join(home, ".claude/projects/p/c.jsonl"), []byte(`{"type":"user"}`+"\n"), 0o600)
	return home
}

func TestDirectSnapshotGoesUpInPartsAndComesBack(t *testing.T) {
	directBackoff = time.Millisecond
	snapHome(t)
	b, c := newFakeBucket(t)
	b.failOnce[2] = true // tried again
	sum, n, err := directSnapshot(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.parts) != 3 || b.puts != 4 || int64(len(b.object)) != n {
		t.Fatalf("%d parts, %d puts, %d of %d bytes", len(b.parts), b.puts, len(b.object), n)
	}
	if !bytes.HasPrefix(b.object, s2Magic) {
		t.Fatal("not an S2 stream")
	}

	// the next machine: ranges of the object into the file, then the hash and the unpack
	rangeSize = 4 << 20
	t.Setenv("HOME", t.TempDir())
	dst := filepath.Join(t.TempDir(), "pred")
	got, sig, err := fetchSnapshot(c, dst)
	if err != nil || got != sum || sig != "the-sig" {
		t.Fatalf("%v %s %s %q", err, got, sum, sig)
	}
	if b.rangeGets < 4 {
		t.Fatalf("%d range reads", b.rangeGets)
	}
	if files, err := unpackFile(dst); err != nil || files != 3 {
		t.Fatal(files, err)
	}
	home, _ := os.UserHomeDir()
	if s, _ := os.ReadFile(filepath.Join(home, "workspace/repo/a.txt")); string(s) != "hello" {
		t.Fatalf("%q", s)
	}
	if fi, err := os.Stat(filepath.Join(home, "workspace/repo/big.bin")); err != nil || fi.Size() != 12<<20 {
		t.Fatal(fi, err)
	}
}

func TestDirectSnapshotFailsAndAbortsWhenAPartNeverGoesUp(t *testing.T) {
	directBackoff, directTries = time.Millisecond, 1
	t.Cleanup(func() { directTries = 4 })
	snapHome(t)
	b, c := newFakeBucket(t)
	b.failOnce[1] = true // its one try fails
	if _, _, err := directSnapshot(c); err == nil || !strings.Contains(err.Error(), "part 1") {
		t.Fatal(err)
	}
	if !b.aborted {
		t.Fatal("the upload wasn't aborted")
	}
}

func TestNoBucketURLsMeansTheStreamThroughTheRouter(t *testing.T) {
	snapHome(t)
	b, c := newFakeBucket(t)
	b.direct = false
	if _, _, err := directSnapshot(c); err != errNoDirect {
		t.Fatal(err)
	}
	sum, _, err := streamSnapshot(c)
	if err != nil || len(b.streamed) == 0 {
		t.Fatal(err)
	}
	b.object = b.streamed
	got, sig, err := fetchSnapshot(c, filepath.Join(t.TempDir(), "pred")) // /m/snapshot, through the router
	if err != nil || got != sum || sig != "the-sig" {
		t.Fatal(err, got, sig)
	}
}
