package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/s2"
)

// directMem: the memory store with the bucket's direct side (snapdirect.go), its part and read URLs served by a test
// server
type directMem struct {
	*memObjects
	srv   *httptest.Server
	mu    sync.Mutex
	parts map[string]map[int][]byte // upload → part → bytes
	done  map[string]bool
}

func newDirectMem(t *testing.T) *directMem {
	d := &directMem{memObjects: newMemObjects(), parts: map[string]map[int][]byte{}, done: map[string]bool{}}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q := req.URL.Query()
		if req.Method == "PUT" {
			p, _ := strconv.Atoi(q.Get("partNumber"))
			b, _ := io.ReadAll(req.Body)
			d.mu.Lock()
			defer d.mu.Unlock()
			if d.parts[q.Get("uploadId")] == nil || d.done[q.Get("uploadId")] {
				w.WriteHeader(404)
				return
			}
			d.parts[q.Get("uploadId")][p] = b
			w.Header().Set("ETag", fmt.Sprintf(`"%d"`, p))
			return
		}
		rd, err := d.Get(req.Context(), strings.TrimPrefix(req.URL.Path, "/"))
		if err != nil {
			w.WriteHeader(404)
			return
		}
		http.ServeContent(w, req, "", time.Time{}, rd)
	}))
	t.Cleanup(d.srv.Close)
	return d
}

func (d *directMem) StartUpload(_ context.Context, key string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	id := randID()
	d.parts[id] = map[int][]byte{}
	return id, nil
}

func (d *directMem) PartURL(_ context.Context, key, upload string, part int, _ time.Duration) (string, error) {
	return fmt.Sprintf("%s/%s?partNumber=%d&uploadId=%s", d.srv.URL, key, part, upload), nil
}

func (d *directMem) FinishUpload(ctx context.Context, key, upload string, etags []string) error {
	d.mu.Lock()
	var all []byte
	for i, e := range etags {
		b, ok := d.parts[upload][i+1]
		if !ok || e != fmt.Sprintf(`"%d"`, i+1) {
			d.mu.Unlock()
			return fmt.Errorf("part %d: no such part", i+1)
		}
		all = append(all, b...)
	}
	d.done[upload] = true
	d.mu.Unlock()
	return d.Put(ctx, key, bytes.NewReader(all), int64(len(all)))
}

func (d *directMem) AbortUpload(_ context.Context, key, upload string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.done[upload] = true
	return nil
}

func (d *directMem) GetURL(_ context.Context, key string, _ time.Duration) (string, error) {
	return d.srv.URL + "/" + key, nil
}

// testSnapTar: a snapshot holding one transcript and the repos' state, compressed with S2 or gzip
func testSnapTar(t *testing.T, gz bool) []byte {
	var buf bytes.Buffer
	var zw io.WriteCloser = s2.NewWriter(&buf)
	if gz {
		zw = gzip.NewWriter(&buf)
	}
	tw := tar.NewWriter(zw)
	put := func(name, body string) {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg, ModTime: time.Now()})
		tw.Write([]byte(body))
	}
	put(".claude/projects/-home-claude-workspace/0b6a2f3e-1111-4222-8333-444455556666.jsonl", `{"type":"user"}`+"\n")
	put(changesFile, "claude-env 2 0\n")
	put("workspace/x", strings.Repeat("x", 6<<20))
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func TestSnapshotFactsReadBothFormats(t *testing.T) {
	for _, gz := range []bool{false, true} {
		f, err := readSnapshotFactsFrom(bytes.NewReader(testSnapTar(t, gz)))
		if err != nil || len(f.Transcripts) != 1 || f.Changes == nil || !strings.Contains(*f.Changes, "claude-env 2 0") {
			t.Fatalf("gzip %v: %+v %v", gz, f, err)
		}
	}
	if _, err := readSnapshotFactsFrom(strings.NewReader("plain text")); err == nil {
		t.Fatal("read facts from neither format")
	}
}

func TestNoDirectBucketMeansNoUploadURLs(t *testing.T) {
	rg := newRig(t)
	runningM2(rg, false)
	m := testMachine{"m2", rg.mkey.k}
	h := rg.r.MachineHandler()
	if code, _ := m.do(t, h, "POST", "/m/snapshot-upload", "{}"); code != 404 {
		t.Fatalf("an upload with no bucket to sign for: %d", code)
	}
}

// the machine puts its snapshot to the bucket in parts; the router reads it back, keeps it pending under that hash, the
// machine's signature commits it, and the successor gets a read URL with the signature
func TestADirectSnapshotIsReadBackCommittedAndHandedToTheSuccessor(t *testing.T) {
	rg := newRig(t)
	d := newDirectMem(t)
	rg.r.objects = d
	runningM2(rg, false)
	m := testMachine{"m2", rg.mkey.k}
	h := rg.r.MachineHandler()
	body := testSnapTar(t, false)

	code, out := m.do(t, h, "POST", "/m/snapshot-upload", "{}")
	if code != 200 || out["partSize"] != float64(directPartSize) {
		t.Fatalf("%d %v", code, out)
	}
	up := out["upload"].(string)
	if code, _ := m.do(t, h, "POST", "/m/snapshot-upload/parts", `{"upload":"`+up+`","from":1,"count":65}`); code != 400 {
		t.Fatalf("65 part URLs at once: %d", code)
	}
	code, out = m.do(t, h, "POST", "/m/snapshot-upload/parts", `{"upload":"`+up+`","from":1,"count":2}`)
	if code != 200 || len(out["urls"].([]any)) != 2 {
		t.Fatalf("%d %v", code, out)
	}
	half := len(body) / 2
	var etags []string
	for i, chunk := range [][]byte{body[:half], body[half:]} {
		req, _ := http.NewRequest("PUT", out["urls"].([]any)[i].(string), bytes.NewReader(chunk))
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			t.Fatal(err, resp.StatusCode)
		}
		etags = append(etags, resp.Header.Get("ETag"))
	}
	if code, _ := m.do(t, h, "POST", "/m/snapshot-upload/done", `{"upload":"`+up+`","parts":[{"n":2,"etag":`+strconv.Quote(etags[1])+`}]}`); code != 400 {
		t.Fatalf("parts out of order: %d", code)
	}
	sum := sha256.Sum256(body)
	want := hex.EncodeToString(sum[:])
	code, out = m.do(t, h, "POST", "/m/snapshot-upload/done", `{"upload":"`+up+`","parts":[{"n":1,"etag":`+strconv.Quote(etags[0])+`},{"n":2,"etag":`+strconv.Quote(etags[1])+`}]}`)
	if code != 200 || out["sha256"] != want || out["bytes"] != float64(len(body)) {
		t.Fatalf("%d %v", code, out)
	}
	if s := rg.r.snap("m2"); s == nil || s.State != "pending" || s.Facts == nil || len(s.Facts.Transcripts) != 1 {
		t.Fatalf("the pending row: %+v", s)
	}
	good, _ := signP256(rg.mkey.k, []byte(want))
	if code, _ := m.do(t, h, "POST", "/m/snapshot-commit", `{"sha256":"`+want+`","sig":"`+good+`"}`); code != 200 || !rg.r.haveSnap("m2") {
		t.Fatalf("commit: %d", code)
	}
	// the finished upload's part URL writes nothing more
	req, _ := http.NewRequest("PUT", out2url(t, m, h, up), strings.NewReader("overwrite"))
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode == 200 {
		t.Fatal("a part URL of the finished upload still writes")
	}

	// the successor m3 (its cert's predecessor is m2)
	m3 := newTestMachine(rg.r, "m3")
	rg.r.st.Do(func(dd *persisted) {
		dd.Certs["m3"] = rg.core.key.doc(map[string]any{"kind": "succession-cert", "predecessorId": "m2", "line": "m1"})
		dd.Machines["m3"] = "s1"
	})
	code, out = m3.do(t, h, "GET", "/m/snapshot-url", "")
	if code != 200 || out["sha256"] != want || out["sig"] != good || out["bytes"] != float64(len(body)) {
		t.Fatalf("%d %v", code, out)
	}
	resp, err := http.Get(out["url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(got, body) {
		t.Fatal("the read URL serves other bytes")
	}
	// a machine with no predecessor gets none
	m4 := newTestMachine(rg.r, "m4")
	if code, out := m4.do(t, h, "GET", "/m/snapshot-url", ""); code != 404 || out["error"] != "no predecessor" {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := m.do(t, h, "POST", "/m/snapshot-upload/abort", `{"upload":"`+up+`"}`); code != 200 {
		t.Fatal(code)
	}
}

func out2url(t *testing.T, m testMachine, h http.Handler, up string) string {
	code, out := m.do(t, h, "POST", "/m/snapshot-upload/parts", `{"upload":"`+up+`","from":1,"count":1}`)
	if code != 200 {
		t.Fatal(code)
	}
	return out["urls"].([]any)[0].(string)
}
