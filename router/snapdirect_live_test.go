package main

// The bucket's side of the machines' direct snapshots (snapdirect.go) against the real bucket: a multipart upload put
// through signed part URLs, finished, read back, read again through a signed URL in ranges, and an upload aborted.
// Only with the credential (OBJECTS_ACCESS_KEY / OBJECTS_SECRET_KEY, the infra store's JARVIS4_OBJECTS_*):
//
//	OBJECTS_ACCESS_KEY=… OBJECTS_SECRET_KEY=… go test -run LiveSnapDirect

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestLiveSnapDirect(t *testing.T) {
	o, err := objectsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if o == nil {
		t.Skip("no OBJECTS_ACCESS_KEY: not against the real bucket")
	}
	d := o.(objDirect)
	ctx := context.Background()
	key := "probe/direct-" + randID() + ".tar.gz"
	defer o.Delete(ctx, key)

	// an unfinished upload of the key is ended by the next start
	stale, err := d.StartUpload(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	up, err := d.StartUpload(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if u, err := d.PartURL(ctx, key, stale, 1, time.Minute); err == nil {
		if code, _ := put(t, u, []byte("x")); code == 200 {
			t.Fatal("a part of the aborted earlier upload was taken")
		}
	}

	parts := [][]byte{make([]byte, 5<<20), make([]byte, 1<<20+7)}
	for _, p := range parts {
		rand.Read(p)
	}
	var etags []string
	for i, p := range parts {
		u, err := d.PartURL(ctx, key, up, i+1, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		code, etag := put(t, u, p)
		if code != 200 || etag == "" {
			t.Fatalf("part %d: HTTP %d, etag %q", i+1, code, etag)
		}
		etags = append(etags, etag)
	}
	if err := d.FinishUpload(ctx, key, up, etags); err != nil {
		t.Fatal(err)
	}
	want := bytes.Join(parts, nil)
	rd, err := o.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rd)
	rd.Close()
	if !bytes.Equal(got, want) {
		t.Fatalf("read back %d bytes, not the %d put", len(got), len(want))
	}
	// a part URL of the finished upload is dead
	if u, err := d.PartURL(ctx, key, up, 1, time.Minute); err == nil {
		if code, _ := put(t, u, []byte("overwrite")); code == 200 {
			t.Fatal("a part URL still writes after the upload was finished")
		}
	}

	u, err := d.GetURL(ctx, key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", 5<<20-3, 5<<20+2))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 206 || !bytes.Equal(b, want[5<<20-3:5<<20+3]) {
		t.Fatalf("range: HTTP %d, %d bytes", resp.StatusCode, len(b))
	}

	ab, err := d.StartUpload(ctx, key+".aborted")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.AbortUpload(ctx, key+".aborted", ab); err != nil {
		t.Fatal(err)
	}
}

func put(t *testing.T, u string, body []byte) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("PUT", u, bytes.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("ETag")
}
