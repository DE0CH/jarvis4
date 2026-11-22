package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// cuttingBucket: one object over S3's GET/HEAD (Range included); the first `cut` GETs send the headers for the whole
// body, half of it, and then drop the connection, as WARP's resets did (2026-11-21)
func cuttingBucket(t *testing.T, body []byte, cut int32) (*s3Objects, *atomic.Int32) {
	t.Helper()
	var gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/bucket/snap" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(404)
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchKey</Code><Message>no</Message></Error>`)
			return
		}
		from := 0
		if r := req.Header.Get("Range"); strings.HasPrefix(r, "bytes=") {
			from, _ = strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(r, "bytes="), "-"))
		}
		part := body[from:]
		h := w.Header()
		h.Set("ETag", `"e1"`)
		h.Set("Last-Modified", time.Unix(1_700_000_000, 0).UTC().Format(http.TimeFormat))
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Accept-Ranges", "bytes")
		h.Set("Content-Length", strconv.Itoa(len(part)))
		if from > 0 {
			h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", from, len(body)-1, len(body)))
			w.WriteHeader(206)
		}
		if req.Method == "HEAD" {
			return
		}
		if gets.Add(1) <= cut {
			w.Write(part[:len(part)/2])
			w.(http.Flusher).Flush()
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		w.Write(part)
	}))
	t.Cleanup(srv.Close)
	c, err := minio.New(strings.TrimPrefix(srv.URL, "http://"), &minio.Options{Creds: credentials.NewStaticV4("k", "s", ""),
		Region: "fsn1", BucketLookup: minio.BucketLookupPath, MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	return &s3Objects{c: c, bucket: "bucket"}, &gets
}

func TestAnObjectReadCutOffGoesOnFromWhereItBroke(t *testing.T) {
	objResumeWait = time.Millisecond
	body := bytes.Repeat([]byte("0123456789abcdef"), 1<<14) // 256 KiB
	o, gets := cuttingBucket(t, body, 2)
	rd, err := o.Get(context.Background(), "snap")
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	got, err := io.ReadAll(rd)
	if err != nil {
		t.Fatalf("the read failed: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("read %d bytes, not the object's %d as it is", len(got), len(body))
	}
	if gets.Load() < 3 {
		t.Fatalf("%d GETs: the read was never cut", gets.Load())
	}
}

func TestAnObjectReadThatKeepsBreakingFailsInTheEnd(t *testing.T) {
	objResumeWait = time.Millisecond
	o, _ := cuttingBucket(t, bytes.Repeat([]byte("x"), 1<<16), 1000)
	rd, err := o.Get(context.Background(), "snap")
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	if _, err := io.ReadAll(rd); err == nil {
		t.Fatal("a read cut on every try came out whole")
	}
}

func TestAMissingObjectIsStillNoObject(t *testing.T) {
	o, _ := cuttingBucket(t, []byte("x"), 0)
	if _, err := o.Get(context.Background(), "other"); err != errNoObject {
		t.Fatalf("got %v, not errNoObject", err)
	}
}
