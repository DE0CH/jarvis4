package main

// Snapshots straight between the machines and the bucket (machine/snapdirect.go, DECISIONS 241). The machines' way to
// the router, Fly's WireGuard peer into m-gateway, carries about 6 MB/s per connection and 15 MB/s in all (measured
// 2026-10-25: the Deepseek session's 1.75 GB snapshot took 14.5 min up and 4.5 min down), while the bucket answers a
// Fly machine at 86 MB/s on one stream. So the router only signs the way and checks what arrived:
//
//	POST /m/snapshot-upload         {} → {upload, partSize}: a multipart upload of the machine's own object
//	                                snapshots/<machine>.tar.gz (an earlier unfinished one of it is aborted)
//	POST /m/snapshot-upload/parts   {upload, from, count ≤ 64} → {urls}: part URLs for parts from … from+count-1, one hour
//	POST /m/snapshot-upload/done    {upload, parts: [{n, etag}], sha256, bytes} → {sha256, bytes}: the upload finished,
//	                                then the object read back through the router, hashed, counted and read for its
//	                                facts (every read is the awaited snapshot's progress), and kept as the machine's
//	                                pending snapshot, exactly as a streamed one (snapstream.go); the machine commits it
//	                                with its signature only when that hash is its own
//	POST /m/snapshot-upload/abort   {upload}
//	GET  /m/snapshot-url            → {url, sha256, bytes, sig?}: a one-hour read URL of the snapshot GET /m/snapshot
//	                                sends (the predecessor's, or a restoring line's first), sig when it has one
//
// 404 when the router has no bucket it can sign for (the memory stand-in): the machine streams through the router.
// What a machine can do with these is what it could already do through the router: write its own object, read its own
// predecessor's; a part URL is dead once its upload is finished or aborted, and the hash the machine signs is the one
// the router read back.

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const (
	directPartSize = 16 << 20
	directURLTTL   = time.Hour
	directMaxParts = 10000 // S3's
)

func (r *Router) objDirect() objDirect {
	d, _ := r.objects.(objDirect)
	return d
}

// snapshotFor: the snapshot a machine's boot takes (GET /m/snapshot): its predecessor's committed one (signed: its
// signature goes with it), or, for a restoring line's first machine, the archived one (checked by the cert's hash) →
// nil and why when there is none
func (r *Router) snapshotFor(machine string) (*Snap, bool, string) {
	var pred string
	r.st.Do(func(d *persisted) {
		if st := d.Started[machine]; st != nil && st.KernelPred != "" { // kernelline.go: the source's machine
			pred = st.KernelPred
			return
		}
		if st := d.Started[machine]; st != nil && st.KernelCert != nil {
			pred = "restore" // a kernel line's first machine: the archived snapshot its source names, if any
			return
		}
		if cert := d.Certs[machine]; cert != nil {
			var c struct {
				PredID string `json:"predecessorId"`
			}
			cert.Decode(&c)
			pred = c.PredID
		}
	})
	switch pred {
	case "restore":
		if s := r.restoreFilesFor(machine); s != nil { // restore.go: only a restoring line's first machine
			return s, false, ""
		}
		return nil, false, "no predecessor"
	case "":
		return nil, false, "no predecessor"
	}
	s := r.snap(pred)
	if s == nil || s.State != "committed" {
		return nil, false, "no snapshot"
	}
	return s, true, ""
}

func (r *Router) registerSnapDirect(m machineRoute) {
	direct := func(w http.ResponseWriter) objDirect {
		d := r.objDirect()
		if d == nil {
			writeJSON(w, 404, map[string]string{"error": "no bucket the machines can reach: stream the snapshot through the router"})
		}
		return d
	}
	m("POST /m/snapshot-upload", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		d := direct(w)
		if d == nil {
			return
		}
		up, err := d.StartUpload(req.Context(), snapKey(machine))
		if err != nil {
			writeErr(w, err)
			return
		}
		log.Printf("machine %s: snapshot upload %.12s… started (straight to the bucket)", machine, up)
		writeJSON(w, 200, map[string]any{"upload": up, "partSize": directPartSize})
	})
	m("POST /m/snapshot-upload/parts", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct {
			Upload      string
			From, Count int
		}
		if json.Unmarshal(body, &in) != nil || in.Upload == "" || in.From < 1 || in.Count < 1 || in.Count > 64 || in.From+in.Count-1 > directMaxParts {
			writeJSON(w, 400, map[string]string{"error": "{upload, from ≥ 1, count 1..64}, parts up to 10000"})
			return
		}
		d := direct(w)
		if d == nil {
			return
		}
		urls := make([]string, 0, in.Count)
		for p := in.From; p < in.From+in.Count; p++ {
			u, err := d.PartURL(req.Context(), snapKey(machine), in.Upload, p, directURLTTL)
			if err != nil {
				writeErr(w, err)
				return
			}
			urls = append(urls, u)
		}
		r.snapshotMoved(machine)
		writeJSON(w, 200, map[string]any{"urls": urls})
	})
	m("POST /m/snapshot-upload/done", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct {
			Upload string
			Parts  []struct {
				N    int
				ETag string
			}
		}
		if json.Unmarshal(body, &in) != nil || in.Upload == "" || len(in.Parts) == 0 || len(in.Parts) > directMaxParts {
			writeJSON(w, 400, map[string]string{"error": "{upload, parts: [{n, etag}]}"})
			return
		}
		etags := make([]string, len(in.Parts))
		for i, p := range in.Parts {
			if p.N != i+1 || p.ETag == "" {
				writeJSON(w, 400, map[string]string{"error": fmt.Sprintf("part %d: the parts go 1, 2, … each with its etag", i+1)})
				return
			}
			etags[i] = p.ETag
		}
		d := direct(w)
		if d == nil {
			return
		}
		key := snapKey(machine)
		if err := d.FinishUpload(req.Context(), key, in.Upload, etags); err != nil {
			log.Printf("machine %s: snapshot upload: finishing: %v", machine, err)
			writeErr(w, err)
			return
		}
		r.snapshotMoved(machine)
		t0 := time.Now()
		rd, err := r.objects.Get(req.Context(), key)
		if err != nil {
			writeErr(w, err)
			return
		}
		defer rd.Close()
		sum, n, facts, err := snapIngest(movedReader{rd, r, machine}, func(b io.Reader) error {
			_, err := io.Copy(io.Discard, b)
			return err
		})
		if err == nil {
			err = r.snapPending(machine, key, sum, n, facts)
		}
		if err != nil {
			log.Printf("machine %s: snapshot upload: reading it back: %v", machine, err)
			writeErr(w, err)
			return
		}
		log.Printf("machine %s: snapshot upload of %d parts done, %d bytes read back in %.1f s (%.12s…)", machine, len(etags), n, time.Since(t0).Seconds(), sum)
		writeJSON(w, 200, map[string]any{"sha256": sum, "bytes": n})
	})
	m("POST /m/snapshot-upload/abort", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct{ Upload string }
		if json.Unmarshal(body, &in) != nil || in.Upload == "" {
			writeJSON(w, 400, map[string]string{"error": "{upload}"})
			return
		}
		d := direct(w)
		if d == nil {
			return
		}
		if err := d.AbortUpload(req.Context(), snapKey(machine), in.Upload); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	m("GET /m/snapshot-url", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		s, signed, why := r.snapshotFor(machine)
		if s == nil {
			writeJSON(w, 404, map[string]string{"error": why})
			return
		}
		d := direct(w)
		if d == nil {
			return
		}
		u, err := d.GetURL(req.Context(), s.Key, directURLTTL)
		if err != nil {
			writeErr(w, err)
			return
		}
		out := map[string]any{"url": u, "sha256": s.Sha256, "bytes": s.Bytes}
		if signed {
			out["sig"] = s.Sig
		}
		writeJSON(w, 200, out)
	})
}
