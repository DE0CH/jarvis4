package main

// The store backups for the app's Recover (docs/DESIGN.md "Recover"). The router holds the backup bucket's
// credential (BACKUP_READ_ACCESS_KEY / BACKUP_READ_SECRET_KEY, router secrets — a Hetzner S3 credential that bucket
// policies narrow to reads of jarvis2-backup-de0ch and new versions of keys/: no delete, no policy, no other prefix),
// writes each key's backup as the key is written (storedocs.go: keys/<store>/<key>.json, sealed to the master key by
// the writer and signed by it), and hands the app the locked backups as they are in the bucket. The router can't
// read, change or forge one (a writer's signature covers it); it can only withhold a backup or serve an older version
// (the bucket is versioned: a new version never removes an old one).
//
// With BACKUP_WRITE_BUCKET (Jarvis 4: jarvis4-backup-de0ch) the router writes its key backups there, never into the
// bucket it reads (Jarvis 2's, whose latest versions must stay Jarvis 2's: a bucket policy denies the key every write
// there), and serves both: the write bucket's objects over the read bucket's of the same name.
//
//	GET /api/backups → {bucket, objects: [{key, body}]}: every object under stores/, keys/ and sensitive/, body = the
//	                   object's text; 503 {error} without the credential.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

type backupBucket struct {
	endpoint, region, bucket string
	write                    string // the bucket the router writes ("" = bucket)
	accessKey, secretKey     string
	http                     *http.Client
	now                      func() time.Time
}

func backupBucketFromEnv() *backupBucket {
	ak, sk := os.Getenv("BACKUP_READ_ACCESS_KEY"), os.Getenv("BACKUP_READ_SECRET_KEY")
	if ak == "" || sk == "" {
		return nil
	}
	return &backupBucket{endpoint: strings.TrimSuffix(env("BACKUP_ENDPOINT", "https://fsn1.your-objectstorage.com"), "/"),
		region: env("BACKUP_REGION", "fsn1"), bucket: env("BACKUP_BUCKET", "jarvis2-backup-de0ch"), write: os.Getenv("BACKUP_WRITE_BUCKET"),
		accessKey: ak, secretKey: sk, http: &http.Client{Timeout: 60 * time.Second}, now: time.Now}
}

// s3enc: AWS's URI encoding (unreserved characters kept; "/" kept in a key path)
func s3enc(s string, slash bool) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' || slash && c == '/' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func hmacSHA(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// get: a SigV4-signed, path-style GET of /<bucket>/<key>?<query>
func (b *backupBucket) get(key string, query map[string]string) ([]byte, error) {
	return b.do("GET", key, query, nil)
}

// put: a new version of one object in the bucket the router writes (versioned: every earlier version stays)
func (b *backupBucket) put(key string, body []byte) error {
	_, err := b.writer().do("PUT", key, nil, body)
	return err
}

// writer: the bucket the router writes, as a client
func (b *backupBucket) writer() *backupBucket {
	if b.write == "" || b.write == b.bucket {
		return b
	}
	w := *b
	w.bucket, w.write = b.write, ""
	return &w
}

func (b *backupBucket) do(method, key string, query map[string]string, body []byte) ([]byte, error) {
	path := "/" + s3enc(b.bucket, false)
	if key != "" {
		path += "/" + s3enc(key, true)
	}
	ks := make([]string, 0, len(query))
	for k := range query {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	qs := make([]string, 0, len(ks))
	for _, k := range ks {
		qs = append(qs, s3enc(k, false)+"="+s3enc(query[k], false))
	}
	q := strings.Join(qs, "&")
	u, err := url.Parse(b.endpoint + path)
	if err != nil {
		return nil, err
	}
	u.RawQuery = q
	t := b.now().UTC()
	amz, day := t.Format("20060102T150405Z"), t.Format("20060102")
	sum := sha256.Sum256(body)
	payload := hex.EncodeToString(sum[:])
	signed := "host;x-amz-content-sha256;x-amz-date"
	canonical := strings.Join([]string{method, path, q, "host:" + u.Host + "\nx-amz-content-sha256:" + payload + "\nx-amz-date:" + amz + "\n", signed, payload}, "\n")
	scope := day + "/" + b.region + "/s3/aws4_request"
	ch := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + amz + "\n" + scope + "\n" + hex.EncodeToString(ch[:])
	k := hmacSHA([]byte("AWS4"+b.secretKey), day)
	for _, p := range []string{b.region, "s3", "aws4_request"} {
		k = hmacSHA(k, p)
	}
	req, _ := http.NewRequest(method, u.String(), bytes.NewReader(body))
	req.Header.Set("x-amz-content-sha256", payload)
	req.Header.Set("x-amz-date", amz)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+b.accessKey+"/"+scope+", SignedHeaders="+signed+", Signature="+hex.EncodeToString(hmacSHA(k, toSign)))
	resp, err := b.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		var e struct{ Code string }
		xml.Unmarshal(out, &e)
		if e.Code == "" {
			e.Code = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("the backup bucket refused %s %s: %s", method, path, e.Code)
	}
	return out, nil
}

// list: every key under prefix (all pages)
func (b *backupBucket) list(prefix string) ([]string, error) {
	var keys []string
	token := ""
	for {
		q := map[string]string{"list-type": "2", "prefix": prefix}
		if token != "" {
			q["continuation-token"] = token
		}
		body, err := b.get("", q)
		if err != nil {
			return nil, err
		}
		var l struct {
			Contents              []struct{ Key string }
			IsTruncated           bool
			NextContinuationToken string
		}
		if err := xml.Unmarshal(body, &l); err != nil {
			return nil, fmt.Errorf("the backup bucket's listing isn't readable: %v", err)
		}
		for _, c := range l.Contents {
			keys = append(keys, c.Key)
		}
		if !l.IsTruncated || l.NextContinuationToken == "" {
			return keys, nil
		}
		token = l.NextContinuationToken
	}
}

type backupObject struct {
	Key  string `json:"key"`
	Body string `json:"body"`
}

// all: the store backups and the sensitivity markers, as they are — the read bucket's, then the write bucket's over
// them (an object of the same name replaced)
func (b *backupBucket) all() ([]backupObject, error) {
	out, err := b.objects()
	if err != nil || b.writer() == b {
		return out, err
	}
	mine, err := b.writer().objects()
	if err != nil {
		return nil, err
	}
	at := map[string]int{}
	for i, o := range out {
		at[o.Key] = i
	}
	for _, o := range mine {
		if i, ok := at[o.Key]; ok {
			out[i] = o
		} else {
			out = append(out, o)
		}
	}
	return out, nil
}

// objects: one bucket's backup objects
func (b *backupBucket) objects() ([]backupObject, error) {
	out := []backupObject{}
	for _, prefix := range []string{"stores/", "keys/", "sensitive/"} {
		keys, err := b.list(prefix)
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			if !strings.HasSuffix(k, ".json") || isLineStateObject(k) { // linestate.go: the router's own object, no backup
				continue
			}
			body, err := b.get(k, nil)
			if err != nil {
				return nil, err
			}
			out = append(out, backupObject{Key: k, Body: string(body)})
		}
	}
	return out, nil
}

func (r *Router) registerBackups(app func(string, http.HandlerFunc)) {
	app("GET /api/backups", func(w http.ResponseWriter, req *http.Request) {
		b := backupBucketFromEnv()
		if b == nil {
			writeJSON(w, 503, map[string]string{"error": "the router has no read key for the backups (BACKUP_READ_ACCESS_KEY): the setup session installs it with infra/backup-read-key.py install (RUNBOOK, the router's secrets)"})
			return
		}
		objs, err := b.all()
		if err != nil {
			if f := r.backupFallback(); f != nil {
				log.Printf("GET /api/backups: the bucket failed (%v): serving the fallback export of %s", err, f.FetchedAt)
				writeJSON(w, 200, map[string]any{"bucket": f.Bucket, "objects": f.Objects,
					"fallback": map[string]string{"fetchedAt": f.FetchedAt, "reason": err.Error()}})
				return
			}
			log.Printf("GET /api/backups: %v", err)
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"bucket": b.bucket, "objects": objs})
	})
	// A fallback for when the bucket can't be read (2026-10-16: Hetzner's fsn1 Object Storage outage blocked a
	// Recover): an export the app saved earlier (Settings → Encrypted backup, format jarvis2-backup-export), served by
	// GET /api/backups only while the bucket fails. It adds no trust: the app checks every object's signature against
	// keys/setup.pub as it does for the bucket's, and the router could always serve an older version anyway.
	app("POST /api/backups/fallback", func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(req.Body, 16<<20))
		var f backupExport
		if err := json.Unmarshal(b, &f); err != nil {
			writeJSON(w, 400, map[string]string{"error": "not an export: " + err.Error()})
			return
		}
		if err := f.check(); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		// an export over an API call's body limit comes in parts: a part of the same export (same bucket and
		// fetchedAt) adds its objects to the kept ones (a key sent again replaces its object)
		if old := r.backupFallback(); old != nil && old.Bucket == f.Bucket && old.FetchedAt == f.FetchedAt {
			byKey := map[string]int{}
			for i, o := range old.Objects {
				byKey[o.Key] = i
			}
			for _, o := range f.Objects {
				if i, ok := byKey[o.Key]; ok {
					old.Objects[i] = o
				} else {
					old.Objects = append(old.Objects, o)
				}
			}
			f.Objects = old.Objects
		}
		b, _ = json.Marshal(f)
		if err := r.st.WriteDoc(backupFallbackFile, b); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		log.Printf("backups: a fallback export of %s is kept (%d objects)", f.FetchedAt, len(f.Objects))
		writeJSON(w, 200, map[string]any{"ok": true, "fetchedAt": f.FetchedAt, "objects": len(f.Objects)})
	})
	app("DELETE /api/backups/fallback", func(w http.ResponseWriter, req *http.Request) {
		r.st.DeleteDoc(backupFallbackFile)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
}

const backupFallbackFile = "backups-fallback.json"

// backupExport: the app's saved copy of the bucket (ios CoreSetup.exportFormat, tools/decrypt-backup.py)
type backupExport struct {
	Format    string         `json:"format"`
	Version   int            `json:"version"`
	Bucket    string         `json:"bucket"`
	FetchedAt string         `json:"fetchedAt"`
	Objects   []backupObject `json:"objects"`
}

func (f *backupExport) check() error {
	if f.Format != "jarvis2-backup-export" || f.Version != 1 {
		return fmt.Errorf("not a jarvis2-backup-export version 1 file")
	}
	if len(f.Objects) == 0 {
		return fmt.Errorf("the export holds no objects")
	}
	for _, o := range f.Objects {
		ok := false
		for _, p := range []string{"stores/", "keys/", "sensitive/"} {
			ok = ok || strings.HasPrefix(o.Key, p)
		}
		if !ok || !strings.HasSuffix(o.Key, ".json") || o.Body == "" {
			return fmt.Errorf("not a backup object: %q", o.Key)
		}
	}
	return nil
}

// backupFallback: the kept export, or nil
func (r *Router) backupFallback() *backupExport {
	b, ok := r.st.ReadDoc(backupFallbackFile)
	if !ok {
		return nil
	}
	var f backupExport
	if json.Unmarshal(b, &f) != nil || f.check() != nil {
		return nil
	}
	return &f
}
