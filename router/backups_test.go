package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// a bucket stand-in: two pages of stores/, one key backup, one marker, and a check that every request is SigV4-signed
func TestBackupsServedAsTheyAreInTheBucket(t *testing.T) {
	objs := map[string]string{"stores/a.json": `{"doc":"a","sig":"x"}`, "stores/b.json": `{"doc":"b","sig":"y"}`, "sensitive/b.json": `{"doc":"m","sig":"z"}`, "stores/README": "no",
		"keys/a/K.json": `{"kind":"key-backup"}`}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if a := req.Header.Get("Authorization"); !strings.HasPrefix(a, "AWS4-HMAC-SHA256 Credential=ak/") || req.Header.Get("x-amz-date") == "" {
			w.WriteHeader(403)
			fmt.Fprint(w, "<Error><Code>AccessDenied</Code></Error>")
			return
		}
		if req.URL.Path == "/bkt" {
			q := req.URL.Query()
			p := q.Get("prefix")
			switch {
			case p == "stores/" && q.Get("continuation-token") == "":
				fmt.Fprint(w, `<ListBucketResult><Contents><Key>stores/a.json</Key></Contents><Contents><Key>stores/README</Key></Contents><IsTruncated>true</IsTruncated><NextContinuationToken>t2</NextContinuationToken></ListBucketResult>`)
			case p == "stores/":
				fmt.Fprint(w, `<ListBucketResult><Contents><Key>stores/b.json</Key></Contents><IsTruncated>false</IsTruncated></ListBucketResult>`)
			case p == "keys/":
				fmt.Fprint(w, `<ListBucketResult><Contents><Key>keys/a/K.json</Key></Contents><IsTruncated>false</IsTruncated></ListBucketResult>`)
			default:
				fmt.Fprint(w, `<ListBucketResult><Contents><Key>sensitive/b.json</Key></Contents><IsTruncated>false</IsTruncated></ListBucketResult>`)
			}
			return
		}
		body, ok := objs[strings.TrimPrefix(req.URL.Path, "/bkt/")]
		if !ok {
			w.WriteHeader(404)
			return
		}
		fmt.Fprint(w, body)
	}))
	defer s.Close()
	r := newTestRouter(t)
	h := r.Handler()
	get := func() (int, map[string]any) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/backups", nil))
		var m map[string]any
		json.Unmarshal(rec.Body.Bytes(), &m)
		return rec.Code, m
	}
	if code, _ := get(); code != 503 {
		t.Fatalf("no credential: got %d", code)
	}
	for k, v := range map[string]string{"BACKUP_READ_ACCESS_KEY": "ak", "BACKUP_READ_SECRET_KEY": "sk", "BACKUP_ENDPOINT": s.URL, "BACKUP_BUCKET": "bkt"} {
		t.Setenv(k, v)
	}
	code, m := get()
	if code != 200 {
		t.Fatalf("got %d %v", code, m)
	}
	got := []string{}
	for _, o := range m["objects"].([]any) {
		ob := o.(map[string]any)
		if ob["body"] != objs[ob["key"].(string)] {
			t.Fatalf("%v changed on the way", ob["key"])
		}
		got = append(got, ob["key"].(string))
	}
	if strings.Join(got, ",") != "stores/a.json,stores/b.json,keys/a/K.json,sensitive/b.json" {
		t.Fatalf("got %v", got)
	}
	t.Setenv("BACKUP_READ_ACCESS_KEY", "wrong")
	if code, m := get(); code != 502 || !strings.Contains(fmt.Sprint(m["error"]), "AccessDenied") {
		t.Fatalf("a refused read: got %d %v", code, m)
	}
}

// the real bucket, read-only (a list), when this session has the admin key: SigV4 against Hetzner itself
func TestBackupsSignatureOnHetzner(t *testing.T) {
	ak, sk := os.Getenv("HETZNER_S3_ACCESS_KEY"), os.Getenv("HETZNER_S3_SECRET_KEY")
	if ak == "" || os.Getenv("JARVIS2_LIVE_S3") != "1" {
		t.Skip("JARVIS2_LIVE_S3=1 with HETZNER_S3_* only")
	}
	t.Setenv("BACKUP_READ_ACCESS_KEY", ak)
	t.Setenv("BACKUP_READ_SECRET_KEY", sk)
	b := backupBucketFromEnv()
	objs, err := b.all()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d backup objects readable", len(objs))
}

// 2026-10-16: the bucket's store (Hetzner fsn1) was down during a Recover; an export the app saved earlier is served
// instead, only while the bucket fails, and marked as such
func TestBackupsFallbackWhileTheBucketFails(t *testing.T) {
	down := true
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if down {
			w.WriteHeader(503)
			fmt.Fprint(w, "<Error><Code>ServiceUnavailable</Code></Error>")
			return
		}
		fmt.Fprint(w, `<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>`)
	}))
	defer s.Close()
	for k, v := range map[string]string{"BACKUP_READ_ACCESS_KEY": "ak", "BACKUP_READ_SECRET_KEY": "sk", "BACKUP_ENDPOINT": s.URL, "BACKUP_BUCKET": "bkt"} {
		t.Setenv(k, v)
	}
	r := newTestRouter(t)
	h := r.Handler()
	do := func(method, path, body string) (int, map[string]any) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		var m map[string]any
		json.Unmarshal(rec.Body.Bytes(), &m)
		return rec.Code, m
	}
	if code, m := do("GET", "/api/backups", ""); code != 502 || !strings.Contains(fmt.Sprint(m["error"]), "ServiceUnavailable") {
		t.Fatalf("no fallback: got %d %v", code, m)
	}
	for _, bad := range []string{`{}`, `{"format":"jarvis2-backup-export","version":1,"objects":[]}`,
		`{"format":"jarvis2-backup-export","version":1,"objects":[{"key":"etc/passwd.json","body":"x"}]}`} {
		if code, _ := do("POST", "/api/backups/fallback", bad); code != 400 {
			t.Fatalf("%s: got %d", bad, code)
		}
	}
	exp := `{"format":"jarvis2-backup-export","version":1,"bucket":"bkt","fetchedAt":"2026-10-14T03:19:04Z","setupKey":"k","objects":[{"key":"stores/a.json","body":"{\"doc\":\"a\",\"sig\":\"x\"}"}]}`
	if code, m := do("POST", "/api/backups/fallback", exp); code != 200 || m["objects"] != float64(1) {
		t.Fatalf("keep: got %d %v", code, m)
	}
	part2 := `{"format":"jarvis2-backup-export","version":1,"bucket":"bkt","fetchedAt":"2026-10-14T03:19:04Z","objects":[{"key":"stores/b.json","body":"{\"doc\":\"b\",\"sig\":\"y\"}"}]}`
	if code, m := do("POST", "/api/backups/fallback", part2); code != 200 || m["objects"] != float64(2) {
		t.Fatalf("second part: got %d %v", code, m)
	}
	code, m := do("GET", "/api/backups", "")
	if code != 200 || m["fallback"].(map[string]any)["fetchedAt"] != "2026-10-14T03:19:04Z" || len(m["objects"].([]any)) != 2 {
		t.Fatalf("fallback: got %d %v", code, m)
	}
	if o := m["objects"].([]any)[0].(map[string]any); o["key"] != "stores/a.json" || o["body"] != `{"doc":"a","sig":"x"}` {
		t.Fatalf("changed on the way: %v", o)
	}
	down = false // the bucket answers again: it wins over the fallback
	if code, m := do("GET", "/api/backups", ""); code != 200 || m["fallback"] != nil {
		t.Fatalf("bucket back: got %d %v", code, m)
	}
	down = true
	if code, _ := do("DELETE", "/api/backups/fallback", ""); code != 200 {
		t.Fatal("delete")
	}
	if code, _ := do("GET", "/api/backups", ""); code != 502 {
		t.Fatalf("after delete: got %d", code)
	}
}

// with a write bucket (Jarvis 4) the router writes there only, and serves both buckets: the write bucket's object over
// the read bucket's of the same name
func TestBackupsWriteBucketOverTheReadBucket(t *testing.T) {
	buckets := map[string]map[string]string{
		"j2": {"stores/a.json": "A2", "keys/a/K.json": "K2"},
		"j4": {"keys/a/K.json": "K4", "keys/b/L.json": "L4"},
	}
	puts := []string{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		parts := strings.SplitN(strings.TrimPrefix(req.URL.Path, "/"), "/", 2)
		objs := buckets[parts[0]]
		if req.Method == "PUT" {
			if parts[0] == "j2" {
				w.WriteHeader(403)
				fmt.Fprint(w, "<Error><Code>AccessDenied</Code></Error>")
				return
			}
			puts = append(puts, req.URL.Path)
			return
		}
		if len(parts) == 1 {
			fmt.Fprint(w, "<ListBucketResult>")
			for k := range objs {
				if strings.HasPrefix(k, req.URL.Query().Get("prefix")) {
					fmt.Fprintf(w, "<Contents><Key>%s</Key></Contents>", k)
				}
			}
			fmt.Fprint(w, "<IsTruncated>false</IsTruncated></ListBucketResult>")
			return
		}
		fmt.Fprint(w, objs[parts[1]])
	}))
	defer s.Close()
	for k, v := range map[string]string{"BACKUP_READ_ACCESS_KEY": "ak", "BACKUP_READ_SECRET_KEY": "sk", "BACKUP_ENDPOINT": s.URL, "BACKUP_BUCKET": "j2", "BACKUP_WRITE_BUCKET": "j4"} {
		t.Setenv(k, v)
	}
	b := backupBucketFromEnv()
	if err := b.put("keys/c/M.json", []byte("M4")); err != nil || len(puts) != 1 || puts[0] != "/j4/keys/c/M.json" {
		t.Fatalf("the write went to %v (%v)", puts, err)
	}
	objs, err := b.all()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, o := range objs {
		got[o.Key] = o.Body
	}
	if len(got) != 3 || got["stores/a.json"] != "A2" || got["keys/a/K.json"] != "K4" || got["keys/b/L.json"] != "L4" {
		t.Fatalf("served %v", got)
	}
}
