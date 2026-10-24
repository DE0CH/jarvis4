package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/kerneltest"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

// kernelVersionsRouter: a box with no core whose serving secrets is the real kernel's (kerneltest), with the fake bucket
func kernelVersionsRouter(t *testing.T) (*Router, *kerneltest.Kernel, *fakeBucket) {
	t.Helper()
	r, _, fb := storeRouter(t)
	k := kerneltest.Start(t, nil)
	r.core = &CoreClient{base: "http://core.invalid:8090", http: http.DefaultClient}
	r.cfg.NoCore = true
	r.wireKernel(&KernelClient{url: func(role string) string {
		if role == "secrets-blue" {
			return k.URLFor("secrets")
		}
		return k.URLFor(role)
	}, http: http.DefaultClient, ids: map[string]sig.Identity{}})
	return r, k, fb
}

func kwBody(data, be string) string {
	b, _ := json.Marshal(map[string]any{"wrapped": map[string]string{"e": "E" + data, "wrapped": "W"}, "data": data,
		"backup": map[string]string{"e": be, "data": "BD"}, "backupSha256": backupSha(be, "BD"), "sig": "S" + data, "explanation": "a key"})
	return string(b)
}

func hexSha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// the kernel's secrets keeps no history (DECISIONS 230): the router keeps each version with secrets' receipts, and a
// restore writes the earlier entry back with its receipt (writer "replay"), its backup back into the bucket first, and
// deletes the keys the earlier version didn't have; secrets keeps the writer the receipt names
func TestAKernelRestoreReplaysTheEarlierEntry(t *testing.T) {
	r, k, fb := kernelVersionsRouter(t)
	addSession(r, "sA", "started", "mA", false)
	r.st.Do(func(d *persisted) { d.Sessions["sA"].Stores = []string{"default"} })
	var v1Backup []byte // A's backup at version 1, overwritten since: the router kept it
	for i, w := range []struct{ key, data, be string }{{"A", "D1", "BE1"}, {"A", "D2", "BE2"}, {"B", "D3", "BE3"}} {
		if code, out := appDo(t, r, "POST", "/setup/stores/default/keys/"+w.key, kwBody(w.data, w.be)); code != 200 {
			t.Fatalf("write %s: %d %v", w.key, code, out)
		}
		if i == 0 {
			v1Backup = append([]byte(nil), fb.objs["keys/default/A.json"]...)
		}
	}
	code, out := appDo(t, r, "POST", "/api/core/stores/versions", `{"store":"default","nonce":"n1"}`)
	vs, _ := out["versions"].([]any)
	if code != 200 || out["kind"] != "store-versions" || out["nonce"] != "n1" || len(vs) != 3 {
		t.Fatalf("versions: %d %v", code, out)
	}
	oldest := vs[2].(map[string]any)
	keys := oldest["keys"].([]any)
	row := keys[0].(map[string]any)
	if oldest["seq"] != float64(1) || len(keys) != 1 || row["name"] != "A" || row["dataSha256"] != hexSha("D1") || row["receipt"] == nil {
		t.Fatalf("version 1: %v", oldest)
	}
	// the receipt is secrets' own signature
	var rc Doc
	rb, _ := json.Marshal(row["receipt"])
	json.Unmarshal(rb, &rc)
	if !sig.Verify(k.Identity("secrets").SigningKey, []byte(rc.Payload), rc.Sig) {
		t.Fatal("the receipt isn't secrets'")
	}
	code, out = appDo(t, r, "POST", "/api/core/stores/restore/begin", `{"store":"default","seq":1}`)
	put, _ := out["put"].([]any)
	if code != 200 || out["replay"] != true || len(put) != 1 || put[0].(map[string]any)["key"] != "A" || len(out["remove"].([]any)) != 1 {
		t.Fatalf("begin: %d %v", code, out)
	}
	code, out = appDo(t, r, "POST", "/api/stores/restore/finish", `{"pending":"`+out["pending"].(string)+`"}`)
	done, _ := out["restored"].(map[string]any)
	if code != 200 || done["kind"] != "store-restored" || done["from"] != float64(1) || done["seq"] != float64(4) {
		t.Fatalf("finish: %d %v", code, out)
	}
	// secrets holds version 1's entry, with its writer; B is gone
	ub, err := k.Secrets.UnlockBegin("default")
	if err != nil {
		t.Fatal(err)
	}
	var u struct {
		Keys []struct {
			Key        string `json:"key"`
			DataSha256 string `json:"dataSha256"`
			Writer     struct{ By, Sig string }
		} `json:"keys"`
	}
	json.Unmarshal([]byte(ub.Payload), &u)
	if len(u.Keys) != 1 || u.Keys[0].Key != "A" || u.Keys[0].DataSha256 != hexSha("D1") || u.Keys[0].Writer.By != "setup" || u.Keys[0].Writer.Sig != "SD1" {
		t.Fatalf("secrets after the restore: %+v", u.Keys)
	}
	// the bucket: version 1's backup of A back; B keeps its last backup (no delete marker the app's Recover would refuse)
	var a1, aNow map[string]any // the same object (Postgres's jsonb keeps it, not its bytes)
	json.Unmarshal(v1Backup, &a1)
	json.Unmarshal(fb.objs["keys/default/A.json"], &aNow)
	if aNow["dataSha256"] != hexSha("D1") || aNow["backupSha256"] != a1["backupSha256"] || aNow["at"] != a1["at"] {
		t.Fatalf("A's backup isn't version 1's: %v", aNow)
	}
	var bobj map[string]any
	json.Unmarshal(fb.objs["keys/default/B.json"], &bobj)
	if bobj["deleted"] != false || bobj["dataSha256"] != hexSha("D3") {
		t.Fatalf("B's backup: %v", bobj)
	}
	if asked, _ := out["refreshAsked"].([]any); len(asked) != 1 {
		t.Fatalf("refresh %v", out["refreshAsked"])
	}
	// a pending is used once; a version already current is refused
	if code, _ := appDo(t, r, "POST", "/api/stores/restore/finish", `{"pending":"`+done["pending"].(string)+`"}`); code != 404 {
		t.Fatalf("a pending twice: %d", code)
	}
	if code, _ := appDo(t, r, "POST", "/api/core/stores/restore/begin", `{"store":"default","seq":4}`); code != 409 {
		t.Fatalf("the current version: %d", code)
	}
	// the setup session reads the same list
	if code, out := appDo(t, r, "POST", "/setup/stores/versions", `{"store":"default","nonce":"n2"}`); code != 200 || len(out["versions"].([]any)) != 4 {
		t.Fatalf("setup versions: %d %v", code, out)
	}
}
