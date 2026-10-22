// e2e: drives a real Jarvis 4 (core + router + Fly machines running the session image) through every
// flow with a SOFTWARE phone standing in for the iPhone. It sets the core up (a Recover with test stores),
// which an empty core accepts once — so run it against a fresh core of its own, never the production one.
//
//	E2E_ROUTER=http://127.0.0.1:28080 E2E_CORE=http://127.0.0.1:28090 E2E_MASTER_KEY_FILE=testdata/master-test.pem E2E_BOX_PUB=… \
//	E2E_FLY_TOKEN=… go run .
//
// It plays the iPhone, the Recover included, with the public TEST master key (e2e/testdata): run a core
// (BOX_KEY_FILE = a throwaway box key) and a router (NO_ACCESS=1, WG_CONFIG = a WireGuard peer of the Fly org,
// the session image) locally, so the machines reach this router over Fly's private network as in production.
// infra/e2e.sh does all that.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/DE0CH/jarvis4/e2e/routerdb"
)

var b64 = base64.StdEncoding

type Doc struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

type phone struct {
	sig *ecdsa.PrivateKey
	agr *ecdh.PrivateKey
}

func (p *phone) signingKey() string {
	k, _ := p.sig.PublicKey.ECDH()
	return b64.EncodeToString(k.Bytes())
}

func (p *phone) sign(payload string) string {
	h := sha256.Sum256([]byte(payload))
	s, _ := ecdsa.SignASN1(rand.Reader, p.sig, h[:])
	return b64.EncodeToString(s)
}

var router, core string
var coreKey string

func call(base, method, path string, in any, out any, hdr ...string) (int, []byte) {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, base+path, body)
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode == 200 {
		json.Unmarshal(b, out)
	}
	return resp.StatusCode, b
}

func must(status int, b []byte, what string) {
	if status != 200 {
		log.Fatalf("%s: HTTP %d %s", what, status, string(b))
	}
}

func verify(d Doc, out any) {
	kb, _ := b64.DecodeString(coreKey)
	pk, err := ecdh.P256().NewPublicKey(kb)
	if err != nil {
		log.Fatal(err)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), pk.Bytes())
	sig, _ := b64.DecodeString(d.Sig)
	h := sha256.Sum256([]byte(d.Payload))
	if !ecdsa.VerifyASN1(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, h[:], sig) {
		log.Fatalf("a document isn't signed by the core: %.120s", d.Payload)
	}
	if out != nil {
		json.Unmarshal([]byte(d.Payload), out)
	}
}

func step(f string, a ...any) { log.Printf("== "+f, a...) }

func main() {
	log.SetFlags(log.Ltime)
	router, core = os.Getenv("E2E_ROUTER"), os.Getenv("E2E_CORE")
	pemb, err := os.ReadFile(os.Getenv("E2E_MASTER_KEY_FILE"))
	if err != nil {
		log.Fatal(err)
	}
	master := parseKey(pemb)
	serveStandIns()        // nojarvis1.go: search, the watch runner and the Storage Box, stood in for
	go blackholeMachines() // nojarvis1.go: Jarvis 1 out of every session machine's reach
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ak, _ := ecdh.P256().GenerateKey(rand.Reader)
	p := &phone{sk, ak}

	step("the core's identity, checked against the box key; it is empty")
	var id0 struct {
		SigningKey   string `json:"signingKey"`
		AgreementKey string `json:"agreementKey"`
		BoxSig       string `json:"boxSig"`
		State        Doc    `json:"state"`
		Bundle       string `json:"bundle"` // "keys": stores made of keys (core/keys.go)
	}
	must2(call(router, "GET", "/api/core/identity", nil, &id0))
	if !verifyRaw(os.Getenv("E2E_BOX_PUB"), "jarvis2-core-identity "+id0.SigningKey+" "+id0.AgreementKey, id0.BoxSig) {
		log.Fatal("the core's identity isn't signed by the box key")
	}
	coreKey = id0.SigningKey
	var state struct{ Kind, Master string }
	verify(id0.State, &state)
	if state.Kind != "core-state" || state.Master != "" {
		log.Fatalf("not an empty core: %+v", state)
	}
	if id0.Bundle != "keys" {
		log.Fatalf("the core doesn't take stores of keys (bundle %q)", id0.Bundle)
	}

	step("Recover: the master key sets the core up, naming the core and the phone; every store comes in, wrapped by the app")
	phoneAgreement := b64.EncodeToString(ak.PublicKey().Bytes())
	var skd Doc
	var skey struct{ Kind, Phone, StoreKey string }
	must2(call(router, "POST", "/api/core/store-key", map[string]string{"phone": phoneAgreement}, &skd))
	verify(skd, &skey)
	if skey.Kind != "store-key" || skey.Phone != phoneAgreement {
		log.Fatalf("not this phone's store key: %+v", skey)
	}
	secret := hex.EncodeToString(randBytes(8))
	recovered := map[string]map[string]string{
		"e2e":       {"E2E_SECRET": secret},
		"e2e-extra": {"E2E_EXTRA": "extra-" + secret},
		"e2e-more":  {"E2E_MORE": "more-" + secret},
		// the Claude login store: no keys, a cert naming it is what gets the router's (fake, seeded below) pair
		"claude": {},
	}
	continuity := os.Getenv("E2E_ONLY") == "continuity"
	var bundle []byte
	if continuity { // continuity.go: the claim with the master key's seed
		seededClaim(master, p, phoneAgreement, recovered, nil)
	} else { // every store's name and every key, each wrapped on its own (core claimBundle)
		names, keys := []string{}, []map[string]any{}
		for _, n := range []string{"claude", "e2e", "e2e-extra", "e2e-more"} {
			names = append(names, n)
			for k, v := range recovered[n] {
				keys = append(keys, wrapKey(skey.StoreKey, n, k, v))
			}
		}
		bundle, _ = json.Marshal(map[string]any{"format": "keys", "stores": names, "keys": keys,
			"flyToken": coreFlyToken(), "notSensitive": []string{"e2e", "claude"}})
	}
	if !continuity {
		sum := sha256.Sum256(bundle)
		mpub, _ := master.PublicKey.ECDH()
		stmt, _ := json.Marshal(map[string]any{"kind": "claim", "master": b64.EncodeToString(mpub.Bytes()),
			"core":         map[string]string{"signingKey": id0.SigningKey, "agreementKey": id0.AgreementKey},
			"phone":        map[string]string{"signingKey": p.signingKey(), "agreementKey": phoneAgreement},
			"bundleSha256": hex.EncodeToString(sum[:])})
		h := sha256.Sum256(stmt)
		msig, _ := ecdsa.SignASN1(rand.Reader, master, h[:])
		var rec Doc
		must2(call(router, "POST", "/api/core/claim", map[string]any{"statement": string(stmt), "masterSig": b64.EncodeToString(msig),
			"bundle": sealTo(id0.AgreementKey, bundle, "jarvis2/claim")}, &rec))
		verify(rec, nil)
		if s, _ := call(router, "POST", "/api/core/claim", map[string]any{"statement": string(stmt), "masterSig": b64.EncodeToString(msig),
			"bundle": sealTo(id0.AgreementKey, bundle, "jarvis2/claim")}, nil); s == 200 {
			log.Fatal("a set-up core was claimed again")
		}
	}

	claudeAccountStep()

	step("stores: e2e not sensitive, e2e-extra sensitive; a created store is not; the upgrade is one-way")
	stores := func() map[string]bool {
		var d Doc
		must2(call(router, "POST", "/api/core/stores", map[string]string{"nonce": "n"}, &d))
		var l struct {
			Stores []struct {
				Name      string
				Sensitive bool
			}
		}
		verify(d, &l)
		m := map[string]bool{}
		for _, x := range l.Stores {
			m[x.Name] = x.Sensitive
		}
		return m
	}
	must2(call(router, "POST", "/api/core/stores/create", map[string]string{"name": "e2e-notes"}, nil))
	if st := stores(); st["e2e"] || !st["e2e-extra"] || st["e2e-notes"] {
		log.Fatalf("sensitivity: %v", st)
	}
	if _, ok := stores()["core"]; ok {
		log.Fatal("the Fly store is a session store")
	}
	must2(call(router, "POST", "/api/core/stores/mark-sensitive", map[string]string{"name": "e2e-notes"}, nil))
	if s, _ := call(router, "POST", "/api/core/stores/create", map[string]string{"name": "e2e-notes"}, nil); s == 200 {
		log.Fatal("re-created a sensitive store")
	}

	step("a standing unlock (the Stores page): open to every session, until locked")
	unlock(p, "e2e-extra", "")
	if !storeOpen("e2e-extra") {
		log.Fatal("a standing unlock doesn't show as unlocked")
	}
	lockAll()
	if storeOpen("e2e-extra") {
		log.Fatal("still unlocked after lock")
	}

	if os.Getenv("E2E_ONLY") == "restore" { // the restore of a store alone, on a core set up as above (no machines)
		restoreStep(p, master, skey.StoreKey)
		expectNoUnlocks("at the end")
		log.Printf("E2E PASSED (the restore of a store only)")
		return
	}
	if os.Getenv("E2E_ONLY") == "jarvis1-import" { // the import alone, on a core set up as above
		jarvis1ImportStep(p)
		expectNoUnlocks("at the end")
		log.Printf("E2E PASSED (the Jarvis 1 import only)")
		return
	}

	step("new session (stores [e2e]): Start unlocks e2e for this session only; locked again once the machine pulled")
	newBody := map[string]any{"label": "e2e test", "stores": []string{"e2e"}, "size": "small", "harness": "claude"}
	if os.Getenv("E2E_ONLY") != "drain" && os.Getenv("E2E_ONLY") != "move" && !continuity {
		contentSetupStep(secret) // nojarvis1.go
		newBody["content"] = []string{"e2e-content"}
	}
	s, b := call(router, "POST", "/api/sessions", newBody, nil)
	must(s, b, "create")
	a := waitApproval("new-session", "")
	checkChallenge(a, []string{"e2e"}, "")
	unlock(p, "e2e", nonceOf(*a.Challenge))
	if storeOpen("e2e") {
		log.Fatal("an unlock for one session shows as open to every session")
	}
	id := approve(p, a)
	waitState(id, "started", 6*time.Minute)
	m1 := machineOf(id)
	expectOnMachine(m1, "session-secret --names | grep -cx E2E_SECRET", "1")
	// the secrets are in the supervisor's RAM only: no ~/.secrets, no private key under ~/.ssh or /run/jarvis2
	expectOnMachine(m1, "test -e /home/claude/.secrets && echo present || echo absent; grep -rl 'PRIVATE KEY' /home/claude/.ssh /run/jarvis2 2>/dev/null | wc -l", "absent\n0")
	expectNoUnlocks("after the Start's pull")
	if continuity {
		continuityStep(p, master, phoneAgreement, recovered, id, m1, secret)
		return
	}
	if os.Getenv("E2E_ONLY") == "move" { // move.go: the router moves to another box under a running session
		moveStep(id, m1)
		return
	}
	expectOnMachine(m1, "echo marker-"+secret+" > /home/claude/artifacts/e2e-marker && chown claude /home/claude/artifacts/e2e-marker && echo ok", "ok")
	// the OpenCode/Paseo and OpenClaw harnesses' state travels in the snapshot too (their pairings), their pid files don't
	expectOnMachine(m1, "cd /home/claude && mkdir -p .paseo .openclaw/devices .local/share/opencode/storage && echo paseo > .paseo/e2e-state && "+
		"echo openclaw > .openclaw/devices/e2e-state && echo opencode > .local/share/opencode/storage/e2e-state && echo 1 > .openclaw/gateway.pid && "+
		"chown -R claude .paseo .openclaw .local && echo ok", "ok")

	if os.Getenv("E2E_ONLY") == "drain" {
		drainStep(id)
		return
	}

	servicesStep(id, m1, secret) // nojarvis1.go

	step("grants: no shell without one; a phone grant opens it; the session's own allow list too")
	s, b = call(router, "POST", "/api/sessions/"+id+"/exec", map[string]any{"cmd": "echo hi"}, nil)
	if s == 200 {
		log.Fatalf("a shell without any grant: %s", b)
	}
	var draft struct{ Text string }
	must2(call(router, "POST", "/api/sessions/"+id+"/grants/draft", map[string]any{"holder": "terminal", "kind": "grant", "minutes": 10}, &draft))
	var grant struct{ ID string }
	must2(call(router, "POST", "/api/sessions/"+id+"/grants", map[string]string{"payload": draft.Text, "sig": p.sign(draft.Text)}, &grant))
	expectExec(id, "echo hi from $(whoami)", "hi from claude")
	must2(call(router, "DELETE", "/api/grants/"+grant.ID, nil, nil))
	expectOnMachine(m1, "su - claude -c 'jarvis2 allow terminal 1h' && echo ok", "ok")
	expectExec(id, "echo allowed", "allowed")
	expectOnMachine(m1, "su - claude -c 'jarvis2 allow --remove terminal' && echo ok", "ok")
	must2(call(router, "POST", "/api/sessions/"+id+"/grants/draft", map[string]any{"holder": "terminal", "kind": "rule", "until": time.Now().Add(24 * time.Hour)}, &draft))
	must2(call(router, "POST", "/api/sessions/"+id+"/grants", map[string]string{"payload": draft.Text, "sig": p.sign(draft.Text)}, &grant))

	step("inputs: the machine's Fly config carries only what the core set; the harness's env has nothing the router chose on its own")
	if env := flyMachineEnv(m1); len(env) != 2 || env["JARVIS2_CORE_KEY"] == "" || env["JARVIS2_URL"] == "" {
		log.Fatalf("the machine's Fly config env is %v, want only JARVIS2_CORE_KEY and JARVIS2_URL", env)
	}
	if u := flyMachineEnv(m1)["JARVIS2_URL"]; strings.Contains(u, "jarvis2-box") {
		log.Fatalf("an e2e machine points at production's router (%s)", u)
	}
	expectOnMachine(m1, "tr '\\0' '\\n' < /proc/$(pgrep -f harness-claude | head -1)/environ | grep -cE '^(JARVIS2_REPOS|SESSION_RESUME_TITLE|JARVIS2_ROLLBACK|JARVIS2_RESTORE_CERT|SESSION_REPOS)=' || true", "0")

	step("status: the machine reports itself; the session's local Jarvis API arms a wakeup (delivered later as its own signed request: no scheduler shell)")
	for i := 0; ; i++ {
		if lr, _ := session(id)["lastReport"].(string); lr != "" && !strings.HasPrefix(lr, "0001") {
			break
		}
		if i > 45 {
			log.Fatal("no status report from the machine in 90 s")
		}
		time.Sleep(2 * time.Second)
	}
	expectOnMachine(m1, "su - claude -c \"curl -s -X POST -H 'Content-Type: application/json' -d '{\\\"prompt\\\":\\\"e2e wake\\\",\\\"delaySeconds\\\":3600,\\\"name\\\":\\\"e2e\\\"}' http://127.0.0.1:7171/api/sessions/"+id+"/wakeups\" | grep -c '\"ok\":true'", "1")
	expectOnMachine(m1, "su - claude -c 'jarvis2 allow' | grep -c '\"scheduler\"' || true", "0")
	expectOnMachine(m1, "su - claude -c 'curl -s -o /dev/null -w %{http_code} http://127.0.0.1:7171/api/sessions/s0000000000000000/wakeups'", "403")
	var wk struct{ Wakeups []map[string]any }
	must2(call(router, "GET", "/api/sessions/"+id+"/wakeups", nil, &wk))
	if len(wk.Wakeups) != 1 || wk.Wakeups[0]["name"] != "e2e" {
		log.Fatalf("the router doesn't list the wakeup: %v", wk.Wakeups)
	}
	must2(call(router, "DELETE", "/api/sessions/"+id+"/wakeups/e2e", nil, nil))

	step("live transcript sync: the machine sends a changed conversation to the router (no Storage Box in the test: received, not stored)")
	tname := "0e2e0000-1111-4222-8333-" + secret[:12] + ".jsonl"
	expectOnMachine(m1, "mkdir -p /home/claude/.claude/projects/-e2e && echo '{\"type\":\"user\",\"message\":{\"content\":\"e2e live\"}}' > /home/claude/.claude/projects/-e2e/"+tname+
		" && chown -R claude /home/claude/.claude/projects && echo ok", "ok")
	waitLiveSync(id, tname, 3*time.Minute)

	keeperStep(id, m1) // keeper.go: the keeper and the uid split; the harness killed and started again

	step("store key names: the core's, listed to the session for every store (not only its own)")
	expectOnMachine(m1, "su - claude -c 'jarvis2 stores' | grep -c '^e2e-extra \\[sensitive, locked\\]: E2E_EXTRA$'", "1")
	expectOnMachine(m1, "su - claude -c 'jarvis2 stores' | grep -c '^e2e \\[in this session, locked\\]: E2E_SECRET$'", "1")

	step("two add-stores pending at once (e2e-extra, e2e-more), each unlocked for its own add-store only, answered in the order " +
		"they weren't filed: the session ends with both (2026-10-13: the second answer used to drop the first store); e2e comes from the carried secrets")
	go flyExec(m1, []string{"su", "-", "claude", "-c", "jarvis2 add-store e2e-extra"})
	go flyExec(m1, []string{"su", "-", "claude", "-c", "jarvis2 add-store e2e-more"})
	pending := waitApprovals("add-store", id, 2)
	byStore := map[string]approval{}
	for _, a := range pending {
		var ch struct{ Request struct{ AddedStore string } }
		verify(*a.Challenge, &ch)
		byStore[ch.Request.AddedStore] = a
	}
	checkChallenge(byStore["e2e-extra"], []string{"e2e", "e2e-extra"}, "e2e-extra")
	checkChallenge(byStore["e2e-more"], []string{"e2e", "e2e-more"}, "e2e-more")
	for _, n := range []string{"e2e-more", "e2e-extra"} {
		unlock(p, n, nonceOf(*byStore[n].Challenge))
	}
	approve(p, byStore["e2e-more"])
	approve(p, byStore["e2e-extra"]) // its challenge continues the cert the first answer replaced
	if st, _ := session(id)["stores"].([]any); fmt.Sprint(st) != "[e2e e2e-extra e2e-more]" {
		log.Fatalf("the session's stores after both answers: %v", st)
	}
	expectOnMachine(m1, "for i in $(seq 1 30); do session-secret --names | grep -qx E2E_EXTRA && session-secret --names | grep -qx E2E_MORE && break; sleep 2; done; "+
		"sleep 6; session-secret --names | grep -cx E2E_EXTRA; session-secret --names | grep -cx E2E_MORE; session-secret --names | grep -cx E2E_SECRET", "1\n1\n1")
	expectNoUnlocks("after the add-stores' pulls")

	step("a session writes one key into a store it doesn't hold, with no approval: backed up first (the bucket stand-in), " +
		"the explanation listed, the phone shown which session wrote it; nobody holds the store, so no refresh is asked")
	expectOnMachine(m1, "su - claude -c \"printf note-"+secret+" | jarvis2 put-key e2e-notes E2E_NOTE --explain 'the e2e note'\" 2>&1 | grep -c 'E2E_NOTE written in e2e-notes'", "1")
	if _, err := os.Stat(filepath.Join(os.Getenv("E2E_S3_DIR"), "keys", "e2e-notes", "E2E_NOTE.json")); err != nil {
		log.Fatalf("no backup of the written key in the bucket: %v", err)
	}
	expectOnMachine(m1, "su - claude -c 'jarvis2 stores --keys' | grep -c '^  E2E_NOTE: the e2e note \\[written by session '", "1")
	unlock(p, "e2e-notes", "")
	if lastUnlockWriters["e2e-notes/E2E_NOTE"] != "machine "+m1 {
		log.Fatalf("the phone isn't shown the session's machine as the writer: %v", lastUnlockWriters)
	}
	lockAll()
	if q := waitRequestFor(id, 5*time.Second); q != "" {
		log.Fatalf("a refresh was asked for a store the session doesn't hold: %s", q)
	}

	step("a key written into a store the session holds: its copy stays as it was until the phone's refresh, which the router " +
		"asks for at once; once allowed (an unlock for its cert) the machine pulls by itself, and the other keys are untouched")
	expectOnMachine(m1, "su - claude -c \"printf more2-"+secret+" | jarvis2 put-key e2e-more E2E_MORE --explain 'the e2e more key'\" >/dev/null 2>&1; "+
		"session-secret --keys E2E_MORE --exec env 2>/dev/null | grep -c more2- || true", "0")
	if q := waitRequestFor(id, 30*time.Second); q == "" {
		log.Fatal("no refresh asked for the session that holds the written store")
	}
	cert := sessionCert(id)
	for _, n := range certStores(cert) {
		unlock(p, n, nonceOf(cert))
	}
	expectOnMachine(m1, "for i in $(seq 1 30); do session-secret --keys E2E_MORE --exec env 2>/dev/null | grep -q more2- && break; sleep 2; done; "+
		"session-secret --keys E2E_MORE --exec env 2>/dev/null | grep -c more2-; session-secret --names | grep -cx E2E_EXTRA; session-secret --names | grep -cx E2E_SECRET", "1\n1\n1")
	expectNoUnlocks("after the refresh's pull")
	denyRequestsFor(id) // the harness unlocked as the app would; the request itself is done with

	step("delete a key: gone from the core's list")
	expectOnMachine(m1, "su - claude -c 'jarvis2 delete-key e2e-notes E2E_NOTE' >/dev/null 2>&1; su - claude -c 'jarvis2 stores' | grep -c '^e2e-notes \\[.*\\]: $'", "1")

	step("downgrade in place: back to [e2e], new keys, the extra secret shredded")
	expectOnMachine(m1, "su - claude -c 'jarvis2 downgrade --keep e2e' >/dev/null 2>&1 && session-secret --names | grep -cx E2E_SECRET && session-secret --names | grep -cx E2E_EXTRA || true", "1\n0")

	step("a key written into e2e before the pause, its refresh not allowed: the resumed session's carried copy is behind, " +
		"and the router asks the phone again after its first pull")
	expectOnMachine(m1, "su - claude -c \"printf late-"+secret+" | jarvis2 put-key e2e E2E_LATE --explain 'written before the pause'\" >/dev/null 2>&1; echo done", "done")
	if q := waitRequestFor(id, 30*time.Second); q == "" {
		log.Fatal("no refresh asked after the write")
	}
	denyRequestsFor(id)

	step("pause → paused (snapshot uploaded, machine killed)")
	s, b = call(router, "POST", "/api/sessions/"+id+"/pause", nil, nil)
	must(s, b, "pause")
	waitState(id, "paused", 12*time.Minute)

	step("resume, same image → no approval (dead-machine responder), snapshot restored (harness state too), secrets carried with no store unlocked")
	s, b = call(router, "POST", "/api/sessions/"+id+"/resume", map[string]bool{"upgrade": false}, nil)
	must(s, b, "resume")
	waitState(id, "started", 8*time.Minute)
	m2 := machineOf(id)
	if m2 == m1 {
		log.Fatal("resume reused the old machine")
	}
	expectOnMachine(m2, "cat /home/claude/artifacts/e2e-marker", "marker-"+secret)
	expectOnMachine(m2, "cd /home/claude && cat .paseo/e2e-state .openclaw/devices/e2e-state .local/share/opencode/storage/e2e-state && "+
		"{ test -e .openclaw/gateway.pid && echo pid || echo no-pid; }", "paseo\nopenclaw\nopencode\nno-pid")
	expectOnMachine(m2, "session-secret --names | grep -cx E2E_EXTRA || true", "0")
	expectOnMachine(m2, "session-secret --names | grep -cx E2E_SECRET", "1")
	expectOnMachine(m2, "session-secret --keys E2E_LATE --exec env 2>/dev/null | grep -c late- || true", "0")
	if q := waitRequestFor(id, 60*time.Second); q == "" {
		log.Fatal("the resumed session's copy is behind a write, and no refresh was asked")
	}
	cert = sessionCert(id)
	for _, n := range certStores(cert) {
		unlock(p, n, nonceOf(cert))
	}
	expectOnMachine(m2, "for i in $(seq 1 30); do session-secret --keys E2E_LATE --exec env 2>/dev/null | grep -q late- && break; sleep 2; done; session-secret --keys E2E_LATE --exec env 2>/dev/null | grep -c late-", "1")
	expectNoUnlocks("after the resumed session's refresh")
	expectNoUnlocks("after the resume")

	step("a lost carry blob: the resume waits on the locked store; an unlock for the session's cert lets it go on, then locks again")
	must2(call(router, "POST", "/api/sessions/"+id+"/pause", nil, nil))
	waitState(id, "paused", 12*time.Minute)
	if dd := os.Getenv("E2E_DATA_DIR"); dd != "" {
		blobs, _ := filepath.Glob(filepath.Join(dd, "snapshots", "*.carry"))
		if len(blobs) != 1 {
			log.Fatalf("carry blobs on the router after the pause: %v", blobs)
		}
		os.Remove(blobs[0])
		must2(call(router, "POST", "/api/sessions/"+id+"/resume", map[string]bool{"upgrade": false}, nil))
		deadline := time.Now().Add(8 * time.Minute)
		for session(id)["lockedStore"] != "e2e" {
			if time.Now().After(deadline) {
				dumpState()
				log.Fatal("the session doesn't say it waits on store e2e")
			}
			time.Sleep(3 * time.Second)
		}
		var cd Doc
		must2(call(router, "GET", "/api/sessions/"+id+"/cert", nil, &cd))
		unlock(p, "e2e", nonceOf(cd))
		waitState(id, "started", 4*time.Minute)
		expectOnMachine(machineOf(id), "session-secret --names | grep -cx E2E_SECRET", "1")
		expectNoUnlocks("after the waiting session's pull")
	}
	expectExec(id, "echo the rule still holds", "the rule still holds") // grants name the line, not the machine

	// a new session starts in bypass, the only start mode: the switch goes to auto
	step("the permission mode is signed: resuming in auto is a change the iPhone approves")
	must2(call(router, "POST", "/api/sessions/"+id+"/pause", nil, nil))
	waitState(id, "paused", 12*time.Minute)
	must2(call(router, "POST", "/api/sessions/"+id+"/permission-mode", map[string]string{"mode": "auto"}, nil))
	must2(call(router, "POST", "/api/sessions/"+id+"/resume", map[string]bool{"upgrade": false}, nil))
	a = waitApproval("resume-upgrade", id)
	if !strings.Contains(a.Challenge.Payload, `"permissionMode":"auto"`) {
		log.Fatal("the challenge doesn't carry the auto mode")
	}
	approve(p, a)
	waitState(id, "started", 8*time.Minute)

	step("pause, then resume with the latest image → the iPhone approves first, then the machine starts")
	must2(call(router, "POST", "/api/sessions/"+id+"/pause", nil, nil))
	waitState(id, "paused", 12*time.Minute)
	must2(call(router, "POST", "/api/sessions/"+id+"/resume", map[string]bool{"upgrade": true}, nil))
	a = waitApproval("resume-upgrade", id)
	approve(p, a)
	waitState(id, "started", 8*time.Minute)
	m3 := machineOf(id)
	expectOnMachine(m3, "cat /home/claude/artifacts/e2e-marker", "marker-"+secret)

	step("destroy → killed + burned (a succession to the null image), moved to records")
	must2(call(router, "POST", "/api/sessions/"+id+"/destroy", nil, nil))
	deadline := time.Now().Add(12 * time.Minute) // destroy waits for the final snapshot
	for {
		var recs struct {
			Records []map[string]any `json:"records"`
		}
		call(router, "GET", "/api/records", nil, &recs)
		if len(recs.Records) > 0 && recs.Records[0]["id"] == id {
			break
		}
		if time.Now().After(deadline) {
			log.Fatal("destroy didn't finish")
		}
		time.Sleep(3 * time.Second)
	}

	keeperTeardownStep(p, secret) // keeper.go: a stop signal to the main child → the transcript tail, then the snapshot

	step("one-shot: once the supervisor marks the prompt done the router destroys it by itself, forcefully, and DMs the work lost")
	// no stores: a new line with the same stores, options and image as the first session would get the same
	// challenge nonce (the core derives it from the request), which the core refuses to certify twice
	// no stores, the Claude account claude-e2e (claudeAccountStep): the machine logs into Claude by itself at boot,
	// with no grant (machine/claudelogin.go), from that account's pair at the router
	s, b = call(router, "POST", "/api/sessions", map[string]any{"label": "e2e one-shot", "stores": []string{}, "size": "small", "harness": "claude",
		"oneShot": true, "prompt": "e2e: nothing to do", "account": "claude-e2e"}, nil)
	must(s, b, "create one-shot")
	a = waitApproval("new-session", "")
	checkChallenge(a, []string{}, "")
	os1 := approve(p, a)
	if acct, _ := session(os1)["claudeAccount"].(string); acct != "claude-e2e" {
		log.Fatalf("the one-shot session's Claude account is %q", acct)
	}
	waitState(os1, "started", 6*time.Minute)
	om := machineOf(os1)
	step("a new session's Claude is logged in with no grant: the machine took its account's pair from the router at boot")
	expectOnMachine(om, "grep -c e2e-fake-refresh /home/claude/.claude/.credentials.json; stat -c %a /home/claude/.claude/.credentials.json", "1\n600")
	// the Claude login sync is the supervisor's (machine/claudelogin.go credsSync, started once booted)
	expectOnMachine(om, "grep -c 'the supervisor keeps the pair in step' /run/jarvis2/supervisor.log", "1")
	// the supervisor (the keeper and its worker) is out of the OOM killer's reach; the harness is not
	expectOnMachine(om, "for p in /proc/[0-9]*; do case \"$(tr '\\0' ' ' < $p/cmdline 2>/dev/null)\" in '/proc/self/exe supervisor '*|'/usr/local/bin/jarvis2-machine boot '*) cat $p/oom_score_adj;; esac; done | sort | uniq -c | awk '{print $1, $2}'", "2 -1000")
	expectOnMachine(om, "cat /proc/$(pgrep -o -f harness-claude)/oom_score_adj", "0")
	// its log reaches the router
	for i := 0; ; i++ {
		var sl struct {
			Events []struct{ Source, Text string } `json:"events"`
		}
		call(router, "GET", "/api/sessions/"+os1+"/events", nil, &sl)
		found := false
		for _, l := range sl.Events {
			found = found || l.Source == "supervisor" && strings.Contains(l.Text, "supervisor up")
		}
		if found {
			log.Printf("   the supervisor log is at the router, in the session's events (%d events)", len(sl.Events))
			break
		}
		if i > 30 {
			log.Fatalf("the supervisor log never reached the router (%d events)", len(sl.Events))
		}
		time.Sleep(2 * time.Second)
	}
	if ng, _ := session(os1)["needsGrant"].(string); ng != "" {
		log.Fatalf("a new session with a Claude account asks for a grant: %q", ng)
	}
	loginRefreshStep(om) // nojarvis1.go
	// a repo with an uncommitted file and no upstream, then the supervisor's marker (no Claude login here, so
	// claude never finishes a prompt by itself)
	expectOnMachine(om, "su - claude -c 'mkdir -p ~/workspace/lost && cd ~/workspace/lost && git init -q && echo x > f && echo ok'", "ok")
	expectOnMachine(om, "su - claude -c 'echo \"done e2e\" > ~/.claude/.one-shot-done && echo ok'", "ok")
	deadline = time.Now().Add(12 * time.Minute)
	for {
		var recs struct {
			Records []map[string]any `json:"records"`
		}
		call(router, "GET", "/api/records", nil, &recs)
		if len(recs.Records) > 0 && recs.Records[0]["id"] == os1 {
			break
		}
		if time.Now().After(deadline) {
			dumpState()
			log.Fatal("the one-shot session wasn't destroyed")
		}
		time.Sleep(3 * time.Second)
	}
	if lf := os.Getenv("E2E_ROUTER_LOG"); lf != "" {
		var logb []byte
		for i := 0; i < 10; i++ {
			logb, _ = os.ReadFile(lf)
			if bytes.Contains(logb, []byte("one-shot session “e2e one-shot” was destroyed with work lost")) {
				break
			}
			time.Sleep(time.Second)
		}
		if !bytes.Contains(logb, []byte("one-shot session “e2e one-shot” was destroyed with work lost")) || !bytes.Contains(logb, []byte("lost: 1 uncommitted file(s), branch has no upstream")) {
			log.Fatal("no lost-work DM for the one-shot session in the router's log")
		}
	}

	step("a task: the iPhone approves its line once; a run resumes it with no phone, runs the script, pauses it")
	var inst map[string]any
	must2(call(router, "POST", "/api/tasks/instances", map[string]any{"template": "hello", "name": "e2e hello", "params": map[string]any{"message": "hi from e2e"}}, &inst))
	iid := fmt.Sprint(inst["id"])
	approve(p, waitApproval("new-session", fmt.Sprint(inst["session"])))
	waitTask(iid, "ready", 10*time.Minute)
	var run struct{ Name string }
	must2(call(router, "POST", "/api/tasks/instances/"+iid+"/run", map[string]any{}, &run))
	deadline = time.Now().Add(10 * time.Minute)
	for {
		var rr struct {
			Run    map[string]any
			Output string
		}
		call(router, "GET", "/api/tasks/runs/"+run.Name, nil, &rr)
		ph := fmt.Sprint(rr.Run["phase"])
		if ph == "succeeded" {
			if !strings.Contains(rr.Output, "hi from e2e") {
				log.Fatalf("the run's output: %q", rr.Output)
			}
			break
		}
		if ph == "failed" || ph == "timedout" || ph == "lost" || time.Now().After(deadline) {
			log.Fatalf("the task run ended %s: %v", ph, rr.Run)
		}
		time.Sleep(5 * time.Second)
	}
	waitTask(iid, "ready", 5*time.Minute) // paused again for the next run
	must2(call(router, "DELETE", "/api/tasks/instances/"+iid, nil, nil))

	jarvis1ImportStep(p)                  // jarvis1import.go
	restoreStep(p, master, skey.StoreKey) // storerestore.go

	step("no store was left unlocked; the unlocked list is signed and empty")
	expectNoUnlocks("at the end")
	checkNoJarvis1("at the end") // nojarvis1.go
	log.Printf("E2E PASSED with Jarvis 1 unreachable (machines %s → %s → %s)", m1, m2, m3)
}

func must2(s int, b []byte) { must(s, b, "request") }

// verifyRaw: an ECDSA P-256 signature (base64 DER) by a base64 x963 public key
func verifyRaw(pubB64, payload, sigB64 string) bool {
	kb, err := b64.DecodeString(strings.TrimSpace(pubB64))
	if err != nil {
		return false
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), kb)
	if x == nil {
		return false
	}
	sig, _ := b64.DecodeString(sigB64)
	h := sha256.Sum256([]byte(payload))
	return ecdsa.VerifyASN1(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, h[:], sig)
}

func parseKey(pemBytes []byte) *ecdsa.PrivateKey {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		log.Fatal("E2E_SETUP_KEY_FILE: not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		log.Fatal("E2E_SETUP_KEY_FILE: not an EC key")
	}
	return ek
}

// sealTo: Sealed{e, data} to a P-256 public key (HKDF-SHA256 empty salt, AES-256-GCM nonce||ct||tag)
func sealTo(recipient string, plain []byte, info string) map[string]string {
	rb, _ := b64.DecodeString(recipient)
	R, err := ecdh.P256().NewPublicKey(rb)
	if err != nil {
		log.Fatal(err)
	}
	e, _ := ecdh.P256().GenerateKey(rand.Reader)
	x, _ := e.ECDH(R)
	k, _ := hkdf.Key(sha256.New, x, nil, info, 32)
	blk, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(blk)
	nonce := randBytes(g.NonceSize())
	return map[string]string{"e": b64.EncodeToString(e.PublicKey().Bytes()), "data": b64.EncodeToString(append(nonce, g.Seal(nil, nonce, plain, nil)...))}
}

// wrapKey: one key as the app wraps it for a Recover — the value under its own data key (AAD store\nkey), that key
// wrapped to the store key
func wrapKey(storeKey, store, key, value string) map[string]any {
	cb, _ := b64.DecodeString(storeKey)
	C, err := ecdh.P256().NewPublicKey(cb)
	if err != nil {
		log.Fatal(err)
	}
	e, _ := ecdh.P256().GenerateKey(rand.Reader)
	x, _ := e.ECDH(C)
	kek, _ := hkdf.Key(sha256.New, x, nil, "jarvis2/store-data-key", 32)
	dk := randBytes(32)
	return map[string]any{"store": store, "key": key, "wrapped": map[string]string{"e": b64.EncodeToString(e.PublicKey().Bytes()), "wrapped": b64.EncodeToString(gcm(kek, dk, nil))},
		"data": b64.EncodeToString(gcm(dk, []byte(value), []byte(store+"\n"+key)))}
}

// gcm: AES-256-GCM, nonce || ciphertext || tag
func gcm(key, plain, aad []byte) []byte {
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	nonce := randBytes(g.NonceSize())
	return append(nonce, g.Seal(nil, nonce, plain, aad)...)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

var unlockIDs []string

// lastUnlockWriters: store/key → who the core said wrote it ("machine <id>", "setup ", "core "), from the last unlock
var lastUnlockWriters = map[string]string{}

// fakePair: the Claude login the test router holds (a fake pair, public; never refreshed: it expires in 2100)
// claudeAccountStep: the Claude account claude-e2e, the default, its pair seeded as Jarvis 1 would push a Re-login
// (Jarvis 1 follows the default account; the test router has no Access in front)
func claudeAccountStep() {
	step("a Claude account: claude-e2e, the default (its sign-in started, its pair pushed as Jarvis 1's Re-login)")
	must2(call(router, "POST", "/api/claude-accounts", map[string]any{"name": "e2e"}, nil))
	must2(call(router, "POST", "/peer/claude-login", map[string]any{"credentials": fakePair,
		"account": `{"oauthAccount":{"accountUuid":"e2e-account","emailAddress":"e2e@example.com"}}`, "relogin": true}, nil))
	var l struct {
		Default  string           `json:"default"`
		Accounts []map[string]any `json:"accounts"`
	}
	must2(call(router, "GET", "/api/claude-accounts", nil, &l))
	if l.Default != "claude-e2e" || len(l.Accounts) != 1 || l.Accounts[0]["hasLogin"] != true {
		log.Fatalf("claude accounts: %+v", l)
	}
}

const fakePair = `{"claudeAiOauth": {"accessToken": "e2e-fake-access", "refreshToken": "e2e-fake-refresh", "expiresAt": 4102444800000, "scopes": ["user:inference"], "subscriptionType": "max"}}`

// unlock: forNonce = the challenge or cert nonce the unlock is for (what the app's Start, add-store and Unlock…
// send); "" = a standing unlock (the Stores page)
func unlock(p *phone, store, forNonce string) {
	var d Doc
	must2(call(router, "POST", "/api/core/unlock/begin", map[string]string{"store": store, "for": forNonce}, &d))
	var ub struct {
		Kind, Pending, Store, T, For string
		Keys                         []struct {
			Key, E string
			Writer struct{ By, Machine string }
		}
	}
	verify(d, &ub)
	if ub.Kind != "unlock-begin" || ub.Store != store || ub.For != forNonce {
		log.Fatalf("unlock-begin: %+v", ub)
	}
	// the phone's share x(p·E) of one E (the Enclave returns only x), sealed to the core's one-off T
	share := func(e string) map[string]string {
		eb, _ := b64.DecodeString(e)
		E, _ := ecdh.P256().NewPublicKey(eb)
		x, _ := p.agr.ECDH(E)
		tb, _ := b64.DecodeString(ub.T)
		T, _ := ecdh.P256().NewPublicKey(tb)
		r, _ := ecdh.P256().GenerateKey(rand.Reader)
		x2, _ := r.ECDH(T)
		k, _ := hkdf.Key(sha256.New, x2, nil, "jarvis2/unlock-share", 32)
		blk, _ := aes.NewCipher(k)
		g, _ := cipher.NewGCM(blk)
		nonce := randBytes(g.NonceSize())
		return map[string]string{"e": b64.EncodeToString(r.PublicKey().Bytes()), "data": b64.EncodeToString(append(nonce, g.Seal(nil, nonce, x, nil)...))}
	}
	shares := map[string]map[string]string{} // one share per key
	for _, k := range ub.Keys {
		shares[k.Key] = share(k.E)
		lastUnlockWriters[store+"/"+k.Key] = k.Writer.By + " " + k.Writer.Machine
	}
	must2(call(router, "POST", "/api/core/unlock/finish", map[string]any{"pending": ub.Pending, "shares": shares}, &d))
	var uf struct{ Kind, ID, Store string }
	verify(d, &uf)
	if uf.Kind != "unlocked" {
		log.Fatalf("unlock-finish: %+v", uf)
	}
	unlockIDs = append(unlockIDs, uf.ID)
}

// nonceOf: a core-signed challenge's or cert's nonce
func nonceOf(d Doc) string {
	var x struct{ Nonce string }
	verify(d, &x)
	return x.Nonce
}

// storeOpen: the core's signed store list says the store is open to every session (a standing unlock)
func storeOpen(name string) bool {
	var d Doc
	must2(call(router, "POST", "/api/core/stores", map[string]string{"nonce": "n-open"}, &d))
	var l struct {
		Stores []struct {
			Name     string
			Unlocked bool
		}
	}
	verify(d, &l)
	for _, x := range l.Stores {
		if x.Name == name {
			return x.Unlocked
		}
	}
	return false
}

// lockAll: lock every unlock this test opened that is still open
func lockAll() {
	for _, uid := range unlockIDs {
		call(router, "POST", "/api/core/lock", map[string]string{"id": uid}, nil)
	}
	unlockIDs = nil
}

// expectNoUnlocks: the core's signed unlocked list is empty — every unlock for a session went with its pull
func expectNoUnlocks(when string) {
	var ul struct {
		Kind     string           `json:"kind"`
		Nonce    string           `json:"nonce"`
		Unlocked []map[string]any `json:"unlocked"`
	}
	var d Doc
	must2(call(router, "POST", "/api/core/unlocked", map[string]string{"nonce": "n-123"}, &d))
	verify(d, &ul)
	if ul.Nonce != "n-123" || len(ul.Unlocked) != 0 {
		log.Fatalf("a store is still unlocked %s: %+v", when, ul)
	}
}

// waitRequestFor: an unlock request (a refresh) for the session in the Inbox within d → its id ("" = none)
func waitRequestFor(sid string, d time.Duration) string {
	for deadline := time.Now().Add(d); ; time.Sleep(2 * time.Second) {
		var out struct {
			Requests []struct{ ID, Kind, Session string }
		}
		call(router, "GET", "/api/requests", nil, &out)
		for _, q := range out.Requests {
			if q.Kind == "unlock" && q.Session == sid {
				return q.ID
			}
		}
		if time.Now().After(deadline) {
			return ""
		}
	}
}

// denyRequestsFor: Deyao denies every Inbox request for the session (a refresh he doesn't allow)
func denyRequestsFor(sid string) {
	var out struct {
		Requests []struct{ ID, Kind, Session string }
		Batches  []struct{ ID string }
	}
	call(router, "GET", "/api/requests", nil, &out)
	for _, b := range out.Batches {
		call(router, "DELETE", "/api/requests/batches/"+b.ID, nil, nil)
	}
	for _, q := range out.Requests {
		if q.Session == sid {
			call(router, "DELETE", "/api/requests/"+q.ID, nil, nil)
		}
	}
}

// sessionCert: the session's newest cert as the router serves it to the app (core-signed)
func sessionCert(sid string) Doc {
	var d Doc
	must2(call(router, "GET", "/api/sessions/"+sid+"/cert", nil, &d))
	return d
}

func certStores(c Doc) []string {
	var x struct{ Stores []string }
	verify(c, &x)
	return x.Stores
}

type approval struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Session   string `json:"session"`
	Challenge *Doc   `json:"challenge"`
}

func waitApproval(kind, session string) approval {
	deadline := time.Now().Add(12 * time.Minute) // destroy waits for the final snapshot
	for time.Now().Before(deadline) {
		var out struct {
			Approvals []approval `json:"approvals"`
		}
		call(router, "GET", "/api/approvals", nil, &out)
		for _, a := range out.Approvals {
			if a.Kind == kind && (session == "" || a.Session == session) {
				return a
			}
		}
		time.Sleep(3 * time.Second)
	}
	dumpState()
	log.Fatalf("no %s approval", kind)
	return approval{}
}

// waitApprovals: n approvals of that kind for the session, all pending at once
func waitApprovals(kind, session string, n int) []approval {
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		var out struct {
			Approvals []approval `json:"approvals"`
		}
		call(router, "GET", "/api/approvals", nil, &out)
		var got []approval
		for _, a := range out.Approvals {
			if a.Kind == kind && a.Session == session {
				got = append(got, a)
			}
		}
		if len(got) == n {
			return got
		}
		time.Sleep(3 * time.Second)
	}
	dumpState()
	log.Fatalf("not %d %s approvals", n, kind)
	return nil
}

// the checks the iPhone makes before signing (docs/API.md)
func checkChallenge(a approval, stores []string, added string) {
	var ch struct {
		Kind    string `json:"kind"`
		Request struct {
			Machine    *map[string]any `json:"machine"`
			Stores     []string        `json:"stores"`
			AddedStore string          `json:"addedStore"`
			Options    struct{ Harness string }
		} `json:"request"`
	}
	verify(*a.Challenge, &ch)
	if ch.Kind != "challenge" || (added != "") != (ch.Request.Machine != nil) || strings.Join(ch.Request.Stores, ",") != strings.Join(stores, ",") ||
		ch.Request.AddedStore != added || ch.Request.Options.Harness != "claude" {
		log.Fatalf("challenge doesn't match: %s", a.Challenge.Payload)
	}
}

func approve(p *phone, a approval) string {
	var out struct {
		Answer  Doc    `json:"answer"`
		Session string `json:"session"`
	}
	s, b := call(router, "POST", "/api/approvals/"+a.ID+"/respond", map[string]string{"signature": p.sign(a.Challenge.Payload)}, &out)
	must(s, b, "respond")
	var c struct{ Kind string }
	verify(out.Answer, &c)
	if c.Kind != "approval" && c.Kind != "succession-cert" { // a new line: an approval; adding a store: the cert at once
		log.Fatalf("answer kind %s", c.Kind)
	}
	return out.Session
}

func session(id string) map[string]any {
	var st struct {
		Sessions []map[string]any `json:"sessions"`
	}
	call(router, "GET", "/api/state", nil, &st)
	for _, s := range st.Sessions {
		if s["id"] == id {
			return s
		}
	}
	return nil
}

func waitState(id, want string, d time.Duration) {
	deadline := time.Now().Add(d)
	last := ""
	for time.Now().Before(deadline) {
		s := session(id)
		if s != nil {
			cur := fmt.Sprint(s["state"])
			if cur != last {
				log.Printf("   %s: %s %v", id, cur, s["error"])
				last = cur
			}
			if cur == want {
				return
			}
			if cur == "failed" {
				log.Fatalf("session failed: %v", s["error"])
			}
		}
		time.Sleep(3 * time.Second)
	}
	dumpState()
	log.Fatalf("%s never reached %s", id, want)
}

func machineOf(id string) string { return fmt.Sprint(session(id)["machineId"]) }

func dumpState() {
	_, b := call(router, "GET", "/api/state", nil, nil)
	log.Printf("state: %.2000s", string(b))
}

// flyMachineEnv: the env in a machine's Fly config
func flyMachineEnv(m string) map[string]string {
	req, _ := http.NewRequest("GET", "https://api.machines.dev/v1/apps/jarvis4-sessions/machines/"+m, nil)
	req.Header.Set("Authorization", "Bearer "+os.Getenv("E2E_FLY_TOKEN"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("fly get %s: %v", m, err)
	}
	defer resp.Body.Close()
	var out struct {
		Config struct {
			Env map[string]string `json:"env"`
		} `json:"config"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	return out.Config.Env
}

// flyExec: a command on a machine through the Machines API → its stdout and exit code
func flyExec(m string, cmd []string) (string, int, error) {
	body, _ := json.Marshal(map[string]any{"command": cmd, "timeout": 60})
	req, _ := http.NewRequest("POST", "https://api.machines.dev/v1/apps/jarvis4-sessions/machines/"+m+"/exec", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+os.Getenv("E2E_FLY_TOKEN"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", -1, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", -1, fmt.Errorf("HTTP %d %s", resp.StatusCode, b)
	}
	var out struct {
		Stdout   string `json:"stdout"`
		ExitCode int    `json:"exit_code"`
	}
	json.Unmarshal(b, &out)
	return out.Stdout, out.ExitCode, nil
}

// expectOnMachine: exit 0 and stdout (trimmed) exactly `want`
func expectOnMachine(m, cmd, want string) {
	var out string
	var code int
	var err error
	for i := 0; i < 10; i++ {
		out, code, err = flyExec(m, []string{"sh", "-c", cmd})
		if err == nil && code == 0 && strings.TrimSpace(out) == want {
			log.Printf("   on %s: %q → %q ok", m, cmd, want)
			return
		}
		time.Sleep(5 * time.Second)
	}
	log.Fatalf("on %s, %q gave %q (exit %d, %v), want %q", m, cmd, out, code, err, want)
}

// expectExec: a command through the router's grant relay (holder "terminal")
func expectExec(id, cmd, want string) {
	var res struct {
		Stdout string
		Code   int
	}
	s, b := call(router, "POST", "/api/sessions/"+id+"/exec", map[string]any{"cmd": cmd, "timeout": 30}, &res)
	must(s, b, "exec "+cmd)
	if strings.TrimSpace(res.Stdout) != want || res.Code != 0 {
		log.Fatalf("exec %q: got %q (code %d), want %q", cmd, res.Stdout, res.Code, want)
	}
}

// waitLiveSync: the router lists the file in the session's liveSync
func waitLiveSync(id, name string, d time.Duration) {
	deadline := time.Now().Add(d)
	for {
		if ls, ok := session(id)["liveSync"].(map[string]any); ok {
			if files, ok := ls["files"].(map[string]any); ok && files[name] != nil {
				log.Printf("   live sync: %s received (stored %v)", name, ls["stored"])
				return
			}
		}
		if time.Now().After(deadline) {
			dumpState()
			log.Fatalf("live sync: %s never reached the router", name)
		}
		time.Sleep(5 * time.Second)
	}
}

func waitTask(id, want string, d time.Duration) {
	deadline := time.Now().Add(d)
	for {
		var t struct{ Instances []map[string]any }
		call(router, "GET", "/api/tasks", nil, &t)
		for _, i := range t.Instances {
			if i["id"] == id && i["state"] == want {
				return
			}
		}
		if time.Now().After(deadline) {
			log.Fatalf("task %s never %s: %v", id, want, t.Instances)
		}
		time.Sleep(5 * time.Second)
	}
}

// drainStep (E2E_ONLY=drain): a router rollout while a pause is in flight. SIGTERM reaches the router right after the
// pause began: it goes on serving reads and the machine's snapshot (over Fly's private network), refuses a new action
// with 503 "router updating, try again shortly", lets the pause finish, then exits on its own.
func drainStep(id string) {
	step("drain: SIGTERM with a pause in flight → reads served, new actions 503, the pause finishes, then the router exits")
	pid, err := strconv.Atoi(os.Getenv("E2E_ROUTER_PID"))
	if err != nil {
		log.Fatal("E2E_ONLY=drain needs E2E_ROUTER_PID (infra/e2e.sh sets it)")
	}
	proc, _ := os.FindProcess(pid)
	s, b := call(router, "POST", "/api/sessions/"+id+"/pause", nil, nil)
	must(s, b, "pause")
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		log.Fatalf("SIGTERM: %v", err)
	}
	time.Sleep(time.Second)
	if s, b := call(router, "GET", "/api/state", nil, nil); s != 200 {
		log.Fatalf("GET /api/state during the drain: %d %s", s, b)
	}
	s, b = call(router, "POST", "/api/sessions/"+id+"/destroy", nil, nil)
	if s != 503 || !strings.Contains(string(b), "router updating, try again shortly") {
		log.Fatalf("a new action during the drain: %d %s", s, b)
	}
	// the router exits once the pause is done (it may be gone before a poll sees "paused"): its volume says how it ended
	for i := 0; proc.Signal(syscall.Signal(0)) == nil; i++ {
		if i > 12*60*2 {
			log.Fatal("the router didn't exit within 12 min of the drain")
		}
		time.Sleep(500 * time.Millisecond)
	}
	var st struct {
		Sessions map[string]struct{ State, Error string }
	}
	sb, err := routerdb.StateJSON()
	if err != nil || json.Unmarshal(sb, &st) != nil {
		log.Fatalf("the router's records: %v", err)
	}
	if x := st.Sessions[id]; x.State != "paused" {
		log.Fatalf("the in-flight pause ended %q (%s)", x.State, x.Error)
	}
	lb, _ := os.ReadFile(os.Getenv("E2E_ROUTER_LOG"))
	if strings.Contains(string(lb), "not waiting for a snapshot") || strings.Contains(string(lb), "never got past boot") {
		log.Fatal("the pause didn't wait for the machine's snapshot: the drain wasn't tested with one in flight")
	}
	if !strings.Contains(string(lb), "drained") {
		log.Fatal("the router's log has no \"drained\"")
	}
	log.Printf("E2E PASSED (the drain only)")
}
