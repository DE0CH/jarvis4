package main

// E2E_ONLY=continuity (docs/DESIGN.md "Core continuity"): the core set up from the master key's seed, a running and a
// paused session, then the core process restarted (empty) and Recovered with the same kit and the line state the
// router kept: the same core key, the running session's machine (on the session image as it is, unchanged) still
// reads the store list, adds a store and pulls, the paused one resumes unattended, and a destroy goes through.

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// derived: the public keys the seed derives (the same derivation as core/continuity.go, written again here)
func derived(seed []byte) (signing, agreement string) {
	scalar := func(label string) []byte {
		for i := 0; i < 16; i++ {
			info := "jarvis2/core/" + label
			if i > 0 {
				info += "/" + strconv.Itoa(i)
			}
			d, _ := hkdf.Key(sha256.New, seed, nil, info, 32)
			if _, err := ecdh.P256().NewPrivateKey(d); err == nil {
				return d
			}
		}
		log.Fatal("no scalar")
		return nil
	}
	sk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar("signing"))
	if err != nil {
		log.Fatal(err)
	}
	pub, _ := sk.PublicKey.ECDH()
	ak, _ := ecdh.P256().NewPrivateKey(scalar("agreement"))
	return b64.EncodeToString(pub.Bytes()), b64.EncodeToString(ak.PublicKey().Bytes())
}

type coreIdentity struct {
	SigningKey   string `json:"signingKey"`
	AgreementKey string `json:"agreementKey"`
	BoxSig       string `json:"boxSig"`
	State        Doc    `json:"state"`
	Continuity   int    `json:"continuity"`
}

// seededClaim: the new app's Recover: the seed, the derived identity in the statement, every key wrapped to P + K for
// the DERIVED K, and the line state (nil = none); answers the derived signing key
func seededClaim(master *ecdsa.PrivateKey, p *phone, phoneAgreement string, recovered map[string]map[string]string, line json.RawMessage) string {
	var id0 coreIdentity
	must2(call(router, "GET", "/api/core/identity", nil, &id0))
	if id0.Continuity != 1 {
		log.Fatal("the core doesn't take a seed")
	}
	d, _ := master.Bytes()
	seed, _ := hkdf.Key(sha256.New, d, nil, "jarvis2/core-seed", 32)
	dsk, dak := derived(seed)
	var skd Doc
	must2(call(router, "POST", "/api/core/store-key", map[string]string{"phone": phoneAgreement, "core": dak}, &skd))
	coreKey = id0.SigningKey // the boot key signs the store key
	var skey struct{ Kind, Phone, StoreKey, Core string }
	verify(skd, &skey)
	if skey.Core != dak {
		log.Fatalf("the store key isn't for the derived core point: %+v", skey)
	}
	names, keys := []string{}, []map[string]any{}
	for _, n := range []string{"claude", "e2e", "e2e-extra", "e2e-more"} {
		names = append(names, n)
		for k, v := range recovered[n] {
			keys = append(keys, wrapKey(skey.StoreKey, n, k, v))
		}
	}
	b := map[string]any{"format": "keys", "stores": names, "keys": keys, "flyToken": coreFlyToken(),
		"notSensitive": []string{"e2e", "claude"}, "coreSeed": b64.EncodeToString(seed)}
	if line != nil {
		b["lineState"] = line
	}
	bundle, _ := json.Marshal(b)
	sum := sha256.Sum256(bundle)
	mpub, _ := master.PublicKey.ECDH()
	stmt, _ := json.Marshal(map[string]any{"kind": "claim", "master": b64.EncodeToString(mpub.Bytes()),
		"core":         map[string]string{"signingKey": id0.SigningKey, "agreementKey": id0.AgreementKey},
		"identity":     map[string]string{"signingKey": dsk, "agreementKey": dak},
		"phone":        map[string]string{"signingKey": p.signingKey(), "agreementKey": phoneAgreement},
		"bundleSha256": hex.EncodeToString(sum[:])})
	h := sha256.Sum256(stmt)
	msig, _ := ecdsa.SignASN1(rand.Reader, master, h[:])
	var rec Doc
	must2(call(router, "POST", "/api/core/claim", map[string]any{"statement": string(stmt), "masterSig": b64.EncodeToString(msig),
		"bundle": sealTo(id0.AgreementKey, bundle, "jarvis2/claim")}, &rec))
	coreKey = dsk // from the claim's answer on, the core signs with the derived key
	var claimed struct {
		Kind    string
		Derived bool
		LineSeq int
	}
	verify(rec, &claimed)
	if !claimed.Derived {
		log.Fatalf("the core didn't take the seed: %+v", claimed)
	}
	var id1 coreIdentity
	must2(call(router, "GET", "/api/core/identity", nil, &id1))
	if id1.SigningKey != dsk || id1.AgreementKey != dak || !verifyRaw(os.Getenv("E2E_BOX_PUB"), "jarvis2-core-identity "+dsk+" "+dak, id1.BoxSig) {
		log.Fatalf("the core's identity after the claim isn't the derived one the box key vouches for: %+v", id1)
	}
	log.Printf("   claimed with the seed: core key %.16s…, line state %d", dsk, claimed.LineSeq)
	return dsk
}

func continuityStep(p *phone, master *ecdsa.PrivateKey, phoneAgreement string, recovered map[string]map[string]string, id, m1, secret string) {
	step("continuity: a second session, paused (its secrets carried)")
	s, b := call(router, "POST", "/api/sessions", map[string]any{"label": "e2e paused", "stores": []string{"e2e"}, "size": "small", "harness": "claude"}, nil)
	must(s, b, "create")
	a := waitApproval("new-session", "")
	unlock(p, "e2e", nonceOf(*a.Challenge))
	id2 := approve(p, a)
	waitState(id2, "started", 6*time.Minute)
	expectOnMachine(machineOf(id2), "session-secret --names | grep -cx E2E_SECRET", "1")
	must2(call(router, "POST", "/api/sessions/"+id2+"/pause", nil, nil))
	waitState(id2, "paused", 12*time.Minute)
	key := coreKey

	step("continuity: the core restarts (an empty core with fresh boot keys)")
	out, err := exec.Command(os.Getenv("E2E_CORE_RESTART")).CombinedOutput()
	if err != nil {
		log.Fatalf("core restart: %v %s", err, out)
	}
	deadline := time.Now().Add(time.Minute)
	for {
		var id coreIdentity
		if s, _ := call(router, "GET", "/api/core/identity", nil, &id); s == 200 && id.SigningKey != key {
			var st struct{ Master string }
			json.Unmarshal([]byte(id.State.Payload), &st)
			if st.Master == "" {
				break
			}
		}
		if time.Now().After(deadline) {
			log.Fatal("no empty core after the restart")
		}
		time.Sleep(time.Second)
	}

	step("continuity: Recover with the same kit and the line state the router kept → the same core key")
	var line json.RawMessage
	s, b = call(router, "GET", "/api/core/line-state", nil, &line)
	must(s, b, "line state")
	if k := seededClaim(master, p, phoneAgreement, recovered, line); k != key {
		log.Fatalf("the Recovered core's key %.16s… isn't the one before %.16s…", k, key)
	}

	step("continuity: the running session's machine reads the store list, adds a store and pulls (its e2e from the carry)")
	expectOnMachine(m1, "su - claude -c 'jarvis stores' >/dev/null 2>&1 && echo ok", "ok")
	go flyExec(m1, []string{"su", "-", "claude", "-c", "jarvis add-store e2e-more"})
	pending := waitApprovals("add-store", id, 1)
	unlock(p, "e2e-more", nonceOf(*pending[0].Challenge))
	approve(p, pending[0])
	expectOnMachine(m1, "for i in $(seq 1 30); do session-secret --names | grep -qx E2E_MORE && break; sleep 2; done; "+
		"session-secret --names | grep -cx E2E_MORE; session-secret --names | grep -cx E2E_SECRET", "1\n1")
	expectNoUnlocks("after the add-store on the Recovered core")
	if session(id)["oldCore"] == true {
		log.Fatal("the running session was taken for an earlier core's")
	}

	step("continuity: the paused session resumes unattended (no approval, no unlock) with its carried secrets")
	must2(call(router, "POST", "/api/sessions/"+id2+"/resume", map[string]bool{"upgrade": false}, nil))
	waitState(id2, "started", 8*time.Minute)
	expectOnMachine(machineOf(id2), "session-secret --names | grep -cx E2E_SECRET", "1")
	expectNoUnlocks("after the resume on the Recovered core")

	step("continuity: destroy goes through on the Recovered core")
	must2(call(router, "POST", "/api/sessions/"+id2+"/destroy", nil, nil))
	deadline = time.Now().Add(10 * time.Minute)
	for session(id2) != nil {
		if time.Now().After(deadline) {
			dumpState()
			log.Fatal("the destroy didn't finish")
		}
		time.Sleep(3 * time.Second)
	}
	log.Printf("E2E PASSED (core continuity: restart + Recover kept the sessions)")
}

// coreFlyToken: the Fly token the test core gets in its Recover bundle (E2E_CORE_FLY_TOKEN: narrowed as production's;
// the test's own Fly calls keep E2E_FLY_TOKEN)
func coreFlyToken() string {
	if t := os.Getenv("E2E_CORE_FLY_TOKEN"); t != "" {
		return t
	}
	return os.Getenv("E2E_FLY_TOKEN")
}
