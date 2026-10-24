package kerneltest

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/DE0CH/jarvis4/kernel/perm"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

// post: a component's answer (a signed document), or the error it gave
func (k *Kernel) post(role, path string, body any) (sig.Doc, error) {
	b, _ := json.Marshal(body)
	resp, err := http.Post(k.URL[role]+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return sig.Doc{}, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	var d sig.Doc
	json.Unmarshal(out, &d)
	if resp.StatusCode != 200 {
		return d, fmt.Errorf("%s%s: HTTP %d %s", role, path, resp.StatusCode, d.Payload)
	}
	return d, nil
}

// Identity: a component's identity
func (k *Kernel) Identity(role string) sig.Identity {
	resp, err := http.Get(k.URL[role] + "/identity")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var id sig.Identity
	if role == "secrets" {
		var m struct{ SigningKey, AgreementKey string }
		json.Unmarshal(b, &m)
		return sig.Identity{Role: role, SigningKey: m.SigningKey, AgreementKey: m.AgreementKey}
	}
	var d sig.Doc
	json.Unmarshal(b, &d)
	json.Unmarshal([]byte(d.Payload), &id)
	return id
}

// Notarize: the notary's challenge, then the notarizer
func (k *Kernel) Notarize(t testing.TB, cert sig.Doc) sig.Doc {
	t.Helper()
	c, err := doc.PeekCert(cert)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := k.post("notary", "/challenge", map[string]string{"subject": cert.ID(), "about": "cert"})
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]any{"cert": cert, "challenge": ch, "notary": k.Identity("notary")}
	if c.Signer == doc.ByIPhone || c.Signer == doc.ByRoot {
		ks, err := k.post("secrets", "/keys", map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		in["keys"], in["secrets"] = ks, k.Identity("secrets")
	} else {
		in["signer"] = k.Identity(c.Signer)
	}
	nz, err := k.post("notarizer", "/notarize", in)
	if err != nil {
		t.Fatal(err)
	}
	return nz
}

// Move: g along the notarized cert
func (k *Kernel) Move(t testing.TB, g gv.Signed, cert, nz sig.Doc) gv.Signed {
	t.Helper()
	in := map[string]any{"grant": g.Grant, "by": g.By, "cert": cert, "notarized": nz, "notarizer": k.Identity("notarizer"), "notary": k.Identity("notary")}
	if g.Signer != nil {
		in["signer"] = g.Signer
	}
	if g.By == "root" {
		ks, _ := k.post("secrets", "/keys", map[string]any{})
		in["keys"], in["secrets"] = ks, k.Identity("secrets")
	}
	d, err := k.post("mover", "/move", in)
	if err != nil {
		t.Fatal(err)
	}
	id := k.Identity("mover")
	return gv.Signed{Grant: d, By: "mover", Signer: &id}
}

// Line: a new line run through the kernel as the router runs it: the phone's cert into a new source (with these
// settings and stores, for session sid), notarized, the root's ⊤ moved onto it; a spawn; the spawner's cert, notarized,
// the grant moved onto the machine. Its boot documents (what GET /m/kernel/boot answers) and the Fly machine.
func (k *Kernel) Line(t testing.TB, sid, image string, settings json.RawMessage, stores ...string) (map[string]any, *FakeMachine) {
	t.Helper()
	b := make([]byte, 16)
	rand.Read(b)
	allowed := []string{}
	for _, s := range stores {
		allowed = append(allowed, "store:"+s)
	}
	c := doc.Cert{Kind: "succession", Pred: doc.Sink, Succ: doc.NewSource(b),
		Pair:   perm.Pair{Allowed: perm.Only(allowed...), Conditions: []string{"session:" + sid}},
		Source: &doc.Source{Image: image, Settings: settings}, Signer: doc.ByIPhone, IssuedAt: doc.Now()}
	sc, err := k.Phone.SignJSON(c)
	if err != nil {
		t.Fatal(err)
	}
	snz := k.Notarize(t, sc)
	g := k.Move(t, gv.Signed{Grant: k.RootTop(), By: "root"}, sc, snz)
	created, err := k.post("spawner", "/spawn", map[string]any{"cert": sc, "notarized": snz, "notarizer": k.Identity("notarizer"), "region": "lhr", "size": "medium", "diskGb": 10})
	if err != nil {
		t.Fatal(err)
	}
	var cr struct{ ID string }
	json.Unmarshal([]byte(created.Payload), &cr)
	mc, err := k.post("spawner", "/init", map[string]string{"id": cr.ID})
	if err != nil {
		t.Fatal(err)
	}
	mnz := k.Notarize(t, mc)
	g = k.Move(t, g, mc, mnz)
	out := map[string]any{"grant": g, "machineCert": mc, "machineNotarized": mnz, "sourceCert": sc, "sourceNotarized": snz}
	for _, r := range []string{"notary", "notarizer", "mover", "merger", "spawner", "secrets"} {
		out[r] = k.Identity(r)
	}
	out["keys"], _ = k.post("secrets", "/keys", map[string]any{})
	out["stores"], _ = k.post("secrets", "/stores", map[string]string{"nonce": "n"})
	return out, k.Fly.Machine(cr.ID)
}

// Challenge: a log-notary challenge (what the router asks for before an input reaches a kernel machine)
func (k *Kernel) Challenge(t testing.TB, subject, about string) sig.Doc {
	t.Helper()
	d, err := k.post("notary", "/challenge", map[string]string{"subject": subject, "about": about})
	if err != nil {
		t.Fatal(err)
	}
	return d
}
