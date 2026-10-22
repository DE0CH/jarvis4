package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/DE0CH/jarvis4/kernel/kerneltest"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

const kImage = "ghcr.io/de0ch/jarvis4-session:sha-aaaaaaaaaaaa@sha256:1111111111111111111111111111111111111111111111111111111111111111"

func bootDocs(t *testing.T, k *kerneltest.Kernel) (kernelBootDocs, *kerneltest.FakeMachine) {
	settings := json.RawMessage(`{"v":1,"harness":"claude","permissionMode":"auto","config":{"v":1,"label":"x","model":"claude-opus-5-5"}}`)
	m, fm := k.Line(t, "s1", kImage, settings, "default", "tunnel")
	raw, _ := json.Marshal(m)
	var b kernelBootDocs
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	return b, fm
}

func fmKeys(fm *kerneltest.FakeMachine) map[string]string {
	return map[string]string{"signingKey": fm.Sig.PublicKey(), "encryptionKey": sig.B64.EncodeToString(fm.Enc.PublicKey().Bytes())}
}

// the documents a kernel machine boots from check, and give the settings, stores and session the source names
func TestAKernelMachineReadsItsDocuments(t *testing.T) {
	k := kerneltest.Start(t, map[string]string{"JARVIS2_URL": "http://router"})
	b, fm := bootDocs(t, k)
	cert, trust, err := checkKernelBoot(b, k.Trust(), fm.Env["JARVIS2_SOURCE"], fm.ID, fmKeys(fm))
	if err != nil {
		t.Fatal(err)
	}
	if cert.Options.Harness != "claude" || cert.Options.PermissionMode != "auto" || !strings.Contains(cert.Options.Config, `"label":"x"`) ||
		strings.Join(cert.Stores, ",") != "default,tunnel" || cert.Line != "s1" || cert.PredID != "" || cert.Snapshot != "" {
		t.Fatalf("%+v", cert)
	}
	if v, err := vouch(cert); err != nil || v.Config.Label != "x" || v.Config.Model != "claude-opus-5-5" {
		t.Fatal(err, v.Config)
	}
	if cert.Phone != k.Phone.PublicKey() || !cert.Sensitive { // no store secrets lists: counted sensitive
		t.Fatalf("phone %q sensitive %v", cert.Phone, cert.Sensitive)
	}
	if trust.Machine != "fly-"+fm.ID || trust.Root != k.Root.PublicKey() {
		t.Fatalf("%+v", trust)
	}
}

// ✱ what a router could hand a kernel machine instead: another machine's documents, another source, another roster,
// a grant from elsewhere, a cert not notarized
func TestAKernelMachineRefusesOtherDocuments(t *testing.T) {
	k := kerneltest.Start(t, map[string]string{"JARVIS2_URL": "http://router"})
	b, fm := bootDocs(t, k)
	b2, fm2 := bootDocs(t, k)
	box, src, keys := k.Trust(), fm.Env["JARVIS2_SOURCE"], fmKeys(fm)
	refuse := func(name string, d kernelBootDocs, box *sig.Trust, src, me string, keys map[string]string) {
		t.Helper()
		if _, _, err := checkKernelBoot(d, box, src, me, keys); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	refuse("another machine's documents", b2, box, src, fm.ID, keys)
	refuse("another source", b, box, fm2.Env["JARVIS2_SOURCE"], fm.ID, keys)
	other, _ := sig.NewSigner()
	strangers := []sig.Identity{}
	for _, r := range []string{"notary", "notarizer", "mover", "merger", "spawner", "secrets"} {
		c, _ := sig.NewComponent(r)
		strangers = append(strangers, c.Identity)
	}
	p, _ := sig.RosterPayload("blue", strangers)
	ps, _ := other.Sign([]byte(p))
	otherTrust := sig.NewTrust(other.PublicKey())
	if err := otherTrust.Set(sig.Doc{Payload: p, Sig: ps}, nil); err != nil {
		t.Fatal(err)
	}
	refuse("another roster", b, otherTrust, src, fm.ID, keys)
	if sig.NewTrust(k.Root.PublicKey()).Set(sig.Doc{Payload: p, Sig: ps}, nil) == nil {
		t.Fatal("a roster another key signed, taken as the root key's")
	}
	refuse("other keys", b, box, src, fm.ID, fmKeys(fm2))
	x := b
	x.Grant = b2.Grant
	refuse("another machine's grant", x, box, src, fm.ID, keys)
	x = b
	x.MachineNotarized = b2.MachineNotarized
	refuse("a notarization of another cert", x, box, src, fm.ID, keys)
	x = b
	x.SourceCert, x.SourceNotarized = b2.SourceCert, b2.SourceNotarized
	refuse("another source's cert", x, box, src, fm.ID, keys)
	x = b
	fake, _ := sig.NewComponent("mover")
	g := b.Grant
	g.Signer = &fake.Identity
	x.Grant = gv.Signed(g)
	refuse("a mover the roster doesn't name", x, box, src, fm.ID, keys)
	if _, _, err := checkKernelBoot(b, box, src, fm.ID, keys); err != nil {
		t.Fatal(err)
	}
}

// the clean env keeps a kernel machine's root key, roster and source, and refuses a machine with neither
func TestCleanEnvKeepsTheKernelsKeys(t *testing.T) {
	key := strings.Repeat("A", 87) + "="
	env, err := cleanEnv([]string{"JARVIS2_KERNEL_ROOT=" + key, `JARVIS2_KERNEL_ROSTER={"payload":"{}","sig":"x"}`, "JARVIS2_SOURCE=source-" + strings.Repeat("ab", 16), "EVIL=1"}, nil)
	if err != nil || !strings.Contains(strings.Join(env, "\n"), "JARVIS2_SOURCE=source-") || strings.Contains(strings.Join(env, "\n"), "EVIL") {
		t.Fatal(err, env)
	}
	if _, err := cleanEnv([]string{"JARVIS2_KERNEL_ROOT=" + key, `JARVIS2_KERNEL_ROSTER={}`, "JARVIS2_SOURCE=nope"}, nil); err == nil {
		t.Fatal("a bad source accepted")
	}
}

// a delivered input is the log notary's challenge over (this machine, its kind, its hash); ✱ another machine's,
// another kind, other bytes, not about an input, another notary
func TestAKernelMachineChecksTheNotarysLog(t *testing.T) {
	k := kerneltest.Start(t, map[string]string{"JARVIS2_URL": "http://router"})
	b, fm := bootDocs(t, k)
	_, trust, err := checkKernelBoot(b, k.Trust(), fm.Env["JARVIS2_SOURCE"], fm.ID, fmKeys(fm))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("wake up")
	sum := hexSum256(body)
	ok := k.Challenge(t, KernelInputSubject("fly-"+fm.ID, "wakeup", sum), "input")
	d := &SignedDoc{Payload: ok.Payload, Sig: ok.Sig}
	if err := checkKernelAttest(trust, fm.ID, "wakeup", body, d); err != nil {
		t.Fatal(err)
	}
	for name, x := range map[string]func() error{
		"another machine": func() error { return checkKernelAttest(trust, "00000000000001", "wakeup", body, d) },
		"another kind":    func() error { return checkKernelAttest(trust, fm.ID, "cron", body, d) },
		"other bytes":     func() error { return checkKernelAttest(trust, fm.ID, "wakeup", []byte("rm -rf"), d) },
		"not an input": func() error {
			c := k.Challenge(t, KernelInputSubject("fly-"+fm.ID, "wakeup", sum), "cert")
			return checkKernelAttest(trust, fm.ID, "wakeup", body, &SignedDoc{Payload: c.Payload, Sig: c.Sig})
		},
		"another notary": func() error {
			t2 := trust
			t2.Notary = trust.Secrets
			return checkKernelAttest(t2, fm.ID, "wakeup", body, d)
		},
	} {
		if x() == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
