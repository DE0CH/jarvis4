package notary

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

const subj = "00000000000000000000000000000000000000000000000000000000000000ab"

func TestTheLogChainsAndSurvivesARestart(t *testing.T) {
	s, _ := sig.NewSigner()
	path := filepath.Join(t.TempDir(), "log")
	n, err := Open(path, s)
	if err != nil {
		t.Fatal(err)
	}
	d1, err := n.Challenge(subj, "cert")
	if err != nil {
		t.Fatal(err)
	}
	n.f.Close()
	n2, err := Open(path, s)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := n2.Challenge(subj, "grant")
	if err != nil {
		t.Fatal(err)
	}
	var c1, c2 doc.Challenge
	if d1.Open(s.PublicKey(), &c1) != nil || d2.Open(s.PublicKey(), &c2) != nil {
		t.Fatal("signature")
	}
	if c1.Seq != 1 || c1.Prev != "" || c2.Seq != 2 || c2.Prev != d1.ID() || c1.Nonce == c2.Nonce {
		t.Fatalf("%+v %+v", c1, c2)
	}
}

// ✱ a subject that isn't a sha256, an about that isn't a short word
func TestBadInputsRefused(t *testing.T) {
	s, _ := sig.NewSigner()
	n, _ := Open(filepath.Join(t.TempDir(), "log"), s)
	for _, in := range [][2]string{{"x", "cert"}, {strings.ToUpper(subj), "cert"}, {subj, "Cert"}, {subj, "a b"}, {subj, ""}} {
		if _, err := n.Challenge(in[0], in[1]); err == nil {
			t.Fatalf("accepted %v", in)
		}
	}
	if n.seq != 0 {
		t.Fatal("a refused challenge was logged")
	}
}
