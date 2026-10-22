// Package notary: the log notary (DESIGN "Target design"). It issues challenges with its own timestamp and logs each
// one before answering it: an append-only file on its own volume, each entry naming the previous one's ID, so a gap
// or an edit shows. It holds no secret but its key, and never reads what a subject means.
package notary

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/internal/serve"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

type Notary struct {
	mu   sync.Mutex
	s    *sig.Signer
	f    *os.File
	seq  int64
	prev string
	now  func() time.Time
}

// Open: the log at path (made if missing); the chain goes on from its last entry
func Open(path string, s *sig.Signer) (*Notary, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	n := &Notary{s: s, f: f, now: time.Now}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var d sig.Doc
		var c doc.Challenge
		if json.Unmarshal(sc.Bytes(), &d) != nil || json.Unmarshal([]byte(d.Payload), &c) != nil {
			return nil, fmt.Errorf("the log at %s has a bad line after seq %d", path, n.seq)
		}
		n.seq, n.prev = c.Seq, d.ID()
	}
	return n, sc.Err()
}

// Challenge: the next log entry over subject, written (and synced) before it is answered
func (n *Notary) Challenge(subject, about string) (sig.Doc, error) {
	if err := doc.CheckChallengeInput(subject, about); err != nil {
		return sig.Doc{}, serve.Fail(400, "%v", err)
	}
	nonce := make([]byte, 16)
	rand.Read(nonce)
	n.mu.Lock()
	defer n.mu.Unlock()
	c := doc.Challenge{Kind: "challenge", Seq: n.seq + 1, Prev: n.prev, At: n.now().UTC().Format(time.RFC3339Nano),
		Subject: subject, About: about, Nonce: hex.EncodeToString(nonce)}
	d, err := n.s.SignJSON(c)
	if err != nil {
		return sig.Doc{}, err
	}
	line, _ := json.Marshal(d)
	if _, err := n.f.Write(append(line, '\n')); err != nil {
		return sig.Doc{}, err
	}
	if err := n.f.Sync(); err != nil {
		return sig.Doc{}, err
	}
	n.seq, n.prev = c.Seq, d.ID()
	return d, nil
}

// Register: POST /challenge {subject, about}
func Register(s *serve.Server, n *Notary) {
	serve.Handle(s, "POST /challenge", func(in struct {
		Subject string `json:"subject"`
		About   string `json:"about"`
	}) (any, error) {
		return n.Challenge(in.Subject, in.About)
	})
}
