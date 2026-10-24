// Package serve: what every kernel component's server shares. A component makes fresh keys at start (RAM only) and
// answers them at GET /identity; the root key vouches for them in the kernel's roster, which the router brings with
// POST /roster and every component checks against KERNEL_ROOT (keys/root.pub). Every answer leaves signed, errors
// too, so the untrusted router can't put words in a component's mouth.
package serve

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/DE0CH/jarvis4/kernel/sig"
)

// Error: an error with the HTTP status it answers and, for an answer the router acts on, a stable reason (the error
// answer's "reason": a short kebab-case word the router matches instead of the message's words)
type Error struct {
	Code   int
	Msg    string
	Reason string
}

func (e *Error) Error() string { return e.Msg }

// Fail: an error answered with code
func Fail(code int, format string, a ...any) error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// FailBecause: an error answered with code and the stable reason
func FailBecause(code int, reason, format string, a ...any) error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...), Reason: reason}
}

// Server: a component's mux; Handle wraps a JSON handler
type Server struct {
	C     *sig.Component
	Trust *sig.Trust // the root key's roster (to check the other components' identities)
	Mux   *http.ServeMux
	// State: a stateful component's handoff and takeover (flip.go), nil for the stateless ones
	State Stateful

	mu       sync.Mutex
	frozenTo string // the roster this component handed over to ("" = it serves)
}

// RosterIn: the root key's roster, as the router posts it
type RosterIn struct {
	Roster sig.Doc `json:"roster"`
}

func New(c *sig.Component, t *sig.Trust) *Server {
	s := &Server{C: c, Trust: t, Mux: http.NewServeMux()}
	s.Mux.HandleFunc("GET /identity", func(w http.ResponseWriter, _ *http.Request) { s.reply(w, 200, c.Identity) })
	s.Mux.HandleFunc("GET /roster", func(w http.ResponseWriter, _ *http.Request) {
		if d := t.Doc(); d != nil {
			s.writeJSON(w, 200, d)
			return
		}
		s.reply(w, 404, map[string]string{"kind": "error", "error": sig.ErrNoRoster.Error()})
	})
	Handle(s, "POST /roster", func(in RosterIn) (any, error) {
		if err := t.Set(in.Roster, &c.Identity); err != nil {
			return nil, Fail(403, "%v", err)
		}
		if s.State != nil {
			if err := s.State.Decide(*t.Roster()); err != nil {
				return nil, err
			}
		}
		log.Printf("%s: the root key's roster taken", c.Role)
		return map[string]string{"kind": "roster-taken", "roster": in.Roster.ID()}, nil
	})
	s.registerFlip()
	return s
}

// Handle: POST pattern with a strict JSON body into In; fn's answer is signed
func Handle[In any](s *Server, pattern string, fn func(In) (any, error)) {
	s.Mux.HandleFunc(pattern, func(w http.ResponseWriter, req *http.Request) {
		if s.frozen() != "" && !frozenAllowed(pattern) {
			s.reply(w, 409, map[string]string{"kind": "error", "reason": ReasonHandedOff,
				"error": "this " + s.C.Role + " handed over to the other kernel copy: it serves nothing"})
			return
		}
		var in In
		body, err := io.ReadAll(io.LimitReader(req.Body, 8<<20))
		if err == nil {
			err = sig.StrictJSON(body, &in)
		}
		if err != nil {
			s.reply(w, 400, map[string]string{"kind": "error", "error": "bad request: " + err.Error()})
			return
		}
		out, err := fn(in)
		if err != nil {
			code, reason := 500, ""
			var e *Error
			if errors.As(err, &e) {
				code, reason = e.Code, e.Reason
			} else if errors.Is(err, sig.ErrNoRoster) {
				code = 503
			}
			if code >= 500 {
				log.Printf("%s: %v", pattern, err)
			}
			out := map[string]string{"kind": "error", "error": err.Error()}
			if reason != "" {
				out["reason"] = reason
			}
			s.reply(w, code, out)
			return
		}
		if d, ok := out.(sig.Doc); ok { // already a signed document
			s.writeJSON(w, 200, d)
			return
		}
		s.reply(w, 200, out)
	})
}

// reply: v signed by the component
func (s *Server) reply(w http.ResponseWriter, code int, v any) {
	d, err := s.C.Signer.SignJSON(v)
	if err != nil {
		http.Error(w, "signing failed", 500)
		return
	}
	s.writeJSON(w, code, d)
}

func (s *Server) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// Main: the component's process: its keys, its routes (setup adds them), then serve on KERNEL_ADDR (default :8080)
func Main(role string, setup func(*Server) error) {
	root := os.Getenv("KERNEL_ROOT")
	if root == "" {
		log.Fatal("KERNEL_ROOT (the root key's public half, keys/root.pub) isn't set")
	}
	c, err := sig.NewComponent(role)
	if err != nil {
		log.Fatal(err)
	}
	s := New(c, sig.NewTrust(root))
	if err := setup(s); err != nil {
		log.Fatal(err)
	}
	addr := os.Getenv("KERNEL_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("%s: serving on %s (signing key %s)", role, addr, c.Identity.SigningKey)
	log.Fatal(http.ListenAndServe(addr, s.Mux))
}
