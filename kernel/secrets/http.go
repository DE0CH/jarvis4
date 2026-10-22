package secrets

// Secrets' HTTP surface (the old core's store routes, the same shapes), plus /keys and /pull. Only the router reaches
// it (NetworkPolicy). Nothing here trusts the caller: what matters is signed (the phone, the master key, the mover or
// merger) or sealed to secrets.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

func Handler(c *Secrets) http.Handler {
	mux := http.NewServeMux()
	type body = map[string]json.RawMessage
	h := func(pattern string, fn func(b body) (any, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if m := c.Mode(); m != modeServing && !allowedIn(m, pattern) {
				writeErr(c, w, fail(409, "this secrets is %s: it serves nothing", m))
				return
			}
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
			if err != nil {
				writeErr(c, w, fail(400, "body: %v", err))
				return
			}
			b := body{}
			if len(raw) != 0 {
				if err := json.Unmarshal(raw, &b); err != nil {
					writeErr(c, w, fail(400, "bad JSON: %v", err))
					return
				}
			}
			out, err := fn(b)
			c.syncLine()
			if n := c.LineSeq(); n > 0 {
				w.Header().Set(lineSeqHeader, strconv.Itoa(n))
			}
			if err != nil {
				writeErr(c, w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(out)
		})
	}
	str := func(b body, k string) string {
		var s string
		json.Unmarshal(b[k], &s)
		return s
	}
	sealed := func(b body, k string) (Sealed, error) {
		var s Sealed
		if json.Unmarshal(b[k], &s) != nil || s.E == "" {
			return s, fail(400, "%s must be sealed to secrets' agreement key", k)
		}
		return s, nil
	}
	into := func(b body, v any) error {
		raw, _ := json.Marshal(b)
		if json.Unmarshal(raw, v) != nil {
			return fail(400, "bad request")
		}
		return nil
	}

	h("GET /identity", func(b body) (any, error) { return c.Identity() })
	h("GET /roster", func(b body) (any, error) {
		if d := c.Roster(); d != nil {
			return d, nil
		}
		return nil, fail(404, "%v", sig.ErrNoRoster)
	})
	h("POST /roster", func(b body) (any, error) {
		var in struct {
			Roster SignedDoc `json:"roster"`
		}
		if err := into(b, &in); err != nil {
			return nil, err
		}
		return c.SetRoster(in.Roster)
	})
	h("POST /keys", func(b body) (any, error) { return c.KeysStatement() })
	h("POST /claim", func(b body) (any, error) {
		s, err := sealed(b, "bundle")
		if err != nil {
			return nil, err
		}
		return c.Claim(str(b, "statement"), str(b, "masterSig"), s)
	})
	h("POST /store-key", func(b body) (any, error) { return c.StoreKey(str(b, "phone"), str(b, "secrets")) })
	h("GET /line-state", func(b body) (any, error) { return c.LineState() })
	h("POST /handoff", func(b body) (any, error) { return c.Handoff() })
	h("POST /takeover", func(b body) (any, error) {
		var d LineStateDoc
		if err := json.Unmarshal(b["lineState"], &d); err != nil {
			return nil, fail(400, "lineState: {head, sealed}")
		}
		return c.Takeover(&d)
	})
	h("POST /wipe", func(b body) (any, error) { return c.Wipe(str(b, "statement"), str(b, "masterSig")) })

	h("POST /stores", func(b body) (any, error) { return c.Stores(str(b, "nonce")) })
	h("POST /stores/create", func(b body) (any, error) { return c.CreateStore(str(b, "name")) })
	h("POST /stores/mark-sensitive", func(b body) (any, error) { return c.MarkSensitive(str(b, "name")) })
	h("POST /stores/write-key", func(b body) (any, error) {
		var in WriteKeyInput
		if err := into(b, &in); err != nil {
			return nil, err
		}
		return c.WriteKey(in)
	})
	h("POST /stores/versions", func(b body) (any, error) { return c.Versions(str(b, "store"), str(b, "nonce")) })
	h("POST /stores/restore/begin", func(b body) (any, error) {
		var seq int
		if json.Unmarshal(b["seq"], &seq) != nil {
			return nil, fail(400, "seq: the version to put back")
		}
		return c.RestoreBegin(str(b, "store"), seq)
	})
	h("POST /stores/restore/finish", func(b body) (any, error) {
		shares := map[string]Sealed{}
		if len(b["shares"]) != 0 && json.Unmarshal(b["shares"], &shares) != nil {
			return nil, fail(400, "shares: {key: sealed share}")
		}
		return c.RestoreFinish(str(b, "pending"), str(b, "signature"), shares)
	})
	h("POST /stores/restore/commit", func(b body) (any, error) { return c.RestoreCommit(str(b, "pending")) })

	h("POST /unlock/begin", func(b body) (any, error) { return c.UnlockBegin(str(b, "store")) })
	h("POST /unlock/finish", func(b body) (any, error) {
		shares := map[string]Sealed{}
		if json.Unmarshal(b["shares"], &shares) != nil {
			return nil, fail(400, "shares: {key: sealed share}")
		}
		return c.UnlockFinish(str(b, "pending"), shares)
	})
	h("POST /lock", func(b body) (any, error) { return c.Lock(str(b, "id")) })
	h("POST /unlocked", func(b body) (any, error) { return c.ListUnlocked(str(b, "nonce")) })

	h("POST /deploy-keys/begin", func(b body) (any, error) {
		var in DeployKeyRequest
		if err := into(b, &in); err != nil {
			return nil, err
		}
		return c.DeployKeyBegin(in)
	})
	h("POST /deploy-keys/finish", func(b body) (any, error) {
		var s Sealed
		json.Unmarshal(b["share"], &s)
		return c.DeployKeyFinish(str(b, "pending"), s, str(b, "signature"))
	})

	h("POST /pull", func(b body) (any, error) {
		var in gv.Signed
		if err := into(b, &in); err != nil {
			return nil, err
		}
		return c.Pull(in)
	})
	return mux
}

// errors leave signed too
func writeErr(c *Secrets, w http.ResponseWriter, err error) {
	status := 500
	var e *Err
	if errors.As(err, &e) {
		status = e.Status
	}
	d, _ := c.sign(map[string]any{"kind": "error", "error": err.Error()})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(d)
}
