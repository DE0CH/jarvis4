// fakekernel: a stand-in for the kernel's nine components, for ios.yml's kernel-health UI test (KernelUITests): one
// server answers every role at http://ADDR/<role> (the router's KERNEL_URL = http://ADDR/%s), each with fresh keys
// and kernel/sig's own roster check (sig.Trust) against a root key made here. With -router it then plays the root key
// and the app: registers the root key with the router and posts the roster it signs (POST /api/kernel/root-key, POST
// /api/kernel/roster; the router runs NO_ACCESS=1), so the router's kernel is healthy. POST /_down/<role> makes a
// role stop answering (the test's unhealthy kernel), POST /_up/<role> brings it back.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/DE0CH/jarvis4/kernel/sig"
)

var roles = []string{"gullible", "identity", "merger", "minter", "mover", "notarizer", "notary", "secrets", "spawner"}

type component struct {
	c     *sig.Component
	trust *sig.Trust
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18310", "where to serve every role")
	router := flag.String("router", "", "a router to register the root key with and post the signed roster to")
	flag.Parse()
	root, err := sig.NewSigner()
	if err != nil {
		log.Fatal(err)
	}
	comps := map[string]*component{}
	ids := []sig.Identity{}
	for _, r := range roles {
		c, err := sig.NewComponent(r)
		if err != nil {
			log.Fatal(err)
		}
		comps[r] = &component{c, sig.NewTrust(root.PublicKey())}
		ids = append(ids, c.Identity)
	}
	var mu sync.Mutex
	down := map[string]bool{}
	reply := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		parts := strings.SplitN(strings.TrimPrefix(req.URL.Path, "/"), "/", 2)
		if len(parts) != 2 {
			http.NotFound(w, req)
			return
		}
		dep, path := parts[0], "/"+parts[1]
		if dep == "_down" || dep == "_up" {
			mu.Lock()
			down[parts[1]] = dep == "_down"
			mu.Unlock()
			log.Printf("%s %s", dep, parts[1])
			reply(w, 200, map[string]bool{"ok": true})
			return
		}
		role := strings.TrimSuffix(strings.TrimSuffix(dep, "-blue"), "-green") // secrets-blue and -green: one secrets
		c := comps[role]
		mu.Lock()
		isDown := down[dep] || down[role]
		mu.Unlock()
		if c == nil || isDown {
			reply(w, 503, map[string]string{"error": dep + " is down"})
			return
		}
		switch req.Method + " " + path {
		case "GET /identity":
			reply(w, 200, c.c.Identity)
		case "GET /roster":
			if d := c.trust.Doc(); d != nil {
				reply(w, 200, d)
				return
			}
			reply(w, 404, map[string]string{"kind": "error", "error": sig.ErrNoRoster.Error()})
		case "POST /roster":
			var in struct {
				Roster sig.Doc `json:"roster"`
			}
			if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
				reply(w, 400, map[string]string{"error": err.Error()})
				return
			}
			if err := c.trust.Set(in.Roster, &c.c.Identity); err != nil {
				reply(w, 403, map[string]string{"error": err.Error()})
				return
			}
			reply(w, 200, map[string]string{"kind": "roster-taken", "roster": in.Roster.ID()})
		default:
			reply(w, 404, map[string]string{"error": "the stand-in answers only /identity and /roster"})
		}
	})
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	ln := make(chan error, 1)
	go func() { ln <- http.Serve(l, nil) }()
	if *router != "" {
		payload, err := sig.Roster{Copy: "blue", Members: ids}.Payload()
		if err != nil {
			log.Fatal(err)
		}
		rs, _ := root.Sign([]byte(payload))
		post(*router+"/api/kernel/root-key", map[string]string{"rootKey": root.PublicKey()})
		out := post(*router+"/api/kernel/roster", map[string]string{"payload": payload, "rootSig": rs})
		log.Printf("the roster is posted: %s", out)
	}
	log.Fatal(<-ln)
}

func post(url string, body any) string {
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		log.Fatalf("%s: HTTP %d %s", url, resp.StatusCode, out)
	}
	return strings.TrimSpace(string(out))
}
