package main

// The AWS runner (docs/PLAN-aws.md; Deyao, 2026-11-03: AWS the default, Fly kept as an option). A session's runner
// says where its machines run: "aws" (one EC2 instance per machine, kernel/spawner/aws.go) or "fly". Its region stays
// a place (London, Singapore, Tokyo: regions.go), which each runner maps to its own region.
//
// An AWS machine reaches the router over WireGuard: the router makes the machine's key pair and tunnel address per
// spawn (kept on the session until the machine is up, so a spawn whose answer was lost is adopted with them), the
// spawner writes them into the instance, and the m-gateways, which list the machines here (GET /gw/aws-peers on the
// machines' port, closed to the machines themselves), start the handshakes to each instance's public IPv4 (the pods'
// IPv4 goes out through WARP, as their handshakes to Fly's WireGuard gateway do). Nothing
// about the tunnel is a trust element: every /m request is signed by the machine's certified key.
//
//	DEFAULT_RUNNER            aws | fly: the runner a session gets when it names none (default fly until AWS is proven)
//	WG_AWS_GATEWAYS           the m-gateways' WireGuard public keys and tunnel addresses: "<key>@10.99.0.1,<key>@10.99.0.2"
//	AWS_READ_ACCESS_KEY_ID,
//	AWS_READ_SECRET_ACCESS_KEY  the router's read-only AWS key (infra/aws iam.tf jarvis4-router-read): instances, costs

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/DE0CH/jarvis4/kernel/spawner"
)

// sessionRunners: what New session offers
var sessionRunners = []struct{ ID, Label string }{{"aws", "AWS"}, {"fly", "Fly"}}

func validRunner(id string) bool { return id == "aws" || id == "fly" }

// defaultRunner: DEFAULT_RUNNER, else fly
func defaultRunner() string {
	if v := os.Getenv("DEFAULT_RUNNER"); validRunner(v) {
		return v
	}
	return "fly"
}

// runnerOf: where the session's machines run (its own runner, else the default)
func (r *Router) runnerOf(s *Session) string {
	if s != nil && validRunner(s.Runner) {
		return s.Runner
	}
	return defaultRunner()
}

// awsRegionOf: each session region (regions.go, Fly's codes) as the AWS region in the same place
var awsRegionOf = map[string]string{"lhr": "eu-west-2", "sin": "ap-southeast-1", "nrt": "ap-northeast-1"}

// spawnRegion: the region the spawner gets for the session's next machine, in its runner's terms
func (r *Router) spawnRegion(s *Session) string {
	reg := r.regionOf(s)
	if r.runnerOf(s) == "aws" {
		if a := awsRegionOf[reg]; a != "" {
			return a
		}
		return awsRegionOf["lhr"]
	}
	return reg
}

// isAWSMachine: an EC2 instance id
func isAWSMachine(id string) bool { return strings.HasPrefix(id, "i-") }

// AWSWG: an AWS machine's WireGuard: its key pair and tunnel address (the private key only until the machine is up)
type AWSWG struct {
	PrivateKey string `json:"privateKey,omitempty"`
	PublicKey  string `json:"publicKey"`
	Address    string `json:"address"`
}

// newAWSWG: a fresh key pair and the first tunnel address in 10.99.1.0–10.99.255.254 that no machine of used has
func newAWSWG(used map[string]bool) (*AWSWG, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, err
	}
	priv[0] &= 248 // clamped, as wg genkey makes them
	priv[31] = priv[31]&127 | 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	for a := netip.MustParseAddr("10.99.1.0"); a.Less(netip.MustParseAddr("10.99.255.255")); a = a.Next() {
		if b := a.As4(); b[3] == 0 || used[a.String()] {
			continue
		}
		return &AWSWG{PrivateKey: base64.StdEncoding.EncodeToString(priv[:]), PublicKey: base64.StdEncoding.EncodeToString(pub),
			Address: a.String()}, nil
	}
	return nil, fmt.Errorf("no free WireGuard address for an AWS machine")
}

// usedWGAddresses: the tunnel addresses of every machine and pending spawn the router knows (under the state lock)
func usedWGAddresses(d *persisted) map[string]bool {
	used := map[string]bool{}
	for _, st := range d.Started {
		if st.WG != nil {
			used[st.WG.Address] = true
		}
	}
	for _, s := range d.Sessions {
		if s.WG != nil {
			used[s.WG.Address] = true
		}
	}
	return used
}

// awsGateways: WG_AWS_GATEWAYS as the spawner's peers
func awsGateways() ([]spawner.WGPeer, error) {
	var out []spawner.WGPeer
	for _, p := range strings.Split(os.Getenv("WG_AWS_GATEWAYS"), ",") {
		key, addr, ok := strings.Cut(strings.TrimSpace(p), "@")
		if !ok {
			continue
		}
		out = append(out, spawner.WGPeer{PublicKey: key, Address: addr})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("WG_AWS_GATEWAYS is not set: no AWS machine can reach the router")
	}
	return out, nil
}

// awsSpawnWG: the WireGuard of the session's next AWS machine: the one a spawn already made for this source (a lost
// answer: the same machine), else a new one, kept on the session before the spawn is asked for
func (r *Router) awsSpawnWG(sid string) (*spawner.WireGuard, error) {
	peers, err := awsGateways()
	if err != nil {
		return nil, err
	}
	var wg *AWSWG
	r.st.Do(func(d *persisted) {
		s := d.Sessions[sid]
		if s == nil {
			err = fmt.Errorf("no session %s", sid)
			return
		}
		if s.WG == nil || s.WG.PrivateKey == "" {
			if s.WG, err = newAWSWG(usedWGAddresses(d)); err != nil {
				return
			}
		}
		c := *s.WG
		wg = &c
	})
	if err != nil {
		return nil, err
	}
	return &spawner.WireGuard{PrivateKey: wg.PrivateKey, Address: wg.Address, Peers: peers}, nil
}

// ---- the router's read-only view of AWS ----

var (
	awsReader     *spawner.AWSAPI
	awsReaderOnce sync.Once
	awsSeenMu     sync.Mutex
	awsSeen       = map[string]spawner.Instance{} // the newest listing (lostTick), for the gateways' peers
)

// listAWSMachines: every session instance EC2 lists (nil, nil when the router has no AWS key: no AWS machines)
func listAWSMachines() ([]spawner.Instance, error) {
	awsReaderOnce.Do(func() {
		id, secret := os.Getenv("AWS_READ_ACCESS_KEY_ID"), os.Getenv("AWS_READ_SECRET_ACCESS_KEY")
		if id != "" && secret != "" {
			awsReader = spawner.NewAWSAPI()
			awsReader.ConfigureReader(id, secret)
		}
	})
	if awsReader == nil {
		return nil, nil
	}
	ins, err := awsReader.List()
	if err != nil {
		return nil, err
	}
	awsSeenMu.Lock()
	clear(awsSeen)
	for _, i := range ins {
		awsSeen[i.ID] = i
	}
	awsSeenMu.Unlock()
	return ins, nil
}

// awsListLoop: the listing every 10 s, so a new instance's address reaches the gateways soon after it boots
func (r *Router) awsListLoop() {
	for {
		if _, err := listAWSMachines(); err != nil {
			log.Printf("[aws] list: %v", err)
		}
		time.Sleep(10 * time.Second)
	}
}

// AWSPeer: one AWS machine as the m-gateways need it
type AWSPeer struct {
	ID        string `json:"id"`
	PublicKey string `json:"publicKey"`
	Address   string `json:"address"`  // its tunnel address
	Endpoint  string `json:"endpoint"` // <public IPv4>:51820
}

// awsPeers: the machines with a WireGuard whose instance EC2 lists up with a public address
func (r *Router) awsPeers() []AWSPeer {
	awsSeenMu.Lock()
	seen := make(map[string]spawner.Instance, len(awsSeen))
	for k, v := range awsSeen {
		seen[k] = v
	}
	awsSeenMu.Unlock()
	out := []AWSPeer{}
	r.st.Do(func(d *persisted) {
		for id, st := range d.Started {
			in, ok := seen[id]
			if st.WG == nil || !ok || in.PublicIP == "" || in.State == "destroyed" || in.State == "destroying" {
				continue
			}
			out = append(out, AWSPeer{ID: id, PublicKey: st.WG.PublicKey, Address: st.WG.Address,
				Endpoint: in.PublicIP + ":51820"})
		}
	})
	return out
}

// registerAWSPeers: GET /gw/aws-peers on the machines' port, for the m-gateways (mGatewayProxy keeps the machines'
// own requests from it)
func (r *Router) registerAWSPeers(mmux *http.ServeMux) {
	mmux.HandleFunc("GET /gw/aws-peers", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"peers": r.awsPeers()})
	})
}
