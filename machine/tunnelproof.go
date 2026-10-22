package main

// The tunnel proof (router/remote.go): an OpenCode/OpenClaw session publishes its web UI through the cf-tunnel
// agent with the store `tunnel`'s Access service token, which the Worker lets register only Jarvis 4 session ids,
// and only with the router's proof for that id (x-agent-secret, which Jarvis 1's agent.js sends from
// TUNNEL_AGENT_SECRET). The proof is fetched at boot over the signed /m channel, so it never sits in the Fly
// machine config. None (the router has no key, or an older router) = no TUNNEL_AGENT_SECRET.

import "log"

func tunnelProof(c *client) string {
	var out struct {
		Proof string `json:"proof"`
	}
	if err := c.json("GET", "/m/tunnel-proof", nil, &out); err != nil {
		log.Printf("tunnel proof: none (%v)", err)
		return ""
	}
	return out.Proof
}
